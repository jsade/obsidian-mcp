//! Path exclusion logic: compile glob patterns and test vault-relative paths.

use std::fs;
use std::path::{Path, PathBuf};

use std::sync::Arc;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};

use crate::error::{VaultError, VaultResult};

/// Whether a vault-relative path belongs to the visible indexing namespace.
pub(crate) fn is_visible_path(path: &Path) -> bool {
    path.components().all(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| !name.starts_with('.'))
    })
}

/// Compiled set of glob patterns for excluding vault paths from indexing.
pub struct ExcludeSet {
    set: GlobSet,
    patterns: Vec<String>,
    /// Folder scope and the canonical vault root it is checked against.
    scope: Option<(Arc<PathScope>, PathBuf)>,
}

/// Server-wide folder scope: the paths a client may reach at all.
///
/// Unlike [`ExcludeSet`], which only hides notes from indexing, a path outside
/// the scope is refused by every `Vault` operation. Deny wins over allow, and
/// an empty allow list allows everything that is not denied.
///
/// Matching ignores case and Unicode normalization form, because a
/// case-insensitive filesystem serves `contract/x.md` from `Contract/`.
/// Every pattern covers the entry it names and everything under it, so
/// `Contract`, `Contract/` and `Contract/**` mean the same.
pub struct PathScope {
    deny: GlobSet,
    allow: Option<GlobSet>,
}

/// Paths no pattern that names a folder or a file would match. A pattern that
/// matches one of them covers every note in the vault.
const WHOLE_VAULT_PROBES: [&str; 4] = [
    "\u{e000}",
    "\u{e000}/\u{e001}",
    "\u{e000}.md",
    "\u{e000}/\u{e001}.md",
];

impl PathScope {
    /// A scope that permits every path.
    pub fn unrestricted() -> Self {
        Self {
            deny: GlobSet::empty(),
            allow: None,
        }
    }

    /// Compile deny and allow patterns. The grammar is that of the exclude
    /// list, except that a pattern also covers everything under the entry it
    /// names, a leading `/` or `./` is dropped, and an invalid pattern is an
    /// error: a scope that silently dropped a pattern would expose the folder
    /// it named.
    pub fn build(deny: &[String], allow: &[String]) -> VaultResult<Self> {
        let deny = Self::compile(deny)?.unwrap_or_else(GlobSet::empty);
        let allow = Self::compile(allow)?;
        Ok(Self { deny, allow })
    }

    fn compile(patterns: &[String]) -> VaultResult<Option<GlobSet>> {
        let mut builder = GlobSetBuilder::new();
        let mut any = false;
        for raw in patterns {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let pattern = Self::fold_case(trimmed)
                .split('/')
                .filter(|segment| !segment.is_empty() && *segment != ".")
                .collect::<Vec<_>>()
                .join("/");
            if pattern.split('/').any(|segment| segment == "..") {
                return Err(VaultError::InvalidPath(format!(
                    "scope pattern '{trimmed}' must not contain '..'"
                )));
            }
            let base = pattern.strip_suffix("/**").unwrap_or(&pattern);
            if base.is_empty() || base == "**" {
                return Err(VaultError::InvalidPath(format!(
                    "scope pattern '{trimmed}' would cover the whole vault"
                )));
            }
            let globs = [base.to_string(), format!("{base}/**")];
            for glob in globs {
                let compiled = GlobBuilder::new(&glob).build().map_err(|e| {
                    VaultError::InvalidPath(format!("invalid scope pattern '{trimmed}': {e}"))
                })?;
                // `*` crosses `/`, so `*`, `*/**` or `*.md` name no folder at all.
                let matcher = compiled.compile_matcher();
                if WHOLE_VAULT_PROBES
                    .iter()
                    .any(|probe| matcher.is_match(probe))
                {
                    return Err(VaultError::InvalidPath(format!(
                        "scope pattern '{trimmed}' would cover the whole vault"
                    )));
                }
                builder.add(compiled);
                any = true;
            }
        }
        if !any {
            return Ok(None);
        }
        builder
            .build()
            .map(Some)
            .map_err(|e| VaultError::Other(format!("glob set compile: {e}")))
    }

    /// True when no deny or allow pattern is configured.
    pub fn is_unrestricted(&self) -> bool {
        self.deny.is_empty() && self.allow.is_none()
    }

    /// Whether a vault-relative path matches a deny pattern.
    pub fn denies(&self, relative_path: &Path) -> bool {
        !self.deny.is_empty() && self.deny.is_match(Self::key(relative_path))
    }

    /// Whether a vault-relative path is inside the scope.
    pub fn permits(&self, relative_path: &Path) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        let key = Self::key(relative_path);
        !self.deny.is_match(&key) && self.allow.as_ref().is_none_or(|allow| allow.is_match(&key))
    }

    fn key(relative_path: &Path) -> String {
        Self::fold_case(&relative_path.to_string_lossy()).replace('\\', "/")
    }

    /// Case-folded, NFC-normalized spelling, applied to patterns and paths
    /// alike. globset's own case-insensitive mode folds ASCII only, which
    /// would miss `Pöytäkirjat`. Upper-casing first also folds the letters
    /// that lower-casing alone leaves apart (`ſ` and `s`, `ς` and `σ`).
    fn fold_case(raw: &str) -> String {
        let folded = super::path::canonical_unicode_key(raw)
            .to_uppercase()
            .to_lowercase();
        super::path::canonical_unicode_key(&folded)
    }
}

impl ExcludeSet {
    /// Compile a list of raw patterns into a `GlobSet`.
    ///
    /// Each pattern is trimmed, blank entries are skipped, and trailing `/`
    /// is normalized to `/**`. Invalid patterns are logged and skipped.
    pub fn build(patterns: Vec<String>) -> VaultResult<Self> {
        let mut builder = GlobSetBuilder::new();
        let mut accepted = Vec::new();

        for raw in &patterns {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }

            let normalized = if let Some(prefix) = trimmed.strip_suffix('/') {
                format!("{prefix}/**")
            } else {
                trimmed.to_string()
            };

            match Glob::new(&normalized) {
                Ok(glob) => {
                    builder.add(glob);
                    accepted.push(normalized);
                }
                Err(e) => {
                    tracing::warn!(pattern = trimmed, error = %e, "skipping invalid exclude pattern");
                }
            }
        }

        let set = builder
            .build()
            .map_err(|e| VaultError::Other(format!("glob set compile: {e}")))?;

        Ok(Self {
            set,
            patterns: accepted,
            scope: None,
        })
    }

    /// Also exclude every path outside `scope`, so that indexing, search,
    /// graph and stats never see a scoped-out note. `vault_root` must be
    /// canonical: a symlink is judged by where it points.
    pub fn with_scope(mut self, scope: Arc<PathScope>, vault_root: &Path) -> Self {
        self.scope = (!scope.is_unrestricted()).then(|| (scope, vault_root.to_path_buf()));
        self
    }

    /// Whether a folder scope puts this path out of reach, under the name
    /// given or under the location a symlink resolves to.
    pub fn is_out_of_scope(&self, relative_path: &Path) -> bool {
        let Some((scope, root)) = &self.scope else {
            return false;
        };
        if !scope.permits(relative_path) {
            return true;
        }
        root.join(relative_path)
            .canonicalize()
            .ok()
            .and_then(|real| real.strip_prefix(root).map(Path::to_path_buf).ok())
            .is_some_and(|real| !is_visible_path(&real) || !scope.permits(&real))
    }

    /// Whether a folder scope denies this folder, so a walk need not open it.
    /// Only a deny pattern counts: a folder off the allow list may still hold
    /// an allowed folder, as `Team` holds `Team/Internal`.
    pub fn denies_dir(&self, relative_path: &Path) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|(scope, _)| scope.denies(relative_path))
    }

    /// Check whether a vault-relative path is excluded.
    pub fn is_excluded(&self, relative_path: &Path) -> bool {
        if self.is_out_of_scope(relative_path) {
            return true;
        }
        if self.is_empty() {
            return false;
        }
        self.set.is_match(relative_path)
    }

    /// True when no patterns are configured.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Active (accepted, normalized) patterns for diagnostics.
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

/// Parse the content of an ignore file into raw pattern strings.
///
/// Lines starting with `#` (after trimming leading whitespace) are comments.
/// Blank lines and surrounding whitespace are stripped.
pub fn parse_ignore_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let ltrimmed = line.trim_start();
            if ltrimmed.starts_with('#') {
                return None;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            Some(trimmed.to_string())
        })
        .collect()
}

/// Load and merge ignore patterns from both config locations.
///
/// Reads `{mcp_home}/ignore` and (if different) `{mcp_data}/ignore`,
/// merges both lists, sorts, and deduplicates.
pub fn load_ignore_patterns(mcp_home: &Path, mcp_data: &Path) -> Vec<String> {
    let mut patterns = Vec::new();

    if let Ok(content) = fs::read_to_string(mcp_home.join("ignore")) {
        patterns.extend(parse_ignore_lines(&content));
    }

    if mcp_data != mcp_home
        && let Ok(content) = fs::read_to_string(mcp_data.join("ignore"))
    {
        patterns.extend(parse_ignore_lines(&content));
    }

    patterns.sort();
    patterns.dedup();
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ExcludeSet::build — normalization ──

    #[test]
    fn build_normalizes_trailing_slash() {
        let set = ExcludeSet::build(vec!["Archive/".into()]).unwrap();
        assert_eq!(set.patterns(), &["Archive/**"]);
    }

    #[test]
    fn build_preserves_explicit_double_star() {
        let set = ExcludeSet::build(vec!["Archive/**".into()]).unwrap();
        assert_eq!(set.patterns(), &["Archive/**"]);
    }

    #[test]
    fn build_normalizes_nested_trailing_slash() {
        let set = ExcludeSet::build(vec!["**/drafts/".into()]).unwrap();
        assert_eq!(set.patterns(), &["**/drafts/**"]);
    }

    #[test]
    fn build_no_normalization_without_trailing_slash() {
        let set = ExcludeSet::build(vec!["*.tmp".into()]).unwrap();
        assert_eq!(set.patterns(), &["*.tmp"]);
    }

    #[test]
    fn build_skips_invalid_pattern() {
        let set = ExcludeSet::build(vec!["[invalid".into(), "valid/**".into()]).unwrap();
        assert_eq!(set.patterns().len(), 1);
        assert_eq!(set.patterns()[0], "valid/**");
    }

    #[test]
    fn build_empty_input() {
        let set = ExcludeSet::build(vec![]).unwrap();
        assert!(set.is_empty());
        assert!(set.patterns().is_empty());
    }

    #[test]
    fn build_all_invalid() {
        let set = ExcludeSet::build(vec!["[bad1".into(), "[bad2".into()]).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn build_trims_whitespace() {
        let set = ExcludeSet::build(vec!["  Archive/  ".into()]).unwrap();
        assert_eq!(set.patterns(), &["Archive/**"]);
    }

    #[test]
    fn build_skips_blank_entries() {
        let set = ExcludeSet::build(vec!["".into(), "  ".into(), "Archive/".into()]).unwrap();
        assert_eq!(set.patterns().len(), 1);
    }

    // ── ExcludeSet::is_excluded ──

    #[test]
    fn is_excluded_matches_file_in_excluded_dir() {
        let set = ExcludeSet::build(vec!["Archive/".into()]).unwrap();
        assert!(set.is_excluded(Path::new("Archive/old-note.md")));
    }

    #[test]
    fn is_excluded_matches_deeply_nested() {
        let set = ExcludeSet::build(vec!["Archive/".into()]).unwrap();
        assert!(set.is_excluded(Path::new("Archive/sub/deep.md")));
    }

    #[test]
    fn is_excluded_rejects_non_matching() {
        let set = ExcludeSet::build(vec!["Archive/".into()]).unwrap();
        assert!(!set.is_excluded(Path::new("Active/note.md")));
    }

    #[test]
    fn is_excluded_rejects_similar_name() {
        let set = ExcludeSet::build(vec!["Archive/".into()]).unwrap();
        assert!(!set.is_excluded(Path::new("Archived-note.md")));
    }

    #[test]
    fn is_excluded_empty_set_always_false() {
        let set = ExcludeSet::build(vec![]).unwrap();
        assert!(!set.is_excluded(Path::new("anything.md")));
    }

    #[test]
    fn is_excluded_wildcard_pattern() {
        let set = ExcludeSet::build(vec!["*.tmp".into()]).unwrap();
        assert!(set.is_excluded(Path::new("scratch.tmp")));
        assert!(!set.is_excluded(Path::new("note.md")));
    }

    #[test]
    fn is_excluded_double_star_pattern() {
        let set = ExcludeSet::build(vec!["**/drafts/".into()]).unwrap();
        assert!(set.is_excluded(Path::new("a/b/drafts/note.md")));
        assert!(set.is_excluded(Path::new("drafts/note.md")));
    }

    #[test]
    fn is_excluded_nested_dir_pattern() {
        let set = ExcludeSet::build(vec!["Resources/Meetings/".into()]).unwrap();
        assert!(set.is_excluded(Path::new("Resources/Meetings/2024-01.md")));
        assert!(!set.is_excluded(Path::new("Resources/Notes/note.md")));
    }

    // ── parse_ignore_lines ──

    #[test]
    fn parse_ignore_lines_strips_comments() {
        let result = parse_ignore_lines("# comment\nArchive/\n# another\n*.tmp");
        assert_eq!(result, vec!["Archive/", "*.tmp"]);
    }

    #[test]
    fn parse_ignore_lines_strips_blank_lines() {
        let result = parse_ignore_lines("Archive/\n\n\n*.tmp");
        assert_eq!(result, vec!["Archive/", "*.tmp"]);
    }

    #[test]
    fn parse_ignore_lines_trims_whitespace() {
        let result = parse_ignore_lines("  Archive/  \n  *.tmp  ");
        assert_eq!(result, vec!["Archive/", "*.tmp"]);
    }

    #[test]
    fn parse_ignore_lines_hash_mid_line_not_comment() {
        let result = parse_ignore_lines("path#with#hashes");
        assert_eq!(result, vec!["path#with#hashes"]);
    }

    #[test]
    fn parse_ignore_lines_indented_comment() {
        let result = parse_ignore_lines("  # indented comment\nArchive/");
        assert_eq!(result, vec!["Archive/"]);
    }

    #[test]
    fn parse_ignore_lines_empty_input() {
        let result = parse_ignore_lines("");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_ignore_lines_only_comments_and_blanks() {
        let result = parse_ignore_lines("# comment\n\n# another\n  ");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_ignore_lines_mixed_content() {
        let input = "\
# Exclusion patterns for obsidian-mcp
# Last updated: 2026-05-29

Archive/
Resources/Meetings/

# Drafts at any depth
**/drafts/*.tmp
";
        let result = parse_ignore_lines(input);
        assert_eq!(
            result,
            vec!["Archive/", "Resources/Meetings/", "**/drafts/*.tmp"]
        );
    }

    // ── load_ignore_patterns ──

    #[test]
    fn load_ignore_patterns_single_location() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("ignore"), "Archive/\n*.tmp\n").unwrap();

        let result = load_ignore_patterns(dir.path(), dir.path());
        assert_eq!(result, vec!["*.tmp", "Archive/"]);
    }

    #[test]
    fn load_ignore_patterns_both_locations() {
        let home = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        std::fs::write(home.path().join("ignore"), "Archive/\n").unwrap();
        std::fs::write(data.path().join("ignore"), "Drafts/\n").unwrap();

        let result = load_ignore_patterns(home.path(), data.path());
        assert_eq!(result, vec!["Archive/", "Drafts/"]);
    }

    #[test]
    fn load_ignore_patterns_dedup() {
        let home = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        std::fs::write(home.path().join("ignore"), "Archive/\nDrafts/\n").unwrap();
        std::fs::write(data.path().join("ignore"), "Archive/\nMeetings/\n").unwrap();

        let result = load_ignore_patterns(home.path(), data.path());
        assert_eq!(result, vec!["Archive/", "Drafts/", "Meetings/"]);
    }

    #[test]
    fn load_ignore_patterns_missing_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = load_ignore_patterns(dir.path(), dir.path());
        assert!(result.is_empty());
    }

    #[test]
    fn load_ignore_patterns_same_path_no_duplicates() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("ignore"), "Archive/\nDrafts/\n").unwrap();

        let result = load_ignore_patterns(dir.path(), dir.path());
        assert_eq!(result, vec!["Archive/", "Drafts/"]);
    }

    #[test]
    fn load_ignore_patterns_one_missing_one_present() {
        let home = tempfile::TempDir::new().unwrap();
        let data = tempfile::TempDir::new().unwrap();
        std::fs::write(data.path().join("ignore"), "External/\n").unwrap();

        let result = load_ignore_patterns(home.path(), data.path());
        assert_eq!(result, vec!["External/"]);
    }

    // ── PathScope ──

    fn scope(deny: &[&str], allow: &[&str]) -> PathScope {
        let owned = |patterns: &[&str]| patterns.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        PathScope::build(&owned(deny), &owned(allow)).unwrap()
    }

    #[test]
    fn scope_unrestricted_permits_everything() {
        let scope = scope(&[], &[]);
        assert!(scope.is_unrestricted());
        assert!(scope.permits(Path::new("Contract/wo.md")));
    }

    #[test]
    fn scope_denies_folder_entry_and_everything_under_it() {
        for pattern in [
            "Contract",
            "Contract/",
            "Contract/**",
            "/Contract/",
            "./Contract//",
        ] {
            let scope = scope(&[pattern], &[]);
            assert!(!scope.permits(Path::new("Contract")), "{pattern}");
            assert!(!scope.permits(Path::new("Contract/wo.md")), "{pattern}");
            assert!(
                !scope.permits(Path::new("Contract/sub/deep.md")),
                "{pattern}"
            );
            assert!(scope.permits(Path::new("Contracts/other.md")), "{pattern}");
            assert!(scope.permits(Path::new("Notes/Contract.md")), "{pattern}");
        }
    }

    #[test]
    fn scope_ignores_case_and_unicode_normalization_form() {
        let scope = scope(&["Contract/", "Caf\u{e9}/", "p\u{f6}yt\u{e4}kirjat/"], &[]);
        assert!(!scope.permits(Path::new("P\u{d6}YT\u{c4}KIRJAT/a.md")));
        assert!(!scope.permits(Path::new("Po\u{308}yta\u{308}kirjat/a.md")));
        assert!(!scope.permits(Path::new("contract/wo.md")));
        assert!(!scope.permits(Path::new("CONTRACT/WO.MD")));
        assert!(!scope.permits(Path::new("Cafe\u{301}/menu.md")));
    }

    #[test]
    fn scope_allow_list_restricts_and_deny_wins() {
        let scope = scope(&["Public/Drafts/"], &["Public/"]);
        assert!(scope.permits(Path::new("Public/a.md")));
        assert!(!scope.permits(Path::new("Public/Drafts/b.md")));
        assert!(!scope.permits(Path::new("Private/c.md")));
        assert!(!scope.permits(Path::new("root.md")));
        assert!(!scope.denies(Path::new("Private/c.md")));
        assert!(scope.denies(Path::new("Public/Drafts/b.md")));
    }

    #[test]
    fn scope_rejects_an_invalid_pattern() {
        for pattern in ["[bad", "/", "**", "./", "Notes/../Private/"] {
            assert!(
                PathScope::build(&[pattern.to_string()], &[]).is_err(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn scope_rejects_a_wildcard_that_covers_the_whole_vault() {
        for pattern in [
            "*",
            "*/",
            "*/**",
            "**/*",
            "?*",
            "*.md",
            "**/*.md",
            "{*,Private}",
        ] {
            assert!(
                PathScope::build(&[], &[pattern.to_string()]).is_err(),
                "allow {pattern}"
            );
            assert!(
                PathScope::build(&[pattern.to_string()], &[]).is_err(),
                "deny {pattern}"
            );
        }
        for pattern in ["Notes/*", "*.key", "*draft*", "Clients/*/Contracts/"] {
            assert!(
                PathScope::build(&[], &[pattern.to_string()]).is_ok(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn scope_keeps_escaped_glob_characters_literal() {
        let scope = scope(&[r"Projects \[2024\]/"], &[]);
        assert!(!scope.permits(Path::new("Projects [2024]/x.md")));
        assert!(scope.permits(Path::new("Projects 2/x.md")));
    }

    #[test]
    fn scope_folds_letters_that_lowercasing_leaves_apart() {
        let scope = scope(&["Minutes/", "Stra\u{df}e/"], &[]);
        assert!(!scope.permits(Path::new("Minute\u{17f}/new.md")));
        assert!(!scope.permits(Path::new("STRASSE/a.md")));
    }

    #[test]
    fn scope_file_pattern_matches_the_file() {
        let scope = scope(&["Notes/secret.md", "*.key"], &[]);
        assert!(!scope.permits(Path::new("Notes/secret.md")));
        assert!(!scope.permits(Path::new("Notes/Sub/id.KEY")));
        assert!(scope.permits(Path::new("Notes/open.md")));
    }

    #[test]
    fn exclude_set_with_scope_excludes_scoped_out_paths() {
        let set = ExcludeSet::build(vec!["Archive/".into()])
            .unwrap()
            .with_scope(
                Arc::new(scope(&["Contract/"], &[])),
                Path::new("/nonexistent"),
            );
        assert!(set.is_excluded(Path::new("Contract/wo.md")));
        assert!(set.is_excluded(Path::new("Archive/old.md")));
        assert!(!set.is_excluded(Path::new("Notes/a.md")));
        assert_eq!(set.patterns(), ["Archive/**"]);
    }

    #[test]
    fn denies_dir_counts_deny_patterns_only() {
        let set = ExcludeSet::build(vec![]).unwrap().with_scope(
            Arc::new(scope(&["Private/"], &["Team/Internal"])),
            Path::new("/nonexistent"),
        );
        assert!(set.denies_dir(Path::new("Private")));
        assert!(set.denies_dir(Path::new("Private/Old")));
        // Off the allow list, but it holds an allowed folder.
        assert!(!set.denies_dir(Path::new("Team")));
        assert!(!set.denies_dir(Path::new("Team/Internal")));
        assert!(
            !ExcludeSet::build(vec![])
                .unwrap()
                .denies_dir(Path::new("Private"))
        );
    }
}
