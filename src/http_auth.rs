//! Named bearer tokens for the HTTP transport.
//!
//! Tokens come from two places: the single `OBSIDIAN_HTTP_AUTH_TOKEN`, kept
//! under the name `default`, and a token file holding one `name:sha256-hex`
//! line per client. The file is re-read when it changes, so removing a line
//! revokes that token without a restart and without touching the others.
//!
//! Only digests and names are kept; a token value never reaches a log line.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

/// Name given to the token from `OBSIDIAN_HTTP_AUTH_TOKEN`.
pub const DEFAULT_TOKEN_NAME: &str = "default";

/// Names the write log uses for clients that are not file tokens.
const RESERVED_NAMES: [&str; 3] = [DEFAULT_TOKEN_NAME, "anonymous", "stdio"];

/// Sessions remembered at once; beyond it the oldest is forgotten and its
/// client has to open a new one.
const MAX_TRACKED_SESSIONS: usize = 4096;

type TokenDigest = [u8; 32];
type NamedDigests = Vec<(Arc<str>, TokenDigest)>;

pub struct TokenSet {
    default: Option<TokenDigest>,
    file: Option<TokenFile>,
}

struct TokenFile {
    path: PathBuf,
    state: Mutex<FileState>,
}

#[derive(Default)]
struct FileState {
    /// Content of the version last read; `None` when it could not be read.
    content: Option<String>,
    tokens: NamedDigests,
}

impl TokenSet {
    /// Build the set from `OBSIDIAN_HTTP_AUTH_TOKEN` and
    /// `OBSIDIAN_HTTP_AUTH_TOKENS_FILE`. `Ok(None)` means neither is set and
    /// the endpoint stays open, as before.
    pub fn from_env() -> Result<Option<Self>, String> {
        // A variable that is set but unusable must not read as "no
        // authentication asked for".
        let default = match std::env::var("OBSIDIAN_HTTP_AUTH_TOKEN") {
            Ok(token) => Some(token).filter(|token| !token.is_empty()),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("OBSIDIAN_HTTP_AUTH_TOKEN is not valid UTF-8".into());
            }
        };
        let file = match std::env::var_os("OBSIDIAN_HTTP_AUTH_TOKENS_FILE") {
            Some(path) if path.is_empty() => {
                return Err("OBSIDIAN_HTTP_AUTH_TOKENS_FILE is set but empty".into());
            }
            path => path.map(PathBuf::from),
        };
        for (key, _) in std::env::vars_os() {
            let key = key.to_string_lossy();
            if (key.starts_with("OBSIDIAN_HTTP_AUTH") || key.starts_with("OBSIDIAN_HTTP_ALLOW"))
                && !matches!(
                    &*key,
                    "OBSIDIAN_HTTP_AUTH_TOKEN"
                        | "OBSIDIAN_HTTP_AUTH_TOKENS_FILE"
                        | "OBSIDIAN_HTTP_ALLOWED_HOSTS"
                )
            {
                tracing::warn!(variable = %key, "unknown HTTP access variable ignored");
            }
        }
        Self::new(default.as_deref(), file)
    }

    /// A token file that cannot be read or parsed at startup is an error: the
    /// operator asked for authentication and must not get a server without it.
    pub fn new(default: Option<&str>, file: Option<PathBuf>) -> Result<Option<Self>, String> {
        if default.is_none() && file.is_none() {
            return Ok(None);
        }
        let file = match file {
            Some(path) => {
                let (content, tokens) = read_token_file(&path)?;
                Some(TokenFile {
                    path,
                    state: Mutex::new(FileState {
                        content: Some(content),
                        tokens,
                    }),
                })
            }
            None => None,
        };
        Ok(Some(Self {
            default: default.map(digest),
            file,
        }))
    }

    /// The name of the token `presented` matches, if any.
    pub fn authenticate(&self, presented: &str) -> Option<Arc<str>> {
        if presented.is_empty() {
            return None;
        }
        let presented = digest(presented);
        let mut matched = None;
        if let Some(default) = &self.default
            && constant_time_eq(default, &presented)
        {
            matched = Some(Arc::from(DEFAULT_TOKEN_NAME));
        }
        if let Some(file) = &self.file {
            // Every entry is compared, so timing does not show which one matched.
            for (name, token) in file.current() {
                if constant_time_eq(&token, &presented) {
                    matched = Some(name);
                }
            }
        }
        matched
    }
}

impl TokenFile {
    /// The file's tokens as of now. The file is small, so it is read on every
    /// request and parsed again only when its content changed. A file that
    /// has become unreadable or invalid yields no tokens until it is fixed:
    /// failing closed beats serving a revoked token.
    fn current(&self) -> NamedDigests {
        let content = std::fs::read_to_string(&self.path).ok();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if content != state.content {
            let parsed = match &content {
                Some(content) => parse_token_file(content),
                None => Err("cannot be read".to_string()),
            };
            state.tokens = match parsed {
                Ok(tokens) => {
                    tracing::info!(tokens = tokens.len(), "HTTP token file reloaded");
                    tokens
                }
                Err(error) => {
                    tracing::error!(
                        path = %self.path.display(),
                        %error,
                        "HTTP token file rejected; its tokens are refused"
                    );
                    Vec::new()
                }
            };
            state.content = content;
        }
        state.tokens.clone()
    }
}

fn read_token_file(path: &Path) -> Result<(String, NamedDigests), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|error| format!("token file {}: {error}", path.display()))?;
    let tokens = parse_token_file(&content)
        .map_err(|error| format!("token file {}: {error}", path.display()))?;
    Ok((content, tokens))
}

/// Parse `name:sha256-hex` lines. `#` starts a comment line. One bad line
/// rejects the whole file, so a typing error cannot silently drop a client or
/// leave a half-edited file in force.
fn parse_token_file(content: &str) -> Result<NamedDigests, String> {
    let mut tokens: NamedDigests = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let (name, hex) = line
            .split_once(':')
            .ok_or_else(|| format!("line {number}: expected name:sha256-hex"))?;
        let name = name.trim();
        let valid_name = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid_name {
            return Err(format!(
                "line {number}: a token name uses letters, digits, '-', '_' and '.'"
            ));
        }
        if RESERVED_NAMES
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(name))
        {
            return Err(format!("line {number}: the name '{name}' is reserved"));
        }
        if tokens
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            return Err(format!("line {number}: duplicate token name '{name}'"));
        }
        let digest = parse_hex_digest(hex.trim())
            .ok_or_else(|| format!("line {number}: expected 64 hexadecimal digits for '{name}'"))?;
        if digest == self::digest("") {
            return Err(format!(
                "line {number}: '{name}' holds the digest of an empty token"
            ));
        }
        // Two names for one token would survive the removal of either line.
        if tokens.iter().any(|(_, existing)| *existing == digest) {
            return Err(format!(
                "line {number}: '{name}' repeats another line's token"
            ));
        }
        tokens.push((Arc::from(name), digest));
    }
    Ok(tokens)
}

fn parse_hex_digest(hex: &str) -> Option<TokenDigest> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

fn digest(token: &str) -> TokenDigest {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(token.as_bytes()));
    digest
}

fn constant_time_eq(a: &TokenDigest, b: &TokenDigest) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Which client opened each live session.
///
/// A session keeps the tool filter and the write-log name of the request that
/// opened it, and the transport routes later requests by session id alone. So
/// only the token that opened a session may use it: otherwise a second client
/// that learned the id could write under the first one's name.
#[derive(Default)]
pub struct SessionOwners {
    state: Mutex<SessionState>,
}

#[derive(Default)]
struct SessionState {
    owners: HashMap<String, (Arc<str>, u64)>,
    opened: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SessionAccess {
    /// The client opened this session.
    Owner,
    /// Another client opened it.
    Foreign,
    /// No record of it: never opened here, or forgotten.
    Unknown,
}

impl SessionOwners {
    /// Record that `client` opened `session`.
    pub fn bind(&self, session: &str, client: Arc<str>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.owners.len() >= MAX_TRACKED_SESSIONS
            && let Some(oldest) = state
                .owners
                .iter()
                .min_by_key(|(_, (_, opened))| *opened)
                .map(|(id, _)| id.clone())
        {
            state.owners.remove(&oldest);
        }
        state.opened += 1;
        let opened = state.opened;
        state.owners.insert(session.to_owned(), (client, opened));
    }

    pub fn access(&self, session: &str, client: &str) -> SessionAccess {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.owners.get(session) {
            Some((owner, _)) if &**owner == client => SessionAccess::Owner,
            Some(_) => SessionAccess::Foreign,
            None => SessionAccess::Unknown,
        }
    }

    /// Drop a session its owner closed.
    pub fn forget(&self, session: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.owners.remove(session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(token: &str) -> String {
        digest(token)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn write(path: &Path, lines: &[(&str, &str)]) {
        let content: String = lines
            .iter()
            .map(|(name, token)| format!("{name}:{}\n", hex(token)))
            .collect();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn nothing_configured_means_no_token_set() {
        assert!(TokenSet::new(None, None).unwrap().is_none());
    }

    #[test]
    fn default_token_is_named_default() {
        let set = TokenSet::new(Some("secret"), None).unwrap().unwrap();
        assert_eq!(set.authenticate("secret").as_deref(), Some("default"));
        assert_eq!(set.authenticate("secret-longer"), None);
        assert_eq!(set.authenticate(""), None);
    }

    #[test]
    fn file_tokens_authenticate_by_name_next_to_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        write(&path, &[("laptop", "aaa"), ("ci-runner", "bbb")]);
        let set = TokenSet::new(Some("legacy"), Some(path)).unwrap().unwrap();
        assert_eq!(set.authenticate("aaa").as_deref(), Some("laptop"));
        assert_eq!(set.authenticate("bbb").as_deref(), Some("ci-runner"));
        assert_eq!(set.authenticate("legacy").as_deref(), Some("default"));
        assert_eq!(set.authenticate("ccc"), None);
        // The digest is not itself a credential.
        assert_eq!(set.authenticate(&hex("aaa")), None);
    }

    #[test]
    fn removing_a_line_revokes_that_token_without_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        write(&path, &[("laptop", "aaa"), ("phone", "bbb")]);
        let set = TokenSet::new(None, Some(path.clone())).unwrap().unwrap();
        assert!(set.authenticate("aaa").is_some());
        write(&path, &[("phone", "bbb")]);
        assert_eq!(set.authenticate("aaa"), None);
        assert_eq!(set.authenticate("bbb").as_deref(), Some("phone"));
        write(&path, &[("phone", "bbb"), ("tablet", "ccc")]);
        assert_eq!(set.authenticate("ccc").as_deref(), Some("tablet"));
    }

    #[test]
    fn a_file_that_turns_invalid_or_disappears_fails_closed_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        write(&path, &[("laptop", "aaa")]);
        let set = TokenSet::new(Some("legacy"), Some(path.clone()))
            .unwrap()
            .unwrap();
        std::fs::write(&path, "laptop:not-a-digest\n").unwrap();
        assert_eq!(set.authenticate("aaa"), None);
        assert_eq!(set.authenticate("legacy").as_deref(), Some("default"));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(set.authenticate("aaa"), None);
        write(&path, &[("laptop", "aaa")]);
        assert_eq!(set.authenticate("aaa").as_deref(), Some("laptop"));
    }

    #[test]
    fn startup_rejects_a_missing_or_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(TokenSet::new(None, Some(dir.path().join("absent"))).is_err());
        for content in [
            "no-separator\n",
            "name:abc\n",
            "bad name:0000\n",
            &format!("default:{}\n", hex("x")),
            &format!("Default:{}\n", hex("x")),
            &format!("stdio:{}\n", hex("x")),
            &format!("anonymous:{}\n", hex("x")),
            &format!("a:{}\nA:{}\n", hex("x"), hex("y")),
            &format!("a:{0}\nb:{0}\n", hex("x")),
            &format!("a:{}\n", hex("")),
        ] {
            let path = dir.path().join("tokens");
            std::fs::write(&path, content).unwrap();
            assert!(TokenSet::new(None, Some(path)).is_err(), "{content}");
        }
    }

    #[test]
    fn an_empty_token_never_authenticates() {
        let set = TokenSet::new(Some("secret"), None).unwrap().unwrap();
        assert_eq!(set.authenticate(""), None);
    }

    #[test]
    fn a_session_belongs_to_the_client_that_opened_it() {
        let sessions = SessionOwners::default();
        sessions.bind("s1", Arc::from("laptop"));
        assert_eq!(sessions.access("s1", "laptop"), SessionAccess::Owner);
        assert_eq!(sessions.access("s1", "phone"), SessionAccess::Foreign);
        assert_eq!(sessions.access("s2", "laptop"), SessionAccess::Unknown);
        sessions.forget("s1");
        assert_eq!(sessions.access("s1", "laptop"), SessionAccess::Unknown);
    }

    #[test]
    fn the_oldest_session_is_forgotten_at_the_limit() {
        let sessions = SessionOwners::default();
        for index in 0..=MAX_TRACKED_SESSIONS {
            sessions.bind(&format!("s{index}"), Arc::from("laptop"));
        }
        assert_eq!(sessions.access("s0", "laptop"), SessionAccess::Unknown);
        assert_eq!(sessions.access("s1", "laptop"), SessionAccess::Owner);
        let newest = format!("s{MAX_TRACKED_SESSIONS}");
        assert_eq!(sessions.access(&newest, "laptop"), SessionAccess::Owner);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let content = format!("# clients\n\n  laptop : {}  \n", hex("aaa"));
        let tokens = parse_token_file(&content).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(&*tokens[0].0, "laptop");
    }
}
