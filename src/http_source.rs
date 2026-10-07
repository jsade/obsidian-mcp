//! Source-address allow-list for the HTTP transport.
//!
//! `OBSIDIAN_HTTP_ALLOWED_SOURCES` holds a comma-separated list of CIDR
//! blocks. When it is set, a request is served only if its source address is
//! inside one of them. The source is the last `X-Forwarded-For` value when
//! the header is present, else the connection's peer address. The header is
//! trusted as it stands, so the list protects a server only when every
//! request reaches it through a proxy that sets that header.

use std::net::IpAddr;

use axum::http::HeaderMap;

pub const SOURCES_VARIABLE: &str = "OBSIDIAN_HTTP_ALLOWED_SOURCES";

const FORWARDED_FOR: &str = "x-forwarded-for";

/// One CIDR block. The address has no bits set past the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    network: IpAddr,
    prefix: u8,
}

impl Block {
    fn parse(entry: &str) -> Result<Self, String> {
        let (address, prefix) = match entry.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (entry, None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| format!("'{entry}' is not an IP address or CIDR block"))?;
        let width = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix {
            // A bare address is a block of one.
            None => width,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= width)
                .ok_or_else(|| format!("'{entry}' has a prefix length outside 0-{width}"))?,
        };
        // Bits past the prefix usually mean a typing error in the prefix.
        if masked(network, prefix) != network {
            return Err(format!(
                "'{entry}' has address bits set past the /{prefix} prefix"
            ));
        }
        Ok(Self { network, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        let same_family = matches!(
            (self.network, address),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        );
        same_family && masked(address, self.prefix) == self.network
    }
}

fn masked(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    }
}

#[derive(Debug)]
pub struct SourceAllowList {
    blocks: Vec<Block>,
}

impl SourceAllowList {
    /// Read `OBSIDIAN_HTTP_ALLOWED_SOURCES`. `Ok(None)` means it is unset or
    /// holds no entries, and every source is served, as before.
    pub fn from_env() -> Result<Option<Self>, String> {
        match std::env::var(SOURCES_VARIABLE) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(format!("{SOURCES_VARIABLE} is not valid UTF-8"))
            }
        }
    }

    /// Parse a comma-separated list. One bad entry rejects the whole list, so
    /// a typing error cannot silently leave a range out or let one in.
    pub fn parse(value: &str) -> Result<Option<Self>, String> {
        let blocks = value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(Block::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("{SOURCES_VARIABLE}: {error}"))?;
        Ok((!blocks.is_empty()).then_some(Self { blocks }))
    }

    pub fn allows(&self, address: IpAddr) -> bool {
        let address = address.to_canonical();
        self.blocks.iter().any(|block| block.contains(address))
    }

    /// The listed blocks, for the startup log.
    pub fn describe(&self) -> Vec<String> {
        self.blocks
            .iter()
            .map(|block| format!("{}/{}", block.network, block.prefix))
            .collect()
    }
}

/// Why a request has no usable source address.
#[derive(Debug, PartialEq, Eq)]
pub enum NoSource {
    /// The last `X-Forwarded-For` value is not a bare IP address.
    Unparsable,
    /// No header, and the connection has no IP peer (a Unix socket).
    Unknown,
}

/// The address a request comes from: the last `X-Forwarded-For` value when
/// the header is present, else `peer`. A proxy that appends to the header
/// puts the address it saw last, so earlier values are the client's own
/// claims and are ignored. Several header lines count as one list in order.
pub fn request_source(headers: &HeaderMap, peer: Option<IpAddr>) -> Result<IpAddr, NoSource> {
    let Some(last_line) = headers.get_all(FORWARDED_FOR).iter().next_back() else {
        return peer
            .map(|peer| peer.to_canonical())
            .ok_or(NoSource::Unknown);
    };
    let value = last_line.to_str().map_err(|_| NoSource::Unparsable)?;
    let last = value.rsplit(',').next().unwrap_or_default().trim();
    last.parse::<IpAddr>()
        .map(|address| address.to_canonical())
        .map_err(|_| NoSource::Unparsable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn list(value: &str) -> SourceAllowList {
        SourceAllowList::parse(value).unwrap().unwrap()
    }

    fn ip(address: &str) -> IpAddr {
        address.parse().unwrap()
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn unset_or_blank_means_no_list() {
        assert!(SourceAllowList::parse("").unwrap().is_none());
        assert!(SourceAllowList::parse(" , ,").unwrap().is_none());
    }

    #[test]
    fn addresses_inside_a_block_pass_and_others_do_not() {
        let allowed = list("203.0.113.0/24, 2001:db8::/32");
        assert!(allowed.allows(ip("203.0.113.0")));
        assert!(allowed.allows(ip("203.0.113.255")));
        assert!(!allowed.allows(ip("203.0.112.255")));
        assert!(!allowed.allows(ip("203.0.114.0")));
        assert!(allowed.allows(ip("2001:db8:ffff::1")));
        assert!(!allowed.allows(ip("2001:db9::1")));
        // An IPv4 block never matches an IPv6 address or the reverse.
        assert!(!list("0.0.0.0/0").allows(ip("::1")));
        assert!(!list("::/0").allows(ip("127.0.0.1")));
    }

    #[test]
    fn an_ipv4_mapped_address_matches_its_ipv4_block() {
        assert!(list("203.0.113.0/24").allows(ip("::ffff:203.0.113.9")));
    }

    #[test]
    fn a_bare_address_is_a_block_of_one() {
        let allowed = list("203.0.113.7,::1");
        assert!(allowed.allows(ip("203.0.113.7")));
        assert!(!allowed.allows(ip("203.0.113.8")));
        assert!(allowed.allows(ip("::1")));
        assert_eq!(allowed.describe(), ["203.0.113.7/32", "::1/128"]);
    }

    #[test]
    fn zero_and_full_prefixes_work() {
        assert!(list("0.0.0.0/0").allows(ip("198.51.100.1")));
        assert!(list("198.51.100.1/32").allows(ip("198.51.100.1")));
        assert!(!list("198.51.100.1/32").allows(ip("198.51.100.2")));
    }

    #[test]
    fn an_invalid_entry_rejects_the_whole_list() {
        for value in [
            "203.0.113.0/33",
            "2001:db8::/129",
            "203.0.113.0/",
            "203.0.113.0/-1",
            "203.0.113.0/24x",
            "example.com",
            "203.0.113",
            "203.0.113.5/24",
            "203.0.113.0/24, nonsense",
            "/24",
        ] {
            let error = SourceAllowList::parse(value).unwrap_err();
            assert!(error.starts_with(SOURCES_VARIABLE), "{value}: {error}");
        }
    }

    #[test]
    fn the_last_forwarded_value_is_the_source() {
        let peer = Some(ip("127.0.0.1"));
        assert_eq!(
            request_source(&headers(&["203.0.113.5"]), peer),
            Ok(ip("203.0.113.5"))
        );
        // A client-supplied first value is ignored.
        assert_eq!(
            request_source(&headers(&["203.0.113.5, 198.51.100.7"]), peer),
            Ok(ip("198.51.100.7"))
        );
        assert_eq!(
            request_source(&headers(&["198.51.100.7,203.0.113.5"]), peer),
            Ok(ip("203.0.113.5"))
        );
        // Several header lines read as one list.
        assert_eq!(
            request_source(&headers(&["203.0.113.5", "198.51.100.7"]), peer),
            Ok(ip("198.51.100.7"))
        );
        assert_eq!(
            request_source(&headers(&[" 2001:db8::1 "]), peer),
            Ok(ip("2001:db8::1"))
        );
        assert_eq!(
            request_source(&headers(&["::ffff:203.0.113.5"]), peer),
            Ok(ip("203.0.113.5"))
        );
    }

    #[test]
    fn an_unparsable_last_value_has_no_source() {
        let peer = Some(ip("127.0.0.1"));
        for value in [
            "",
            "garbage",
            "203.0.113.5,",
            "198.51.100.7, garbage",
            "203.0.113.5:443",
            "[2001:db8::1]",
            "unknown",
        ] {
            assert_eq!(
                request_source(&headers(&[value]), peer),
                Err(NoSource::Unparsable),
                "{value:?}"
            );
        }
        // An allowed address in an earlier line does not rescue a bad last one.
        assert_eq!(
            request_source(&headers(&["203.0.113.5", "garbage"]), peer),
            Err(NoSource::Unparsable)
        );
        let mut opaque = HeaderMap::new();
        opaque.insert(
            FORWARDED_FOR,
            HeaderValue::from_bytes(b"203.0.113.\xff").unwrap(),
        );
        assert_eq!(request_source(&opaque, peer), Err(NoSource::Unparsable));
    }

    #[test]
    fn without_the_header_the_peer_is_the_source() {
        let allowed = list("203.0.113.0/24");
        let inside = request_source(&HeaderMap::new(), Some(ip("203.0.113.9"))).unwrap();
        assert!(allowed.allows(inside));
        let outside = request_source(&HeaderMap::new(), Some(ip("198.51.100.9"))).unwrap();
        assert!(!allowed.allows(outside));
        let mapped = request_source(&HeaderMap::new(), Some(ip("::ffff:203.0.113.9"))).unwrap();
        assert!(allowed.allows(mapped));
        assert_eq!(
            request_source(&HeaderMap::new(), None),
            Err(NoSource::Unknown)
        );
    }
}
