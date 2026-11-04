//! Peer routing identifiers (`plan.md` §2.1, §3.2).
//!
//! This module keeps two things that look similar but are not the same,
//! strictly apart — a distinction the plan calls out explicitly:
//!
//! * [`OnionId`] — a Tor v3 address. **Routing only.** It is
//!   `base32(SHA3-256(pubkey ‖ blinded_pubkey ‖ version)[..35]).onion` and is
//!   produced by the onion service, not by this crate.
//! * A *contact code* — the durable, human-shareable identity
//!   (`anon-core::ContactCode`). This crate does not participate in identity.
//!
//! Treating an onion address as an identity would be a security bug: onion
//! addresses are rotatable and blinded, so they are not a stable identity.

use crate::TransportError;

/// Length of the base32 portion of a v3 onion address, before `.onion`.
///
/// A v3 address encodes a 35-byte value (32-byte pubkey + 2-byte checksum +
/// 1-byte version). `plan.md` §3.1 verification note.
pub const ONION_BASE32_LEN: usize = 56;

/// The `.onion` suffix.
pub const ONION_SUFFIX: &str = ".onion";

/// A validated Tor v3 onion address.
///
/// Holding this type is proof the string was structurally a v3 address. It makes
/// no claim that the address exists or is reachable.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct OnionId(String);

impl OnionId {
    /// Parse and validate an onion address.
    ///
    /// v3 addresses are exactly 56 base32 characters (RFC 4648 lowercase, with
    /// no padding) followed by `.onion`.
    pub fn parse(text: &str) -> Result<Self, TransportError> {
        let trimmed = text.trim();
        let lower = trimmed.to_ascii_lowercase();

        let body = lower.strip_suffix(ONION_SUFFIX).ok_or_else(|| {
            TransportError::InvalidRoute("onion address must end with `.onion`".to_string())
        })?;

        if body.len() != ONION_BASE32_LEN {
            return Err(TransportError::InvalidRoute(format!(
                "v3 onion address must be {ONION_BASE32_LEN} base32 characters, found {}",
                body.len()
            )));
        }

        if !body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(TransportError::InvalidRoute(
                "onion address contains characters outside the base32 alphabet".to_string(),
            ));
        }

        Ok(Self(lower))
    }

    /// The address as text, including the `.onion` suffix.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// First 12 characters of the base32 body, for display in a UI.
    ///
    /// Short enough to fit a label, long enough to distinguish peers at a
    /// glance. Not an identity — see the module docs.
    pub fn short_label(&self) -> String {
        self.0.chars().take(12).collect()
    }
}

impl std::fmt::Display for OnionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a route is intended to be reached.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteKind {
    /// Onion-service rendezvous. The only kind valid for internet delivery.
    OnionRendezvous,
    /// A local-only route, used by tests. Never valid for real delivery.
    Local,
}

/// Where a payload is going.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PeerRoute {
    kind: RouteKind,
    target: String,
}

impl PeerRoute {
    /// Build an onion rendezvous route.
    pub fn onion(id: OnionId) -> Self {
        Self {
            kind: RouteKind::OnionRendezvous,
            target: id.0,
        }
    }

    /// Build a local (test-only) route.
    pub fn local(name: impl Into<String>) -> Self {
        Self {
            kind: RouteKind::Local,
            target: name.into(),
        }
    }

    /// The kind of route.
    pub fn kind(&self) -> RouteKind {
        self.kind
    }

    /// Whether this route is valid for delivering to a real peer.
    pub fn is_internet_routable(&self) -> bool {
        matches!(self.kind, RouteKind::OnionRendezvous)
    }

    /// The onion address this route targets, when it is an onion route.
    ///
    /// Exposed so a caller that must persist a route (the send queue) can store
    /// the address itself rather than a display string it would have to parse
    /// back out.
    pub fn onion_target(&self) -> Option<&str> {
        match self.kind {
            RouteKind::OnionRendezvous => Some(&self.target),
            RouteKind::Local => None,
        }
    }

    /// Human-readable description for logs. Contains no secret material — an
    /// onion address is public by nature.
    pub fn describe(&self) -> String {
        match self.kind {
            RouteKind::OnionRendezvous => format!("onion:{}", self.target),
            RouteKind::Local => format!("local:{}", self.target),
        }
    }
}

impl OnionId {
    /// Length of the base32 body. Test helper.
    #[cfg(test)]
    fn base32_body_len(&self) -> usize {
        self.0.trim_end_matches(ONION_SUFFIX).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";

    #[test]
    fn parses_a_valid_v3_address() {
        let id = OnionId::parse(VALID).unwrap();
        assert_eq!(id.as_str(), VALID);
        assert_eq!(id.base32_body_len(), 56);
    }

    #[test]
    fn is_case_insensitive_and_trims_whitespace() {
        let upper = VALID.to_ascii_uppercase();
        let id = OnionId::parse(&format!("  {upper}  ")).unwrap();
        assert_eq!(id.as_str(), VALID);
    }

    #[test]
    fn rejects_missing_suffix() {
        let bad = VALID.trim_end_matches(".onion");
        assert!(OnionId::parse(bad).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        // v2-style 16-character addresses are no longer acceptable.
        let short = "vww6ybal4bd7szmg.onion";
        assert!(OnionId::parse(short).is_err());
    }

    #[test]
    fn rejects_non_base32_characters() {
        // '0', '1', '8', '9' are not in the base32 alphabet.
        let mut body: Vec<char> = VALID.trim_end_matches(".onion").chars().collect();
        body[0] = '0';
        let bad: String = body.into_iter().collect::<String>() + ".onion";
        assert!(OnionId::parse(&bad).is_err());
    }

    #[test]
    fn short_label_is_twelve_chars() {
        let id = OnionId::parse(VALID).unwrap();
        assert_eq!(id.short_label().len(), 12);
        assert!(VALID.starts_with(&id.short_label()));
    }

    #[test]
    fn onion_routes_are_internet_routable_local_ones_are_not() {
        let onion = PeerRoute::onion(OnionId::parse(VALID).unwrap());
        assert!(onion.is_internet_routable());
        assert_eq!(onion.kind(), RouteKind::OnionRendezvous);

        let local = PeerRoute::local("selftest");
        assert!(!local.is_internet_routable());
        assert_eq!(local.kind(), RouteKind::Local);
    }

    #[test]
    fn describe_contains_no_secret_and_is_stable() {
        let onion = PeerRoute::onion(OnionId::parse(VALID).unwrap());
        assert_eq!(onion.describe(), format!("onion:{VALID}"));
        assert_eq!(PeerRoute::local("x").describe(), "local:x");
    }
}
