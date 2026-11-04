//! Bridge and pluggable-transport configuration (`GAP-CLOSURE-PLAN.md` Gap 3, item 3).
//!
//! # Why this exists
//!
//! A user behind a censoring network cannot reach the ordinary Tor directory
//! authorities. Their only route onto the network is a **bridge**: an unlisted relay,
//! usually wrapped in a **pluggable transport** (obfs4, snowflake, ...) that makes the
//! connection not look like Tor. Without a way to supply bridge lines, this app is
//! simply unusable for exactly the people who need it most.
//!
//! # The rule this module enforces
//!
//! **Bridges requested but unusable is an error, never a silent fallback.**
//!
//! If a user configures bridges because direct connections are blocked, and we quietly
//! connect directly instead, we have done two bad things at once: we ignored their
//! instruction, and we made a connection they specifically asked us not to make. That is
//! a privacy failure, not a convenience. So every failure path here returns an error and
//! the transport stays `Failed` — sending stays disabled rather than leaking.
//!
//! The same reasoning applies to a malformed bridge line. Skipping it and carrying on
//! with the remaining lines would mean "some of your bridges are in use", which the user
//! cannot distinguish from "all of them are". A typo must be loud.
//!
//! # Where configuration comes from
//!
//! Two sources, in increasing precedence:
//!
//! 1. `tor.conf` in the app's data directory — one directive per line, `#` comments.
//! 2. The `ANON_TOR_BRIDGES` environment variable — one bridge line per entry, separated
//!    by newlines or semicolons. An environment variable is the escape hatch for a user
//!    who cannot edit a file (a locked-down machine, a container).
//!
//! The environment variable *replaces* the file's bridge list rather than appending to
//! it. Merging two lists would make "which bridges am I actually using?" ambiguous, and
//! ambiguity about the anonymity path is the thing this module exists to prevent.

use crate::error::{Result, TransportError};

/// The environment variable carrying bridge lines.
///
/// Newline- or semicolon-separated. Set this instead of writing `tor.conf` when the data
/// directory is not writable.
pub const BRIDGES_ENV: &str = "ANON_TOR_BRIDGES";

/// The file name read from the app's data directory.
pub const CONFIG_FILE_NAME: &str = "tor.conf";

/// The directive that introduces a bridge line in `tor.conf`.
const BRIDGE_DIRECTIVE: &str = "Bridge";

/// The directive that introduces a pluggable-transport binary in `tor.conf`.
const TRANSPORT_DIRECTIVE: &str = "UseTransport";

/// Bridge and pluggable-transport settings for the Arti transport.
///
/// The default is "no bridges", which means "connect directly". That default is correct
/// for an uncensored network and is *not* a fallback: it is only reached when the user
/// asked for nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TorConfig {
    /// Bridge lines, verbatim as the user supplied them.
    ///
    /// Kept as strings rather than parsed values so the error message can quote exactly
    /// what the user wrote. Parsing happens in [`TorConfig::validate`].
    bridges: Vec<String>,
    /// Pluggable-transport binaries, as `protocol=/path/to/binary`.
    ///
    /// A bridge line whose first word is a transport name (`obfs4 ...`) needs a matching
    /// entry here, or Arti cannot launch the transport and the bridge is unusable.
    transports: Vec<String>,
    data_dir: Option<std::path::PathBuf>,
}

impl TorConfig {
    /// An empty configuration: no bridges, direct connections.
    pub fn none() -> Self {
        Self::default()
    }

    /// Build a configuration from bridge lines.
    ///
    /// Does not validate; call [`TorConfig::validate`] before handing this to Arti. Kept
    /// separate so a caller can accumulate lines and report *all* the bad ones at once
    /// rather than failing on the first.
    pub fn with_bridges<I, S>(bridges: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            bridges: bridges.into_iter().map(Into::into).collect(),
            transports: Vec::new(),
            data_dir: None,
        }
    }

    /// Add a pluggable-transport binary as `protocol=/path/to/binary`.
    pub fn with_transport(mut self, protocol: impl Into<String>, path: impl Into<String>) -> Self {
        self.transports
            .push(format!("{}={}", protocol.into(), path.into()));
        self
    }

    /// The configured bridge lines.
    pub fn bridges(&self) -> &[String] {
        &self.bridges
    }

    /// The configured pluggable transports, as `protocol=/path` strings.
    pub fn transports(&self) -> &[String] {
        &self.transports
    }

    /// Whether any bridge was requested.
    ///
    /// This is the flag that decides whether a failure to use bridges is fatal. See the
    /// module docs: once this is `true`, there is no direct-connection fallback.
    pub fn bridges_requested(&self) -> bool {
        !self.bridges.is_empty()
    }

    /// Keep Arti state and cache separate from other applications and profiles.
    pub fn with_data_dir(mut self, data_dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    #[cfg(feature = "arti")]
    pub(crate) fn data_dir(&self) -> Option<&std::path::Path> {
        self.data_dir.as_deref()
    }

    /// Parse `tor.conf` contents.
    ///
    /// Format: one directive per line. Blank lines and lines whose first non-space
    /// character is `#` are ignored. Recognised directives:
    ///
    /// ```text
    /// Bridge obfs4 192.0.2.55:38114 316E6433... cert=... iat-mode=0
    /// UseTransport obfs4=/usr/bin/obfs4proxy
    /// ```
    ///
    /// An unrecognised directive is an error rather than being ignored: a user who wrote
    /// `Bridges` instead of `Bridge` believes their bridges are configured, and silently
    /// dropping the line would leave them connecting directly while believing otherwise.
    pub fn parse(contents: &str) -> Result<Self> {
        let mut config = Self::default();

        for (index, raw) in contents.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (directive, rest) = match line.split_once(char::is_whitespace) {
                Some((d, r)) => (d, r.trim()),
                None => (line, ""),
            };

            if directive.eq_ignore_ascii_case(BRIDGE_DIRECTIVE) {
                if rest.is_empty() {
                    return Err(TransportError::Failed(format!(
                        "{}:{}: `{BRIDGE_DIRECTIVE}` with no bridge line. A bridge line looks \
                         like `Bridge obfs4 <host>:<port> <fingerprint> cert=...`.",
                        CONFIG_FILE_NAME,
                        index + 1
                    )));
                }
                config.bridges.push(rest.to_string());
            } else if directive.eq_ignore_ascii_case(TRANSPORT_DIRECTIVE) {
                if rest.is_empty() {
                    return Err(TransportError::Failed(format!(
                        "{}:{}: `{TRANSPORT_DIRECTIVE}` with no value. Expected \
                         `{TRANSPORT_DIRECTIVE} <protocol>=<path-to-binary>`.",
                        CONFIG_FILE_NAME,
                        index + 1
                    )));
                }
                config.transports.push(rest.to_string());
            } else {
                return Err(TransportError::Failed(format!(
                    "{}:{}: unknown directive `{directive}`. Supported directives are \
                     `{BRIDGE_DIRECTIVE}` and `{TRANSPORT_DIRECTIVE}`.",
                    CONFIG_FILE_NAME,
                    index + 1
                )));
            }
        }

        Ok(config)
    }

    /// Parse bridge lines from the `ANON_TOR_BRIDGES` environment variable.
    ///
    /// Entries are separated by newlines or semicolons. A leading `Bridge ` prefix is
    /// tolerated so a user can paste lines straight from a bridge-distribution email
    /// without editing them.
    pub fn from_env_value(value: &str) -> Self {
        let bridges = value
            .split(['\n', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                // Tolerate the `Bridge ` prefix from a pasted bridge line. Case-insensitive
                // because bridge-distribution emails are inconsistent about it.
                match s.split_once(char::is_whitespace) {
                    Some((first, rest)) if first.eq_ignore_ascii_case(BRIDGE_DIRECTIVE) => {
                        rest.trim().to_string()
                    }
                    _ => s.to_string(),
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            bridges,
            transports: Vec::new(),
            data_dir: None,
        }
    }

    /// Load configuration from the environment, falling back to `tor.conf` in `data_dir`.
    ///
    /// The environment variable wins when set. A missing `tor.conf` is not an error — it
    /// means "no bridges", which is the normal case.
    ///
    /// A `tor.conf` that exists but cannot be read *is* an error: a permissions problem
    /// would otherwise look identical to "no bridges configured", and the user would
    /// connect directly while believing their bridges were in use.
    pub fn load(data_dir: &std::path::Path) -> Result<Self> {
        let path = data_dir.join(CONFIG_FILE_NAME);
        let mut config = match std::fs::read_to_string(&path) {
            Ok(contents) => Self::parse(&contents)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::none(),
            Err(e) => {
                return Err(TransportError::Failed(format!(
                    "could not read {}: {e}. Refusing to guess: an unreadable bridge \
                 configuration must not be treated as \"no bridges\", because that would \
                 connect directly when bridges were requested.",
                    path.display()
                )))
            }
        };
        match std::env::var(BRIDGES_ENV) {
            Ok(value) if !value.trim().is_empty() => {
                let override_config = Self::from_env_value(&value);
                if !override_config.bridges_requested() {
                    return Err(TransportError::Failed(
                        "ANON_TOR_BRIDGES contains no bridge lines; refusing a direct connection"
                            .to_string(),
                    ));
                }
                config.bridges = override_config.bridges;
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(TransportError::Failed(
                    "ANON_TOR_BRIDGES is not valid Unicode; refusing a direct connection"
                        .to_string(),
                ));
            }
            _ => {}
        }
        Ok(config)
    }

    /// Validate every bridge line and transport, failing closed on the first problem.
    ///
    /// Returns the parsed bridge lines so the caller does not have to parse twice. The
    /// error names the offending line verbatim, because "invalid bridge" without the text
    /// is not actionable when a user has pasted six lines.
    ///
    /// # What "valid" means here
    ///
    /// A bridge line must have at least two whitespace-separated words: an address
    /// (`host:port`, or a transport name followed by `host:port`) and a fingerprint. That
    /// is the minimum shape of every bridge line Tor distributes. Full syntax validation
    /// is Arti's job — [`crate::arti::ArtiTransport::bootstrap_with_config`] hands the
    /// lines to `BridgeConfigBuilder`, whose parser is authoritative. This check exists so
    /// an obviously malformed line fails with *our* message before we build a client.
    pub fn validate(&self) -> Result<Vec<String>> {
        for line in &self.bridges {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.len() < 2 {
                return Err(TransportError::Failed(format!(
                    "malformed bridge line {line:?}: expected at least an address and a \
                     fingerprint, e.g. `obfs4 192.0.2.55:38114 <fingerprint> cert=...`. \
                     Refusing to fall back to a direct connection when bridges were \
                     requested."
                )));
            }

            // A line whose first word is not a `host:port` is treated as a pluggable
            // transport name, and then a matching transport binary must be configured.
            // Without one Arti cannot launch the transport, so the bridge is unusable —
            // and "bridges requested but unusable" is fatal, not a fallback.
            let first = words[0];
            if !looks_like_host_port(first) && !self.has_transport(first) {
                return Err(TransportError::Failed(format!(
                    "bridge line {line:?} uses pluggable transport `{first}`, but no \
                     transport binary is configured for it. Add \
                     `{TRANSPORT_DIRECTIVE} {first}=<path-to-binary>` to {CONFIG_FILE_NAME}. \
                     Refusing to fall back to a direct connection when bridges were \
                     requested."
                )));
            }
        }

        for transport in &self.transports {
            let Some((protocol, path)) = transport.split_once('=') else {
                return Err(TransportError::Failed(format!(
                    "malformed transport {transport:?}: expected `<protocol>=<path-to-binary>`, \
                     e.g. `obfs4=/usr/bin/obfs4proxy`."
                )));
            };
            if protocol.trim().is_empty() || path.trim().is_empty() {
                return Err(TransportError::Failed(format!(
                    "malformed transport {transport:?}: both the protocol name and the \
                     binary path must be non-empty."
                )));
            }
        }

        Ok(self.bridges.clone())
    }

    /// Whether a transport binary is configured for `protocol`.
    fn has_transport(&self, protocol: &str) -> bool {
        self.transports.iter().any(|t| {
            t.split_once('=')
                .map(|(p, _)| p.trim().eq_ignore_ascii_case(protocol))
                .unwrap_or(false)
        })
    }
}

/// Whether `word` looks like a `host:port` address rather than a transport name.
///
/// Deliberately loose: this only has to distinguish `192.0.2.55:38114` and
/// `bridge.example.net:443` from `obfs4`. Anything with a colon and a numeric port is
/// treated as an address; Arti's parser makes the real decision.
fn looks_like_host_port(word: &str) -> bool {
    match word.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that read or write [`BRIDGES_ENV`].
    ///
    /// Cargo runs the tests in one binary on parallel threads and the environment is
    /// process-wide. Three tests here set and restore that variable; without this lock one
    /// test's "no bridges" state could be observed by another test's "bridges configured"
    /// assertion, and the failure would look like a bug in `load` rather than in the test.
    /// Poisoning is ignored so one panic does not cascade into misleading failures.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Acquires [`ENV_LOCK`], ignoring poisoning.
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn the_default_is_no_bridges_and_no_fallback_concern() {
        let config = TorConfig::none();
        assert!(!config.bridges_requested());
        assert!(config.bridges().is_empty());
        assert!(config.transports().is_empty());
        // Validating "no bridges" succeeds: there is nothing to be unusable.
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_valid_direct_bridge_line_is_accepted_and_passed_through() {
        let line = "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956";
        let config = TorConfig::with_bridges([line]);

        assert!(config.bridges_requested());
        let validated = config.validate().expect("a well-formed line must validate");
        assert_eq!(validated, vec![line.to_string()]);
    }

    #[test]
    fn a_valid_obfs4_bridge_line_is_accepted_when_its_transport_is_configured() {
        let line = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F \
                    cert=YXJlIGZyZXF1ZW50bHkgZnVsbA iat-mode=0";
        let config = TorConfig::with_bridges([line]).with_transport("obfs4", "/usr/bin/obfs4proxy");

        let validated = config
            .validate()
            .expect("a configured transport must validate");
        assert_eq!(validated.len(), 1);
    }

    #[test]
    fn a_malformed_bridge_line_is_rejected_rather_than_skipped() {
        // One word: no fingerprint. This is the "typo" case — the user believes bridges
        // are configured. Skipping it would connect directly while they believed
        // otherwise, so it must be an error.
        let config = TorConfig::with_bridges(["obfs4"]);
        let err = config
            .validate()
            .expect_err("a one-word line must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("malformed bridge line"),
            "the error must say what is wrong, got: {message}"
        );
        assert!(
            message.contains("Refusing to fall back to a direct connection"),
            "the error must state the privacy consequence, got: {message}"
        );
    }

    #[test]
    fn bridges_requested_but_unusable_fails_closed() {
        // An obfs4 bridge with no transport binary configured. Arti cannot launch the
        // transport, so the bridge cannot be used. Falling back to direct would be a
        // privacy failure, so this must be an error.
        let line = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc";
        let config = TorConfig::with_bridges([line]);

        let err = config
            .validate()
            .expect_err("a bridge needing a missing transport must fail closed");
        let message = err.to_string();
        assert!(
            message.contains("no transport binary is configured"),
            "the error must name the missing transport, got: {message}"
        );
        assert!(
            message.contains("Refusing to fall back to a direct connection"),
            "the error must state the privacy consequence, got: {message}"
        );
    }

    #[test]
    fn a_malformed_transport_directive_is_rejected() {
        let config = TorConfig::none().with_transport("obfs4", "");
        let err = config
            .validate()
            .expect_err("an empty path must be rejected");
        assert!(err.to_string().contains("malformed transport"));
    }

    #[test]
    fn tor_conf_parses_bridges_and_transports_and_ignores_comments() {
        let contents = "\
# Bridges for a censored network.
# A comment line is ignored.

Bridge obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc iat-mode=0
UseTransport obfs4=/usr/bin/obfs4proxy
";
        let config = TorConfig::parse(contents).expect("a well-formed file must parse");
        assert_eq!(config.bridges().len(), 1);
        assert_eq!(config.transports().len(), 1);
        assert!(config.bridges_requested());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_unknown_directive_is_an_error_not_a_silent_skip() {
        // `Bridges` (plural) is the plausible typo. Ignoring it would leave the user
        // connecting directly while believing their bridges were configured.
        let err = TorConfig::parse("Bridges obfs4 192.0.2.55:38114 abc")
            .expect_err("an unknown directive must be rejected");
        let message = err.to_string();
        assert!(message.contains("unknown directive"), "got: {message}");
        assert!(
            message.contains("tor.conf:1"),
            "the error must give the line, got: {message}"
        );
    }

    #[test]
    fn a_bridge_directive_with_no_line_is_an_error() {
        let err = TorConfig::parse("Bridge").expect_err("an empty bridge directive must fail");
        assert!(err.to_string().contains("no bridge line"));
    }

    #[test]
    fn the_environment_form_accepts_newlines_semicolons_and_a_bridge_prefix() {
        let value = "Bridge 192.0.2.83:80 $0bac3941; obfs4 192.0.2.55:38114 abc\n\n";
        let config = TorConfig::from_env_value(value);

        assert_eq!(
            config.bridges(),
            &[
                "192.0.2.83:80 $0bac3941".to_string(),
                "obfs4 192.0.2.55:38114 abc".to_string(),
            ],
            "the `Bridge ` prefix must be stripped and separators honoured"
        );
    }

    #[test]
    fn an_empty_environment_value_requests_no_bridges() {
        let config = TorConfig::from_env_value("   \n ; \n");
        assert!(!config.bridges_requested());
    }

    #[test]
    fn a_missing_config_file_means_no_bridges() {
        let dir = std::env::temp_dir().join("anon-tor-config-missing-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");

        // Guard against a developer's own ANON_TOR_BRIDGES leaking into the test.
        let _env_guard = lock_env();
        let previous = std::env::var(BRIDGES_ENV).ok();
        std::env::remove_var(BRIDGES_ENV);

        let config = TorConfig::load(&dir).expect("a missing file is not an error");
        assert!(!config.bridges_requested());

        match previous {
            Some(v) => std::env::set_var(BRIDGES_ENV, v),
            None => std::env::remove_var(BRIDGES_ENV),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_config_file_in_the_data_directory_is_read() {
        let dir = std::env::temp_dir().join("anon-tor-config-read-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join(CONFIG_FILE_NAME),
            "Bridge 192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956\nUseTransport obfs4=obfs4proxy\n",
        )
        .expect("write config");

        let _env_guard = lock_env();
        let previous = std::env::var(BRIDGES_ENV).ok();
        std::env::remove_var(BRIDGES_ENV);

        let config = TorConfig::load(&dir).expect("a readable file must load");
        assert_eq!(config.bridges().len(), 1);

        match previous {
            Some(v) => std::env::set_var(BRIDGES_ENV, v),
            None => std::env::remove_var(BRIDGES_ENV),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_environment_variable_wins_over_the_file() {
        let dir = std::env::temp_dir().join("anon-tor-config-precedence-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join(CONFIG_FILE_NAME),
            "Bridge 192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956\nUseTransport obfs4=obfs4proxy\n",
        )
        .expect("write config");

        let _env_guard = lock_env();
        let previous = std::env::var(BRIDGES_ENV).ok();
        std::env::set_var(
            BRIDGES_ENV,
            "198.51.100.25:443 $7DD62766BF2052432051D7B7E08A22F7E34A4543",
        );

        let config = TorConfig::load(&dir).expect("the environment value must load");
        assert_eq!(
            config.bridges(),
            &["198.51.100.25:443 $7DD62766BF2052432051D7B7E08A22F7E34A4543".to_string()],
            "the environment variable must replace the file's list, not merge with it"
        );
        assert_eq!(config.transports(), &["obfs4=obfs4proxy".to_string()]);
        std::env::set_var(BRIDGES_ENV, "; ;");
        assert!(
            TorConfig::load(&dir).is_err(),
            "empty bridge entries must not fall back"
        );

        match previous {
            Some(v) => std::env::set_var(BRIDGES_ENV, v),
            None => std::env::remove_var(BRIDGES_ENV),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_port_detection_distinguishes_addresses_from_transport_names() {
        assert!(looks_like_host_port("192.0.2.55:38114"));
        assert!(looks_like_host_port("bridge.example.net:443"));
        assert!(!looks_like_host_port("obfs4"));
        assert!(!looks_like_host_port("snowflake"));
        // A colon with a non-numeric port is not an address.
        assert!(!looks_like_host_port("obfs4:notaport"));
    }
}
