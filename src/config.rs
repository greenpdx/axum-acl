//! TOML configuration support for ACL rules.
//!
//! This module provides structures for loading ACL rules from TOML configuration,
//! either compiled-in at build time or read from a file at runtime.
//!
//! # Example TOML Format
//!
//! ```toml
//! [settings]
//! default_action = "deny"
//!
//! [[rules]]
//! role = "admin"
//! endpoint = "*"
//! action = "allow"
//! description = "Admins have full access"
//!
//! [[rules]]
//! role = "user"
//! endpoint = "/api/**"
//! time = { start = 9, end = 17, days = [0,1,2,3,4] }
//! action = "allow"
//!
//! [[rules]]
//! role = "*"
//! endpoint = "/blocked/**"
//! action = { type = "error", code = 403, message = "Access forbidden" }
//! ```
//!
//! # Usage
//!
//! ## Compile-time embedded config
//!
//! ```ignore
//! use axum_acl::AclTable;
//!
//! // Embed at compile time
//! const ACL_CONFIG: &str = include_str!("../acl.toml");
//!
//! let table = AclTable::from_toml(ACL_CONFIG).unwrap();
//! ```
//!
//! ## Runtime file loading
//!
//! ```ignore
//! use axum_acl::AclTable;
//!
//! let table = AclTable::from_toml_file("config/acl.toml").unwrap();
//! ```

use crate::rule::{AclAction, AclRuleFilter, EndpointPattern, IpMatcher, TimeWindow};
use crate::table::AclTable;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// Global settings.
    #[serde(default)]
    pub settings: ConfigSettings,
    /// List of ACL rules.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

/// Global configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSettings {
    /// Default action when no rules match.
    #[serde(default = "default_action")]
    pub default_action: ActionConfig,
}

fn default_action() -> ActionConfig {
    ActionConfig::Simple(SimpleAction::Deny)
}

impl Default for ConfigSettings {
    fn default() -> Self {
        Self {
            default_action: default_action(),
        }
    }
}

/// A single rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Role bitmask. Use 0xFFFFFFFF for all roles, or specific bits like 0b11.
    /// Can be decimal (e.g., 3), hex (e.g., "0x3"), or binary string.
    #[serde(default = "default_role_mask")]
    pub role_mask: RoleMaskConfig,

    /// ID to match. Use "*" for any ID.
    #[serde(default = "default_id")]
    pub id: String,

    /// Endpoint pattern to match.
    /// - "*" or "any" for all endpoints
    /// - "/path/" (trailing slash) for prefix match
    /// - "/path/**" for glob match
    /// - "/path" for exact match
    #[serde(default = "default_endpoint")]
    pub endpoint: String,

    /// HTTP methods to match (optional). Empty means all methods.
    #[serde(default)]
    pub methods: Vec<String>,

    /// Time window configuration (optional).
    #[serde(default)]
    pub time: Option<TimeConfig>,

    /// IP address/CIDR to match (optional). "*" or omitted means any IP.
    #[serde(default)]
    pub ip: Option<String>,

    /// Action to take when rule matches.
    pub action: ActionConfig,

    /// Optional description for logging/debugging.
    #[serde(default)]
    pub description: Option<String>,

    /// Priority (lower = higher priority). Rules are sorted by priority.
    #[serde(default = "default_priority")]
    pub priority: i32,
}

/// Role mask configuration - can be a number or string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoleMaskConfig {
    /// Numeric role mask.
    Number(u32),
    /// String role mask (can be hex like "0xFF" or "*" for all).
    String(String),
}

impl RoleMaskConfig {
    /// Convert to u32 bitmask.
    pub fn to_mask(&self) -> u32 {
        match self {
            RoleMaskConfig::Number(n) => *n,
            RoleMaskConfig::String(s) => {
                let s = s.trim();
                if s == "*" || s.eq_ignore_ascii_case("all") {
                    u32::MAX
                } else if let Some(hex) = s.strip_prefix("0x") {
                    u32::from_str_radix(hex, 16).unwrap_or(u32::MAX)
                } else if let Some(bin) = s.strip_prefix("0b") {
                    u32::from_str_radix(bin, 2).unwrap_or(u32::MAX)
                } else {
                    s.parse().unwrap_or(u32::MAX)
                }
            }
        }
    }
}

fn default_role_mask() -> RoleMaskConfig {
    RoleMaskConfig::Number(u32::MAX)
}

fn default_id() -> String {
    "*".to_string()
}

fn default_endpoint() -> String {
    "*".to_string()
}

fn default_priority() -> i32 {
    100
}

/// Time window configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConfig {
    /// Start hour (0-23).
    #[serde(default)]
    pub start: Option<u32>,
    /// End hour (0-23).
    #[serde(default)]
    pub end: Option<u32>,
    /// Days of week (0=Monday, 6=Sunday). Empty means all days.
    #[serde(default)]
    pub days: Vec<u32>,
}

/// Action configuration - can be simple string or complex object.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionConfig {
    /// Simple action: "allow", "deny"
    Simple(SimpleAction),
    /// Complex action with parameters
    Complex(ComplexAction),
}

/// Simple action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SimpleAction {
    /// Allow the request.
    Allow,
    /// Deny with 403 Forbidden.
    Deny,
    /// Block (same as deny, alias).
    Block,
}

/// Complex action with additional parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ComplexAction {
    /// Allow the request.
    Allow,
    /// Deny with 403.
    Deny,
    /// Block (alias for deny).
    Block,
    /// Return a custom error response.
    Error {
        /// HTTP status code.
        #[serde(default = "default_error_code")]
        code: u16,
        /// Error message body.
        #[serde(default)]
        message: Option<String>,
    },
    /// Reroute to a different path.
    Reroute {
        /// Target path to reroute to.
        target: String,
        /// Whether to preserve the original path as a header.
        #[serde(default)]
        preserve_path: bool,
    },
    /// Rate limit the request.
    RateLimit {
        /// Maximum requests per window.
        max_requests: u32,
        /// Window duration in seconds.
        window_secs: u64,
    },
    /// Log and allow (for monitoring).
    Log {
        /// Log level: "trace", "debug", "info", "warn", "error"
        #[serde(default = "default_log_level")]
        level: String,
        /// Custom log message.
        #[serde(default)]
        message: Option<String>,
    },
}

fn default_error_code() -> u16 {
    403
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Error type for configuration parsing.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// TOML parsing error.
    #[error("Failed to parse TOML: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// File I/O error.
    #[error("Failed to read config file: {0}")]
    FileRead(#[from] std::io::Error),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    Invalid(String),

    /// Invalid IP pattern.
    #[error("Invalid IP pattern '{0}': {1}")]
    InvalidIp(String, String),

    /// Invalid action configuration.
    #[error("Invalid action configuration: {0}")]
    InvalidAction(String),
}

impl AclConfig {
    /// Parse configuration from a TOML string.
    ///
    /// # Example
    /// ```
    /// use axum_acl::TomlConfig;
    ///
    /// let toml = r#"
    /// [settings]
    /// default_action = "deny"
    ///
    /// [[rules]]
    /// role = "admin"
    /// endpoint = "*"
    /// action = "allow"
    /// "#;
    ///
    /// let config = TomlConfig::from_toml(toml).unwrap();
    /// ```
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let config: AclConfig = toml::from_str(toml_str)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a TOML file.
    ///
    /// # Example
    /// ```ignore
    /// use axum_acl::AclConfig;
    ///
    /// let config = AclConfig::from_file("config/acl.toml").unwrap();
    /// ```
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<(), ConfigError> {
        for (i, rule) in self.rules.iter().enumerate() {
            // Validate IP pattern if provided
            if let Some(ref ip) = rule.ip {
                if ip != "*" && !ip.eq_ignore_ascii_case("any") {
                    IpMatcher::parse(ip)
                        .map_err(|e| ConfigError::InvalidIp(ip.clone(), e))?;
                }
            }

            // Validate time config
            if let Some(ref time) = rule.time {
                if let Some(start) = time.start {
                    if start > 23 {
                        return Err(ConfigError::Invalid(format!(
                            "Rule {}: start hour {} is invalid (must be 0-23)",
                            i, start
                        )));
                    }
                }
                if let Some(end) = time.end {
                    if end > 23 {
                        return Err(ConfigError::Invalid(format!(
                            "Rule {}: end hour {} is invalid (must be 0-23)",
                            i, end
                        )));
                    }
                }
                for &day in &time.days {
                    if day > 6 {
                        return Err(ConfigError::Invalid(format!(
                            "Rule {}: day {} is invalid (must be 0-6)",
                            i, day
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Convert configuration to an AclTable.
    ///
    /// # Example
    /// ```
    /// use axum_acl::TomlConfig;
    ///
    /// let toml = r#"
    /// [[rules]]
    /// role_mask = 1
    /// endpoint = "*"
    /// action = "allow"
    /// "#;
    ///
    /// let config = TomlConfig::from_toml(toml).unwrap();
    /// let table = config.into_table();
    /// ```
    pub fn into_table(self) -> AclTable {
        let default_action = action_config_to_action(&self.settings.default_action);

        // Sort rules by priority (lower = higher priority)
        let mut rules: Vec<(i32, RuleConfig)> = self
            .rules
            .into_iter()
            .map(|r| (r.priority, r))
            .collect();
        rules.sort_by_key(|(p, _)| *p);

        // Build the table using the builder
        let mut builder = AclTable::builder().default_action(default_action);

        for (_, rule_config) in rules {
            let endpoint = EndpointPattern::parse(&rule_config.endpoint);
            let filter = rule_config_to_filter(rule_config);

            // Add to appropriate collection based on endpoint type
            match endpoint {
                EndpointPattern::Exact(path) => {
                    builder = builder.add_exact(path, filter);
                }
                pattern => {
                    builder = builder.add_pattern(pattern, filter);
                }
            }
        }

        builder.build()
    }
}

/// Convert ActionConfig to AclAction.
fn action_config_to_action(config: &ActionConfig) -> AclAction {
    match config {
        ActionConfig::Simple(simple) => match simple {
            SimpleAction::Allow => AclAction::Allow,
            SimpleAction::Deny | SimpleAction::Block => AclAction::Deny,
        },
        ActionConfig::Complex(complex) => match complex {
            ComplexAction::Allow => AclAction::Allow,
            ComplexAction::Deny | ComplexAction::Block => AclAction::Deny,
            ComplexAction::Error { code, message } => AclAction::Error {
                code: *code,
                message: message.clone(),
            },
            ComplexAction::Reroute {
                target,
                preserve_path,
            } => AclAction::Reroute {
                target: target.clone(),
                preserve_path: *preserve_path,
            },
            ComplexAction::RateLimit {
                max_requests,
                window_secs,
            } => AclAction::RateLimit {
                max_requests: *max_requests,
                window_secs: *window_secs,
            },
            ComplexAction::Log { level, message } => AclAction::Log {
                level: level.clone(),
                message: message.clone(),
            },
        },
    }
}

/// Convert RuleConfig to AclRuleFilter.
fn rule_config_to_filter(config: RuleConfig) -> AclRuleFilter {
    let time = config.time.map(|t| {
        if t.start.is_none() && t.end.is_none() && t.days.is_empty() {
            TimeWindow::any()
        } else {
            TimeWindow {
                start: t.start.and_then(|h| chrono::NaiveTime::from_hms_opt(h, 0, 0)),
                end: t.end.and_then(|h| chrono::NaiveTime::from_hms_opt(h, 0, 0)),
                days: t.days,
            }
        }
    }).unwrap_or_else(TimeWindow::any);

    let ip = config
        .ip
        .map(|s| IpMatcher::parse(&s).unwrap_or(IpMatcher::Any))
        .unwrap_or(IpMatcher::Any);

    let action = action_config_to_action(&config.action);

    let mut filter = AclRuleFilter::new()
        .id(config.id)
        .role_mask(config.role_mask.to_mask())
        .time(time)
        .ip(ip)
        .action(action);

    if let Some(desc) = config.description {
        filter = filter.description(desc);
    }

    filter
}

impl AclTable {
    /// Create an AclTable from a TOML configuration string.
    ///
    /// This is the recommended way to load embedded configuration.
    ///
    /// # Example
    /// ```
    /// use axum_acl::AclTable;
    ///
    /// // Compile-time embedded config
    /// const CONFIG: &str = r#"
    /// [settings]
    /// default_action = "deny"
    ///
    /// [[rules]]
    /// role_mask = 1
    /// endpoint = "*"
    /// action = "allow"
    ///
    /// [[rules]]
    /// role_mask = 2
    /// endpoint = "/api/**"
    /// action = "allow"
    /// "#;
    ///
    /// let table = AclTable::from_toml(CONFIG).unwrap();
    /// ```
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let config = AclConfig::from_toml(toml_str)?;
        Ok(config.into_table())
    }

    /// Create an AclTable from a TOML configuration file.
    ///
    /// # Example
    /// ```ignore
    /// use axum_acl::AclTable;
    ///
    /// let table = AclTable::from_toml_file("config/acl.toml").unwrap();
    /// ```
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let config = AclConfig::from_file(path)?;
        Ok(config.into_table())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use crate::rule::RequestContext;

    #[test]
    fn test_parse_simple_config() {
        let toml = r#"
[settings]
default_action = "deny"

[[rules]]
role_mask = 1
endpoint = "*"
action = "allow"
description = "Admin access"

[[rules]]
role_mask = 2
endpoint = "/api/**"
action = "allow"
"#;

        let config = AclConfig::from_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 2);

        let table = config.into_table();
        // Check the table has pattern rules (since endpoints use * and **)
        assert!(!table.pattern_rules().is_empty());
    }

    #[test]
    fn test_parse_complex_actions() {
        let toml = r#"
[[rules]]
endpoint = "/error"
action = { type = "error", code = 418, message = "I'm a teapot" }

[[rules]]
endpoint = "/redirect"
action = { type = "reroute", target = "/new-path", preserve_path = true }
"#;

        let config = AclConfig::from_toml(toml).unwrap();
        assert_eq!(config.rules.len(), 2);

        let table = config.into_table();
        // Check error action is returned for /error path
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ctx = RequestContext::new(u32::MAX, ip, "*");
        let action = table.evaluate("/error", &ctx);
        match action {
            AclAction::Error { code, message } => {
                assert_eq!(code, 418);
                assert_eq!(message.as_deref(), Some("I'm a teapot"));
            }
            _ => panic!("Expected Error action"),
        }
    }

    #[test]
    fn test_parse_time_config() {
        let toml = r#"
[[rules]]
role_mask = 2
endpoint = "/api/**"
time = { start = 9, end = 17, days = [0, 1, 2, 3, 4] }
action = "allow"
"#;

        let config = AclConfig::from_toml(toml).unwrap();
        let table = config.into_table();

        // The table should have pattern rules with time config
        assert!(!table.pattern_rules().is_empty());
    }

    #[test]
    fn test_parse_ip_config() {
        let toml = r#"
[[rules]]
endpoint = "/internal/**"
ip = "192.168.1.0/24"
action = "allow"
"#;

        let config = AclConfig::from_toml(toml).unwrap();
        let table = config.into_table();

        // Check the filter has correct IP matcher
        let (_, filters) = &table.pattern_rules()[0];
        match &filters[0].ip {
            IpMatcher::Network(_) => {}
            _ => panic!("Expected Network IP matcher"),
        }
    }

    #[test]
    fn test_role_mask_formats() {
        let toml = r#"
[[rules]]
role_mask = 3
endpoint = "/decimal"
action = "allow"

[[rules]]
role_mask = "0xFF"
endpoint = "/hex"
action = "allow"

[[rules]]
role_mask = "*"
endpoint = "/all"
action = "allow"
"#;

        let config = AclConfig::from_toml(toml).unwrap();
        assert_eq!(config.rules[0].role_mask.to_mask(), 3);
        assert_eq!(config.rules[1].role_mask.to_mask(), 0xFF);
        assert_eq!(config.rules[2].role_mask.to_mask(), u32::MAX);
    }
}
