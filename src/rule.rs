//! ACL rule definitions and matching logic.
//!
//! This module provides the core [`AclRuleFilter`] struct that defines access control rules
//! using a 5-tuple: (endpoint, role, time, ip, id).
//!
//! - **Endpoint**: Used as HashMap key for O(1) lookup
//! - **Role**: `u32` bitmask for efficient role matching (up to 32 roles)
//! - **Time**: Time window filter (start < now < end)
//! - **IP**: IP address/CIDR filter (ip & mask == network)
//! - **ID**: Exact match or "*" wildcard

use chrono::{Datelike, NaiveTime, Utc};
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// Request context for ACL evaluation.
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    /// User's role bitmask (up to 32 roles).
    pub roles: u32,
    /// Client IP address.
    pub ip: IpAddr,
    /// User/session ID.
    pub id: &'a str,
}

impl<'a> RequestContext<'a> {
    /// Create a new request context.
    pub fn new(roles: u32, ip: IpAddr, id: &'a str) -> Self {
        Self { roles, ip, id }
    }
}

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AclAction {
    /// Allow the request to proceed.
    #[default]
    Allow,
    /// Deny the request with 403 Forbidden.
    Deny,
    /// Return a custom error response.
    Error {
        /// HTTP status code (default: 403).
        code: u16,
        /// Custom error message.
        message: Option<String>,
    },
    /// Reroute to a different path.
    Reroute {
        /// Target path to reroute to.
        target: String,
        /// Whether to preserve original path in X-Original-Path header.
        preserve_path: bool,
    },
    /// Rate limit (placeholder - requires external state).
    RateLimit {
        /// Maximum requests per window.
        max_requests: u32,
        /// Window duration in seconds.
        window_secs: u64,
    },
    /// Log and allow (for monitoring/auditing).
    Log {
        /// Log level: "trace", "debug", "info", "warn", "error".
        level: String,
        /// Custom log message.
        message: Option<String>,
    },
}

impl AclAction {
    /// Create a deny action (alias for Deny variant).
    pub fn deny() -> Self {
        Self::Deny
    }

    /// Create an allow action (alias for Allow variant).
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Create a custom error action.
    pub fn error(code: u16, message: impl Into<Option<String>>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }

    /// Create a reroute action.
    pub fn reroute(target: impl Into<String>) -> Self {
        Self::Reroute {
            target: target.into(),
            preserve_path: false,
        }
    }

    /// Create a reroute action that preserves the original path.
    pub fn reroute_with_preserve(target: impl Into<String>) -> Self {
        Self::Reroute {
            target: target.into(),
            preserve_path: true,
        }
    }

    /// Check if this action allows the request to proceed.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow | Self::Log { .. })
    }

    /// Check if this action denies/blocks the request.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny | Self::Error { .. })
    }
}

/// ACL rule filter for the 5-tuple matching system.
///
/// Filters are applied after endpoint lookup (endpoint is the HashMap key).
/// Match priority: id → roles → ip → time
#[derive(Debug, Clone)]
pub struct AclRuleFilter {
    /// ID matcher: "*" for any, or exact match.
    pub id: String,
    /// Role bitmask: `(rule.role_mask & ctx.roles) != 0` to match.
    pub role_mask: u32,
    /// Time window: start < now < end.
    pub time: TimeWindow,
    /// IP matcher: CIDR-style matching.
    pub ip: IpMatcher,
    /// Action to take when this filter matches.
    pub action: AclAction,
    /// Optional description for logging/debugging.
    pub description: Option<String>,
}

impl AclRuleFilter {
    /// Create a new filter that matches any ID and all roles.
    pub fn new() -> Self {
        Self {
            id: "*".to_string(),
            role_mask: u32::MAX, // all roles
            time: TimeWindow::default(),
            ip: IpMatcher::Any,
            action: AclAction::Allow,
            description: None,
        }
    }

    /// Set the ID matcher (exact match or "*" for any).
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    /// Set the role bitmask.
    pub fn role_mask(mut self, mask: u32) -> Self {
        self.role_mask = mask;
        self
    }

    /// Set a single role bit.
    pub fn role(mut self, role_id: u8) -> Self {
        self.role_mask = 1 << role_id;
        self
    }

    /// Add a role bit to the mask.
    pub fn add_role(mut self, role_id: u8) -> Self {
        self.role_mask |= 1 << role_id;
        self
    }

    /// Set the time window.
    pub fn time(mut self, window: TimeWindow) -> Self {
        self.time = window;
        self
    }

    /// Set the IP matcher.
    pub fn ip(mut self, matcher: IpMatcher) -> Self {
        self.ip = matcher;
        self
    }

    /// Set the action.
    pub fn action(mut self, action: AclAction) -> Self {
        self.action = action;
        self
    }

    /// Set a description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Check if this filter matches the given context.
    ///
    /// Match order: id → roles → ip → time
    #[inline]
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        // 1. ID match (exact or wildcard)
        (self.id == "*" || self.id == ctx.id)
            // 2. Role match (any bit overlap)
            && (self.role_mask & ctx.roles) != 0
            // 3. IP match
            && self.ip.matches(&ctx.ip)
            // 4. Time match
            && self.time.matches_now()
    }
}

impl Default for AclRuleFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Time window specification for rule matching.
///
/// Defines a time range during which a rule is active.
/// Times are evaluated in UTC.
#[derive(Debug, Clone)]
pub struct TimeWindow {
    /// Start time (inclusive). None means from midnight.
    pub start: Option<NaiveTime>,
    /// End time (inclusive). None means until midnight.
    pub end: Option<NaiveTime>,
    /// Days of the week when this window is active (0 = Monday, 6 = Sunday).
    /// Empty means all days.
    pub days: Vec<u32>,
}

impl Default for TimeWindow {
    fn default() -> Self {
        Self {
            start: None,
            end: None,
            days: Vec::new(),
        }
    }
}

impl TimeWindow {
    /// Create a time window that matches any time.
    pub fn any() -> Self {
        Self::default()
    }

    /// Create a time window for specific hours (24-hour format, UTC).
    ///
    /// # Example
    /// ```
    /// use axum_acl::TimeWindow;
    ///
    /// // Active from 9 AM to 5 PM UTC
    /// let window = TimeWindow::hours(9, 17);
    /// ```
    pub fn hours(start_hour: u32, end_hour: u32) -> Self {
        Self {
            start: Some(NaiveTime::from_hms_opt(start_hour, 0, 0).unwrap_or_default()),
            end: Some(NaiveTime::from_hms_opt(end_hour, 0, 0).unwrap_or_default()),
            days: Vec::new(),
        }
    }

    /// Create a time window for specific hours on specific days.
    ///
    /// # Arguments
    /// * `start_hour` - Start hour (0-23)
    /// * `end_hour` - End hour (0-23)
    /// * `days` - Days of week (0 = Monday, 6 = Sunday)
    ///
    /// # Example
    /// ```
    /// use axum_acl::TimeWindow;
    ///
    /// // Active Mon-Fri 9 AM to 5 PM UTC
    /// let window = TimeWindow::hours_on_days(9, 17, vec![0, 1, 2, 3, 4]);
    /// ```
    pub fn hours_on_days(start_hour: u32, end_hour: u32, days: Vec<u32>) -> Self {
        Self {
            start: Some(NaiveTime::from_hms_opt(start_hour, 0, 0).unwrap_or_default()),
            end: Some(NaiveTime::from_hms_opt(end_hour, 0, 0).unwrap_or_default()),
            days,
        }
    }

    /// Check if the current time falls within this window.
    pub fn matches_now(&self) -> bool {
        let now = Utc::now();
        let current_time = now.time();
        let current_day = now.weekday().num_days_from_monday();

        // Check day of week
        if !self.days.is_empty() && !self.days.contains(&current_day) {
            return false;
        }

        // Check time range
        match (&self.start, &self.end) {
            (Some(start), Some(end)) => {
                if start <= end {
                    // Normal range: 9:00 - 17:00
                    current_time >= *start && current_time <= *end
                } else {
                    // Overnight range: 22:00 - 06:00
                    current_time >= *start || current_time <= *end
                }
            }
            (Some(start), None) => current_time >= *start,
            (None, Some(end)) => current_time <= *end,
            (None, None) => true,
        }
    }
}

/// IP address specification for rule matching.
#[derive(Debug, Clone)]
pub enum IpMatcher {
    /// Match any IP address.
    Any,
    /// Match a single IP address.
    Single(IpAddr),
    /// Match an IP network (CIDR notation).
    Network(IpNetwork),
    /// Match multiple IP addresses or networks.
    List(Vec<IpMatcher>),
}

impl Default for IpMatcher {
    fn default() -> Self {
        Self::Any
    }
}

impl IpMatcher {
    /// Create a matcher for any IP address.
    pub fn any() -> Self {
        Self::Any
    }

    /// Create a matcher for a single IP address.
    ///
    /// # Example
    /// ```
    /// use axum_acl::IpMatcher;
    /// use std::net::IpAddr;
    ///
    /// let matcher = IpMatcher::single("192.168.1.1".parse().unwrap());
    /// ```
    pub fn single(ip: IpAddr) -> Self {
        Self::Single(ip)
    }

    /// Create a matcher for a CIDR network.
    ///
    /// # Example
    /// ```
    /// use axum_acl::IpMatcher;
    ///
    /// let matcher = IpMatcher::cidr("192.168.1.0/24".parse().unwrap());
    /// ```
    pub fn cidr(network: IpNetwork) -> Self {
        Self::Network(network)
    }

    /// Parse an IP matcher from a string.
    ///
    /// Accepts:
    /// - `*` or `any` for any IP
    /// - A single IP address (e.g., `192.168.1.1`)
    /// - A CIDR network (e.g., `192.168.1.0/24`)
    ///
    /// # Example
    /// ```
    /// use axum_acl::IpMatcher;
    ///
    /// let any = IpMatcher::parse("*").unwrap();
    /// let single = IpMatcher::parse("10.0.0.1").unwrap();
    /// let network = IpMatcher::parse("10.0.0.0/8").unwrap();
    /// ```
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "*" || s.eq_ignore_ascii_case("any") {
            return Ok(Self::Any);
        }

        // Try as CIDR first
        if s.contains('/') {
            return s
                .parse::<IpNetwork>()
                .map(Self::Network)
                .map_err(|e| format!("Invalid CIDR: {}", e));
        }

        // Try as single IP
        s.parse::<IpAddr>()
            .map(Self::Single)
            .map_err(|e| format!("Invalid IP address: {}", e))
    }

    /// Check if an IP address matches this matcher.
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Single(addr) => addr == ip,
            Self::Network(network) => network.contains(*ip),
            Self::List(matchers) => matchers.iter().any(|m| m.matches(ip)),
        }
    }
}

/// Endpoint pattern for rule matching.
#[derive(Debug, Clone)]
pub enum EndpointPattern {
    /// Match any endpoint.
    Any,
    /// Match an exact path.
    Exact(String),
    /// Match a path prefix (e.g., `/api/` matches `/api/users`).
    Prefix(String),
    /// Match using a glob pattern (e.g., `/api/*/users`).
    Glob(String),
}

impl Default for EndpointPattern {
    fn default() -> Self {
        Self::Any
    }
}

impl EndpointPattern {
    /// Create a pattern that matches any endpoint.
    pub fn any() -> Self {
        Self::Any
    }

    /// Create a pattern for an exact path match.
    pub fn exact(path: impl Into<String>) -> Self {
        Self::Exact(path.into())
    }

    /// Create a pattern for a prefix match.
    pub fn prefix(path: impl Into<String>) -> Self {
        Self::Prefix(path.into())
    }

    /// Create a glob pattern.
    ///
    /// Supported wildcards:
    /// - `*` matches any single path segment
    /// - `**` matches any number of path segments
    pub fn glob(pattern: impl Into<String>) -> Self {
        Self::Glob(pattern.into())
    }

    /// Parse an endpoint pattern from a string.
    ///
    /// - `*` or `any` - matches any endpoint
    /// - Paths ending with `*` or `**` - glob pattern
    /// - Paths ending with `/` - prefix match
    /// - Other paths - exact match
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "*" || s.eq_ignore_ascii_case("any") {
            return Self::Any;
        }

        if s.contains('*') {
            return Self::Glob(s.to_string());
        }

        if s.ends_with('/') {
            return Self::Prefix(s.to_string());
        }

        Self::Exact(s.to_string())
    }

    /// Check if a path matches this pattern.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(p) => p == path,
            Self::Prefix(prefix) => path.starts_with(prefix),
            Self::Glob(pattern) => Self::glob_matches(pattern, path),
        }
    }

    fn glob_matches(pattern: &str, path: &str) -> bool {
        let pattern_parts: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
        let path_parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        Self::glob_match_parts(&pattern_parts, &path_parts)
    }

    fn glob_match_parts(pattern: &[&str], path: &[&str]) -> bool {
        if pattern.is_empty() {
            return path.is_empty();
        }

        let (first_pattern, rest_pattern) = (pattern[0], &pattern[1..]);

        if first_pattern == "**" {
            // ** matches zero or more segments
            if rest_pattern.is_empty() {
                return true;
            }
            // Try matching ** against 0, 1, 2, ... path segments
            for i in 0..=path.len() {
                if Self::glob_match_parts(rest_pattern, &path[i..]) {
                    return true;
                }
            }
            false
        } else if path.is_empty() {
            false
        } else {
            let (first_path, rest_path) = (path[0], &path[1..]);
            let segment_matches = first_pattern == "*" || first_pattern == first_path;
            segment_matches && Self::glob_match_parts(rest_pattern, rest_path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_matcher_single() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let matcher = IpMatcher::single(ip);
        assert!(matcher.matches(&ip));
        assert!(!matcher.matches(&"192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn test_ip_matcher_cidr() {
        let matcher = IpMatcher::cidr("192.168.1.0/24".parse().unwrap());
        assert!(matcher.matches(&"192.168.1.1".parse().unwrap()));
        assert!(matcher.matches(&"192.168.1.255".parse().unwrap()));
        assert!(!matcher.matches(&"192.168.2.1".parse().unwrap()));
    }

    #[test]
    fn test_endpoint_exact() {
        let pattern = EndpointPattern::exact("/api/users");
        assert!(pattern.matches("/api/users"));
        assert!(!pattern.matches("/api/users/"));
        assert!(!pattern.matches("/api/users/1"));
    }

    #[test]
    fn test_endpoint_prefix() {
        let pattern = EndpointPattern::prefix("/api/");
        assert!(pattern.matches("/api/users"));
        assert!(pattern.matches("/api/users/1"));
        assert!(!pattern.matches("/admin/users"));
    }

    #[test]
    fn test_endpoint_glob() {
        let pattern = EndpointPattern::glob("/api/*/users");
        assert!(pattern.matches("/api/v1/users"));
        assert!(pattern.matches("/api/v2/users"));
        assert!(!pattern.matches("/api/v1/posts"));

        let pattern = EndpointPattern::glob("/api/**");
        assert!(pattern.matches("/api/users"));
        assert!(pattern.matches("/api/v1/users/1"));
    }

    #[test]
    fn test_filter_matches() {
        let filter = AclRuleFilter::new()
            .role_mask(0b001)  // admin role
            .ip(IpMatcher::any());

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Admin matches
        let ctx = RequestContext::new(0b001, ip, "*");
        assert!(filter.matches(&ctx));

        // User (0b010) doesn't match admin filter (0b001)
        let ctx = RequestContext::new(0b010, ip, "*");
        assert!(!filter.matches(&ctx));

        // Admin + User (0b011) matches because admin bit is set
        let ctx = RequestContext::new(0b011, ip, "*");
        assert!(filter.matches(&ctx));
    }

    #[test]
    fn test_filter_id_match() {
        let filter = AclRuleFilter::new()
            .id("user123")
            .role_mask(u32::MAX);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Exact ID match
        let ctx = RequestContext::new(0b1, ip, "user123");
        assert!(filter.matches(&ctx));

        // Different ID doesn't match
        let ctx = RequestContext::new(0b1, ip, "user456");
        assert!(!filter.matches(&ctx));
    }

    #[test]
    fn test_filter_wildcard_id() {
        let filter = AclRuleFilter::new()
            .id("*")
            .role_mask(u32::MAX);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Wildcard matches any ID
        let ctx = RequestContext::new(0b1, ip, "anyone");
        assert!(filter.matches(&ctx));
    }
}
