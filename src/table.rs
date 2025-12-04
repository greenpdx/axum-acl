//! ACL table for storing and evaluating rules.
//!
//! The [`AclTable`] is the central data structure that holds all ACL rules
//! and provides methods to evaluate requests against them.
//!
//! Uses a HashMap for O(1) endpoint lookup, with filters for role/time/ip/id matching.

use crate::rule::{AclAction, AclRuleFilter, EndpointPattern, RequestContext};
use std::collections::HashMap;
use std::sync::Arc;

/// A table containing ACL rules for evaluation.
///
/// Uses a 5-tuple system: (endpoint, role, time, ip, id)
/// - Endpoint is used as HashMap key for O(1) lookup
/// - Role, time, ip, id are filters applied after endpoint match
///
/// # Example
/// ```
/// use axum_acl::{AclTable, AclRuleFilter, AclAction};
///
/// let table = AclTable::builder()
///     .default_action(AclAction::Deny)
///     // Exact endpoint match
///     .add_exact("/api/users", AclRuleFilter::new()
///         .role_mask(0b11)  // roles 0 and 1
///         .action(AclAction::Allow))
///     // Prefix match for /admin/*
///     .add_prefix("/admin/", AclRuleFilter::new()
///         .role_mask(0b1)   // role 0 only (admin)
///         .action(AclAction::Allow))
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct AclTable {
    /// O(1) lookup for exact endpoint matches.
    pub(crate) exact_rules: HashMap<String, Vec<AclRuleFilter>>,
    /// Fallback for prefix/glob/any patterns (checked in order).
    pub(crate) pattern_rules: Vec<(EndpointPattern, Vec<AclRuleFilter>)>,
    /// Default action when no rules match.
    pub(crate) default_action: AclAction,
}

impl Default for AclTable {
    fn default() -> Self {
        Self {
            exact_rules: HashMap::new(),
            pattern_rules: Vec::new(),
            default_action: AclAction::Deny,
        }
    }
}

impl AclTable {
    /// Create a new empty ACL table with deny as default action.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for constructing an ACL table.
    pub fn builder() -> AclTableBuilder {
        AclTableBuilder::new()
    }

    /// Get the exact rules map.
    pub fn exact_rules(&self) -> &HashMap<String, Vec<AclRuleFilter>> {
        &self.exact_rules
    }

    /// Get the pattern rules.
    pub fn pattern_rules(&self) -> &[(EndpointPattern, Vec<AclRuleFilter>)] {
        &self.pattern_rules
    }

    /// Get the default action when no rules match.
    pub fn default_action(&self) -> AclAction {
        self.default_action.clone()
    }

    /// Evaluate the ACL rules for a given request context.
    ///
    /// Lookup order:
    /// 1. Exact endpoint match in HashMap (O(1))
    /// 2. Pattern rules (prefix/glob/any) in order
    ///
    /// For each endpoint match, filters are checked: id → roles → ip → time
    ///
    /// # Example
    /// ```
    /// use axum_acl::{AclTable, AclRuleFilter, AclAction, RequestContext};
    /// use std::net::IpAddr;
    ///
    /// let table = AclTable::builder()
    ///     .add_exact("/api/users", AclRuleFilter::new()
    ///         .role_mask(0b11)
    ///         .action(AclAction::Allow))
    ///     .build();
    ///
    /// let ip: IpAddr = "127.0.0.1".parse().unwrap();
    /// let ctx = RequestContext::new(0b01, ip, "user123");
    /// let action = table.evaluate("/api/users", &ctx);
    /// assert_eq!(action, AclAction::Allow);
    /// ```
    pub fn evaluate(&self, path: &str, ctx: &RequestContext) -> AclAction {
        self.evaluate_with_match(path, ctx).0
    }

    /// Evaluate the ACL rules and return both the action and match info.
    ///
    /// Returns `(action, Some((endpoint, filter_index)))` if matched,
    /// or `(default_action, None)` if no rules matched.
    pub fn evaluate_with_match(&self, path: &str, ctx: &RequestContext) -> (AclAction, Option<(String, usize)>) {
        // 1. Try exact endpoint match first (O(1))
        if let Some(filters) = self.exact_rules.get(path) {
            for (idx, filter) in filters.iter().enumerate() {
                if filter.matches(ctx) {
                    tracing::debug!(
                        endpoint = path,
                        filter_index = idx,
                        filter_description = ?filter.description,
                        roles = ctx.roles,
                        id = ctx.id,
                        ip = %ctx.ip,
                        action = ?filter.action,
                        "ACL exact match"
                    );
                    return (filter.action.clone(), Some((path.to_string(), idx)));
                }
            }
        }

        // 2. Try pattern rules (prefix/glob/any)
        for (pattern, filters) in &self.pattern_rules {
            if pattern.matches(path) {
                for (idx, filter) in filters.iter().enumerate() {
                    if filter.matches(ctx) {
                        tracing::debug!(
                            endpoint = ?pattern,
                            filter_index = idx,
                            filter_description = ?filter.description,
                            roles = ctx.roles,
                            id = ctx.id,
                            ip = %ctx.ip,
                            action = ?filter.action,
                            "ACL pattern match"
                        );
                        return (filter.action.clone(), Some((format!("{:?}", pattern), idx)));
                    }
                }
            }
        }

        tracing::debug!(
            path = path,
            roles = ctx.roles,
            id = ctx.id,
            ip = %ctx.ip,
            action = ?self.default_action,
            "No ACL rule matched, using default action"
        );
        (self.default_action.clone(), None)
    }

    /// Check if access is allowed for the given context.
    pub fn is_allowed(&self, path: &str, ctx: &RequestContext) -> bool {
        self.evaluate(path, ctx) == AclAction::Allow
    }
}

/// Builder for constructing an [`AclTable`].
#[derive(Debug, Default)]
pub struct AclTableBuilder {
    exact_rules: HashMap<String, Vec<AclRuleFilter>>,
    pattern_rules: Vec<(EndpointPattern, Vec<AclRuleFilter>)>,
    default_action: AclAction,
}

impl AclTableBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default action when no rules match.
    ///
    /// The default is `AclAction::Deny`.
    pub fn default_action(mut self, action: AclAction) -> Self {
        self.default_action = action;
        self
    }

    /// Add a filter for an exact endpoint match (O(1) lookup).
    pub fn add_exact(mut self, endpoint: impl Into<String>, filter: AclRuleFilter) -> Self {
        let endpoint = endpoint.into();
        self.exact_rules
            .entry(endpoint)
            .or_default()
            .push(filter);
        self
    }

    /// Add multiple filters for an exact endpoint.
    pub fn add_exact_filters(
        mut self,
        endpoint: impl Into<String>,
        filters: impl IntoIterator<Item = AclRuleFilter>,
    ) -> Self {
        let endpoint = endpoint.into();
        self.exact_rules
            .entry(endpoint)
            .or_default()
            .extend(filters);
        self
    }

    /// Add a filter for a prefix endpoint match.
    pub fn add_prefix(self, prefix: impl Into<String>, filter: AclRuleFilter) -> Self {
        let pattern = EndpointPattern::Prefix(prefix.into());
        self.add_pattern(pattern, filter)
    }

    /// Add a filter for a glob endpoint match.
    pub fn add_glob(self, glob: impl Into<String>, filter: AclRuleFilter) -> Self {
        let pattern = EndpointPattern::Glob(glob.into());
        self.add_pattern(pattern, filter)
    }

    /// Add a filter that matches any endpoint.
    pub fn add_any(self, filter: AclRuleFilter) -> Self {
        self.add_pattern(EndpointPattern::Any, filter)
    }

    /// Add a filter for a custom endpoint pattern.
    pub fn add_pattern(mut self, pattern: EndpointPattern, filter: AclRuleFilter) -> Self {
        // Check if this pattern already exists
        for (existing_pattern, filters) in &mut self.pattern_rules {
            let is_match = match (existing_pattern, &pattern) {
                (EndpointPattern::Any, EndpointPattern::Any) => true,
                (EndpointPattern::Prefix(a), EndpointPattern::Prefix(b)) => a == b,
                (EndpointPattern::Glob(a), EndpointPattern::Glob(b)) => a == b,
                (EndpointPattern::Exact(a), EndpointPattern::Exact(b)) => a == b,
                _ => false,
            };
            if is_match {
                filters.push(filter);
                return self;
            }
        }
        // New pattern
        self.pattern_rules.push((pattern, vec![filter]));
        self
    }

    /// Build the ACL table.
    pub fn build(self) -> AclTable {
        AclTable {
            exact_rules: self.exact_rules,
            pattern_rules: self.pattern_rules,
            default_action: self.default_action,
        }
    }

    /// Build the ACL table wrapped in an Arc for sharing.
    pub fn build_shared(self) -> Arc<AclTable> {
        Arc::new(self.build())
    }
}

/// Rule entry for providers: endpoint pattern + filter.
#[derive(Debug, Clone)]
pub struct RuleEntry {
    /// The endpoint pattern.
    pub pattern: EndpointPattern,
    /// The filter for this endpoint.
    pub filter: AclRuleFilter,
}

impl RuleEntry {
    /// Create a new rule entry.
    pub fn new(pattern: EndpointPattern, filter: AclRuleFilter) -> Self {
        Self { pattern, filter }
    }

    /// Create an exact endpoint rule.
    pub fn exact(endpoint: impl Into<String>, filter: AclRuleFilter) -> Self {
        Self::new(EndpointPattern::Exact(endpoint.into()), filter)
    }

    /// Create a prefix endpoint rule.
    pub fn prefix(prefix: impl Into<String>, filter: AclRuleFilter) -> Self {
        Self::new(EndpointPattern::Prefix(prefix.into()), filter)
    }

    /// Create a glob endpoint rule.
    pub fn glob(glob: impl Into<String>, filter: AclRuleFilter) -> Self {
        Self::new(EndpointPattern::Glob(glob.into()), filter)
    }

    /// Create an any endpoint rule.
    pub fn any(filter: AclRuleFilter) -> Self {
        Self::new(EndpointPattern::Any, filter)
    }
}

/// Trait for types that can provide ACL rules.
///
/// Implement this trait to load rules from external sources like databases,
/// configuration files, or remote services.
///
/// # Example
/// ```
/// use axum_acl::{AclRuleProvider, RuleEntry, AclRuleFilter, AclAction, EndpointPattern};
///
/// struct ConfigRuleProvider {
///     config_path: String,
/// }
///
/// impl AclRuleProvider for ConfigRuleProvider {
///     type Error = std::io::Error;
///
///     fn load_rules(&self) -> Result<Vec<RuleEntry>, Self::Error> {
///         // Load rules from config file
///         Ok(vec![
///             RuleEntry::any(AclRuleFilter::new()
///                 .role_mask(0b1)  // admin role
///                 .action(AclAction::Allow))
///         ])
///     }
/// }
/// ```
pub trait AclRuleProvider: Send + Sync {
    /// Error type for rule loading failures.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load rules from the provider.
    fn load_rules(&self) -> Result<Vec<RuleEntry>, Self::Error>;
}

/// A simple rule provider that returns a static list of rules.
#[derive(Debug, Clone)]
pub struct StaticRuleProvider {
    rules: Vec<RuleEntry>,
}

impl StaticRuleProvider {
    /// Create a new static rule provider.
    pub fn new(rules: Vec<RuleEntry>) -> Self {
        Self { rules }
    }
}

impl AclRuleProvider for StaticRuleProvider {
    type Error = std::convert::Infallible;

    fn load_rules(&self) -> Result<Vec<RuleEntry>, Self::Error> {
        Ok(self.rules.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const ROLE_ADMIN: u32 = 0b001;
    const ROLE_USER: u32 = 0b010;
    const ROLE_GUEST: u32 = 0b100;

    #[test]
    fn test_table_evaluation() {
        let table = AclTable::builder()
            .default_action(AclAction::Deny)
            // Admin can access anything
            .add_any(AclRuleFilter::new()
                .role_mask(ROLE_ADMIN)
                .action(AclAction::Allow))
            // User can access /api/
            .add_prefix("/api/", AclRuleFilter::new()
                .role_mask(ROLE_USER)
                .action(AclAction::Allow))
            .build();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Admin can access anything
        let admin_ctx = RequestContext::new(ROLE_ADMIN, ip, "admin1");
        assert!(table.is_allowed("/admin/dashboard", &admin_ctx));
        assert!(table.is_allowed("/api/users", &admin_ctx));

        // User can only access /api/
        let user_ctx = RequestContext::new(ROLE_USER, ip, "user1");
        assert!(table.is_allowed("/api/users", &user_ctx));
        assert!(!table.is_allowed("/admin/dashboard", &user_ctx));

        // Guest is denied (default action)
        let guest_ctx = RequestContext::new(ROLE_GUEST, ip, "guest1");
        assert!(!table.is_allowed("/api/users", &guest_ctx));
    }

    #[test]
    fn test_exact_before_pattern() {
        // Exact match takes priority over patterns
        let table = AclTable::builder()
            .default_action(AclAction::Deny)
            // Exact match for /public
            .add_exact("/public", AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::Allow))
            // Deny everything else
            .add_any(AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::Deny))
            .build();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ctx = RequestContext::new(0b1, ip, "anyone");

        assert!(table.is_allowed("/public", &ctx));
        assert!(!table.is_allowed("/private", &ctx));
    }

    #[test]
    fn test_role_bitmask() {
        let table = AclTable::builder()
            .default_action(AclAction::Deny)
            .add_exact("/shared", AclRuleFilter::new()
                .role_mask(ROLE_ADMIN | ROLE_USER)  // admin OR user
                .action(AclAction::Allow))
            .build();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Admin can access
        assert!(table.is_allowed("/shared", &RequestContext::new(ROLE_ADMIN, ip, "a")));
        // User can access
        assert!(table.is_allowed("/shared", &RequestContext::new(ROLE_USER, ip, "u")));
        // Guest cannot
        assert!(!table.is_allowed("/shared", &RequestContext::new(ROLE_GUEST, ip, "g")));
        // User+Admin can access (has overlap)
        assert!(table.is_allowed("/shared", &RequestContext::new(ROLE_ADMIN | ROLE_USER, ip, "au")));
    }
}
