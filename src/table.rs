//! ACL table for storing and evaluating rules.
//!
//! The [`AclTable`] is the central data structure that holds all ACL rules
//! and provides methods to evaluate requests against them.
//!
//! Uses a HashMap for O(1) endpoint lookup, with filters for role/time/ip/id matching.

use crate::rule::{
    AclAction, AclRuleFilter, BitmaskAuth, EndpointPattern, RequestContext, RequestMeta,
    RuleMatcher,
};
use std::collections::HashMap;
use std::sync::Arc;

/// A single rule in the generic ACL table, wrapping a `RuleMatcher<A>`.
pub struct AclRule<A> {
    pub(crate) matcher: Arc<dyn RuleMatcher<A>>,
}

impl<A> Clone for AclRule<A> {
    fn clone(&self) -> Self {
        Self {
            matcher: self.matcher.clone(),
        }
    }
}

impl<A> std::fmt::Debug for AclRule<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclRule")
            .field("matcher", &self.matcher)
            .finish()
    }
}

impl<A> AclRule<A> {
    /// Create a rule from a matcher.
    pub fn from_matcher(matcher: Arc<dyn RuleMatcher<A>>) -> Self {
        Self { matcher }
    }

    /// Create a rule with HTTP method filtering.
    pub fn from_matcher_with_methods(
        matcher: Arc<dyn RuleMatcher<A>>,
        methods: Vec<http::Method>,
        action: AclAction,
    ) -> Self
    where
        A: Send + Sync + 'static,
    {
        Self {
            matcher: Arc::new(MethodFilterMatcher {
                inner: matcher,
                methods,
                action,
            }),
        }
    }

    /// Get the action this rule takes when matched.
    pub fn action(&self) -> &AclAction {
        self.matcher.action()
    }

    /// Get the description of this rule.
    pub fn description(&self) -> Option<&str> {
        self.matcher.description()
    }
}

/// Wrapper matcher that adds HTTP method filtering to another matcher.
struct MethodFilterMatcher<A> {
    inner: Arc<dyn RuleMatcher<A>>,
    methods: Vec<http::Method>,
    action: AclAction,
}

impl<A> std::fmt::Debug for MethodFilterMatcher<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodFilterMatcher")
            .field("methods", &self.methods)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<A> RuleMatcher<A> for MethodFilterMatcher<A>
where
    A: Send + Sync,
{
    fn matches(&self, auth: &A, meta: &RequestMeta) -> bool {
        (self.methods.is_empty() || self.methods.contains(&meta.method))
            && self.inner.matches(auth, meta)
    }

    fn action(&self) -> &AclAction {
        &self.action
    }

    fn description(&self) -> Option<&str> {
        self.inner.description()
    }
}

/// A table containing ACL rules for evaluation.
///
/// Uses a 5-tuple system: (endpoint, role, time, ip, id)
/// - Endpoint is used as HashMap key for O(1) lookup
/// - Role, time, ip, id are filters applied after endpoint match
///
/// The type parameter `A` is the auth context type. Defaults to `BitmaskAuth`
/// for backward compatibility with the u32 bitmask role system.
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
pub struct AclTable<A = BitmaskAuth> {
    /// O(1) lookup for exact endpoint matches.
    pub(crate) exact_rules: HashMap<String, Vec<AclRule<A>>>,
    /// Fallback for prefix/glob/any patterns (checked in order).
    pub(crate) pattern_rules: Vec<(EndpointPattern, Vec<AclRule<A>>)>,
    /// Default action when no rules match.
    pub(crate) default_action: AclAction,
}

impl<A> Clone for AclTable<A> {
    fn clone(&self) -> Self {
        Self {
            exact_rules: self.exact_rules.clone(),
            pattern_rules: self.pattern_rules.clone(),
            default_action: self.default_action.clone(),
        }
    }
}

impl<A> std::fmt::Debug for AclTable<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclTable")
            .field("exact_rules_count", &self.exact_rules.len())
            .field("pattern_rules_count", &self.pattern_rules.len())
            .field("default_action", &self.default_action)
            .finish()
    }
}

impl<A> Default for AclTable<A> {
    fn default() -> Self {
        Self {
            exact_rules: HashMap::new(),
            pattern_rules: Vec::new(),
            default_action: AclAction::Deny,
        }
    }
}

// Generic methods available for all auth types.
impl<A> AclTable<A> {
    /// Get the exact rules map.
    pub fn exact_rules(&self) -> &HashMap<String, Vec<AclRule<A>>> {
        &self.exact_rules
    }

    /// Get the pattern rules.
    pub fn pattern_rules(&self) -> &[(EndpointPattern, Vec<AclRule<A>>)] {
        &self.pattern_rules
    }

    /// Get the default action when no rules match.
    pub fn default_action(&self) -> AclAction {
        self.default_action.clone()
    }

    /// Evaluate ACL rules using the generic auth type and request metadata.
    ///
    /// During pattern rule evaluation, named path parameters are extracted
    /// from the matching pattern and set on `meta.path_params`.
    pub fn evaluate_request(&self, auth: &A, meta: &RequestMeta) -> AclAction {
        self.evaluate_request_with_match(auth, meta).0
    }

    /// Evaluate ACL rules and return both the action and match info.
    pub fn evaluate_request_with_match(
        &self,
        auth: &A,
        meta: &RequestMeta,
    ) -> (AclAction, Option<(String, usize)>) {
        // 1. Try exact endpoint match first (O(1))
        if let Some(rules) = self.exact_rules.get(&meta.path) {
            for (idx, rule) in rules.iter().enumerate() {
                if rule.matcher.matches(auth, meta) {
                    tracing::debug!(
                        endpoint = %meta.path,
                        filter_index = idx,
                        filter_description = ?rule.description(),
                        ip = %meta.ip,
                        action = ?rule.action(),
                        "ACL exact match"
                    );
                    return (rule.action().clone(), Some((meta.path.clone(), idx)));
                }
            }
        }

        // 2. Try pattern rules (prefix/glob/any)
        for (pattern, rules) in &self.pattern_rules {
            if pattern.matches(&meta.path) {
                let mut meta_with_params = meta.clone();
                meta_with_params.path_params = pattern.extract_named_params(&meta.path);

                for (idx, rule) in rules.iter().enumerate() {
                    if rule.matcher.matches(auth, &meta_with_params) {
                        tracing::debug!(
                            endpoint = ?pattern,
                            filter_index = idx,
                            filter_description = ?rule.description(),
                            ip = %meta.ip,
                            action = ?rule.action(),
                            "ACL pattern match"
                        );
                        return (
                            rule.action().clone(),
                            Some((format!("{:?}", pattern), idx)),
                        );
                    }
                }
            }
        }

        tracing::debug!(
            path = %meta.path,
            ip = %meta.ip,
            action = ?self.default_action,
            "No ACL rule matched, using default action"
        );
        (self.default_action.clone(), None)
    }

    /// Check if access is allowed using the generic auth type.
    pub fn is_request_allowed(&self, auth: &A, meta: &RequestMeta) -> bool {
        self.evaluate_request(auth, meta) == AclAction::Allow
    }
}

// Backward-compatible methods for BitmaskAuth (the default).
impl AclTable<BitmaskAuth> {
    /// Create a new empty ACL table with deny as default action.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for constructing an ACL table.
    pub fn builder() -> AclTableBuilder<BitmaskAuth> {
        AclTableBuilder::new()
    }

    /// Evaluate the ACL rules for a given request context.
    ///
    /// Lookup order:
    /// 1. Exact endpoint match in HashMap (O(1))
    /// 2. Pattern rules (prefix/glob/any) in order
    ///
    /// For each endpoint match, filters are checked: id → roles → ip → time
    ///
    /// # Note
    ///
    /// This convenience API evaluates as an HTTP `GET` request, so
    /// method-filtered rules (`AclRuleFilter::method`) are not honored here.
    /// For method-aware evaluation, build a [`RequestMeta`] with the real
    /// method and call [`evaluate_request`](AclTable::evaluate_request).
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
    pub fn evaluate_with_match(
        &self,
        path: &str,
        ctx: &RequestContext,
    ) -> (AclAction, Option<(String, usize)>) {
        let meta = RequestMeta {
            method: http::Method::GET,
            path: path.to_string(),
            path_params: HashMap::new(),
            ip: ctx.ip,
        };
        let auth = BitmaskAuth {
            roles: ctx.roles,
            id: ctx.id.to_string(),
        };
        self.evaluate_request_with_match(&auth, &meta)
    }

    /// Check if access is allowed for the given context.
    pub fn is_allowed(&self, path: &str, ctx: &RequestContext) -> bool {
        self.evaluate(path, ctx) == AclAction::Allow
    }
}

/// Builder for constructing an [`AclTable`].
pub struct AclTableBuilder<A = BitmaskAuth> {
    exact_rules: HashMap<String, Vec<AclRule<A>>>,
    pattern_rules: Vec<(EndpointPattern, Vec<AclRule<A>>)>,
    default_action: AclAction,
}

impl<A> Default for AclTableBuilder<A> {
    fn default() -> Self {
        Self {
            exact_rules: HashMap::new(),
            pattern_rules: Vec::new(),
            default_action: AclAction::Deny,
        }
    }
}

impl<A> std::fmt::Debug for AclTableBuilder<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AclTableBuilder")
            .field("default_action", &self.default_action)
            .finish()
    }
}

// Generic builder methods for any auth type.
impl<A: 'static> AclTableBuilder<A> {
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

    /// Add a matcher for an exact endpoint match (O(1) lookup).
    pub fn add_exact_matcher(
        mut self,
        endpoint: impl Into<String>,
        matcher: impl RuleMatcher<A> + 'static,
    ) -> Self {
        let rule = AclRule {
            matcher: Arc::new(matcher),
        };
        self.exact_rules.entry(endpoint.into()).or_default().push(rule);
        self
    }

    /// Add a matcher for a pattern endpoint match.
    pub fn add_pattern_matcher(
        mut self,
        pattern: EndpointPattern,
        matcher: impl RuleMatcher<A> + 'static,
    ) -> Self {
        let rule = AclRule {
            matcher: Arc::new(matcher),
        };
        for (existing_pattern, rules) in &mut self.pattern_rules {
            let is_match = match (existing_pattern, &pattern) {
                (EndpointPattern::Any, EndpointPattern::Any) => true,
                (EndpointPattern::Prefix(a), EndpointPattern::Prefix(b)) => a == b,
                (EndpointPattern::Glob(a), EndpointPattern::Glob(b)) => a == b,
                (EndpointPattern::Exact(a), EndpointPattern::Exact(b)) => a == b,
                _ => false,
            };
            if is_match {
                rules.push(rule);
                return self;
            }
        }
        self.pattern_rules.push((pattern, vec![rule]));
        self
    }

    /// Add a matcher that applies to any endpoint.
    pub fn add_any_matcher(self, matcher: impl RuleMatcher<A> + 'static) -> Self {
        self.add_pattern_matcher(EndpointPattern::Any, matcher)
    }

    /// Build the ACL table.
    pub fn build(self) -> AclTable<A> {
        AclTable {
            exact_rules: self.exact_rules,
            pattern_rules: self.pattern_rules,
            default_action: self.default_action,
        }
    }

    /// Build the ACL table wrapped in an Arc for sharing.
    pub fn build_shared(self) -> Arc<AclTable<A>> {
        Arc::new(self.build())
    }
}

// Backward-compatible builder methods for BitmaskAuth.
impl AclTableBuilder<BitmaskAuth> {
    /// Add a filter for an exact endpoint match (O(1) lookup).
    pub fn add_exact(self, endpoint: impl Into<String>, filter: AclRuleFilter) -> Self {
        self.add_exact_matcher(endpoint, filter)
    }

    /// Add multiple filters for an exact endpoint.
    pub fn add_exact_filters(
        mut self,
        endpoint: impl Into<String>,
        filters: impl IntoIterator<Item = AclRuleFilter>,
    ) -> Self {
        let endpoint = endpoint.into();
        let rules: Vec<AclRule<BitmaskAuth>> = filters
            .into_iter()
            .map(|f| AclRule {
                matcher: Arc::new(f),
            })
            .collect();
        self.exact_rules.entry(endpoint).or_default().extend(rules);
        self
    }

    /// Add a filter for a prefix endpoint match.
    pub fn add_prefix(self, prefix: impl Into<String>, filter: AclRuleFilter) -> Self {
        let pattern = EndpointPattern::Prefix(prefix.into());
        self.add_pattern_matcher(pattern, filter)
    }

    /// Add a filter for a glob endpoint match.
    pub fn add_glob(self, glob: impl Into<String>, filter: AclRuleFilter) -> Self {
        let pattern = EndpointPattern::Glob(glob.into());
        self.add_pattern_matcher(pattern, filter)
    }

    /// Add a filter that matches any endpoint.
    pub fn add_any(self, filter: AclRuleFilter) -> Self {
        self.add_pattern_matcher(EndpointPattern::Any, filter)
    }

    /// Add a filter for a custom endpoint pattern.
    pub fn add_pattern(self, pattern: EndpointPattern, filter: AclRuleFilter) -> Self {
        self.add_pattern_matcher(pattern, filter)
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
            .add_any(
                AclRuleFilter::new()
                    .role_mask(ROLE_ADMIN)
                    .action(AclAction::Allow),
            )
            // User can access /api/
            .add_prefix(
                "/api/",
                AclRuleFilter::new()
                    .role_mask(ROLE_USER)
                    .action(AclAction::Allow),
            )
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
            .add_exact(
                "/public",
                AclRuleFilter::new()
                    .role_mask(u32::MAX)
                    .action(AclAction::Allow),
            )
            // Deny everything else
            .add_any(
                AclRuleFilter::new()
                    .role_mask(u32::MAX)
                    .action(AclAction::Deny),
            )
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
            .add_exact(
                "/shared",
                AclRuleFilter::new()
                    .role_mask(ROLE_ADMIN | ROLE_USER) // admin OR user
                    .action(AclAction::Allow),
            )
            .build();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Admin can access
        assert!(table.is_allowed("/shared", &RequestContext::new(ROLE_ADMIN, ip, "a")));
        // User can access
        assert!(table.is_allowed("/shared", &RequestContext::new(ROLE_USER, ip, "u")));
        // Guest cannot
        assert!(!table.is_allowed("/shared", &RequestContext::new(ROLE_GUEST, ip, "g")));
        // User+Admin can access (has overlap)
        assert!(table.is_allowed(
            "/shared",
            &RequestContext::new(ROLE_ADMIN | ROLE_USER, ip, "au")
        ));
    }

    #[test]
    fn test_id_ownership_via_path_param() {
        // `{id}` in the endpoint must be matched against the caller's id so a
        // user can only reach their own resource.
        let table = AclTable::builder()
            .default_action(AclAction::Deny)
            .add_glob(
                "/api/boat/{id}/**",
                AclRuleFilter::new()
                    .role_mask(u32::MAX)
                    .id("{id}")
                    .action(AclAction::Allow),
            )
            .build();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let meta = |path: &str| RequestMeta {
            method: http::Method::GET,
            path: path.to_string(),
            path_params: HashMap::new(),
            ip,
        };

        let owner = BitmaskAuth { roles: 0b1, id: "boat-123".to_string() };
        let other = BitmaskAuth { roles: 0b1, id: "boat-999".to_string() };

        // Owner reaches their own resource.
        assert_eq!(
            table.evaluate_request(&owner, &meta("/api/boat/boat-123/size")),
            AclAction::Allow
        );
        // A different user is denied (not just defaulted by a never-matching rule).
        assert_eq!(
            table.evaluate_request(&other, &meta("/api/boat/boat-123/size")),
            AclAction::Deny
        );
        // Owner cannot reach someone else's resource either.
        assert_eq!(
            table.evaluate_request(&owner, &meta("/api/boat/boat-999/size")),
            AclAction::Deny
        );
    }

    #[test]
    fn test_generic_table_custom_auth() {
        #[derive(Debug, Clone)]
        struct CustomAuth {
            role: String,
        }

        #[derive(Debug)]
        struct RequireRole {
            role: String,
            action: AclAction,
        }

        impl RuleMatcher<CustomAuth> for RequireRole {
            fn matches(&self, auth: &CustomAuth, _meta: &RequestMeta) -> bool {
                auth.role == self.role
            }
            fn action(&self) -> &AclAction {
                &self.action
            }
        }

        let table: AclTable<CustomAuth> = AclTableBuilder::new()
            .default_action(AclAction::Deny)
            .add_exact_matcher(
                "/admin",
                RequireRole {
                    role: "admin".to_string(),
                    action: AclAction::Allow,
                },
            )
            .build();

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let meta = RequestMeta {
            method: http::Method::GET,
            path: "/admin".to_string(),
            path_params: HashMap::new(),
            ip,
        };

        let admin = CustomAuth {
            role: "admin".to_string(),
        };
        assert!(table.is_request_allowed(&admin, &meta));

        let user = CustomAuth {
            role: "user".to_string(),
        };
        assert!(!table.is_request_allowed(&user, &meta));
    }
}
