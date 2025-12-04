//! Role extraction from HTTP requests.
//!
//! This module provides the [`RoleExtractor`] trait for extracting user roles
//! from incoming requests, along with several built-in implementations.
//!
//! Roles are represented as `u32` bitmasks, allowing up to 32 roles per user.

use http::Request;
use std::sync::Arc;

/// Result of role extraction.
#[derive(Debug, Clone)]
pub enum RoleExtractionResult {
    /// Roles were successfully extracted (u32 bitmask).
    Roles(u32),
    /// No role could be extracted (user is anonymous/guest).
    Anonymous,
    /// An error occurred during extraction.
    Error(String),
}

impl RoleExtractionResult {
    /// Get the roles bitmask, returning a default for anonymous users.
    pub fn roles_or(&self, default: u32) -> u32 {
        match self {
            Self::Roles(roles) => *roles,
            Self::Anonymous => default,
            Self::Error(_) => default,
        }
    }

    /// Get the roles, returning 0 (no roles) for anonymous users.
    pub fn roles_or_none(&self) -> u32 {
        self.roles_or(0)
    }
}

/// Trait for extracting roles from HTTP requests.
///
/// Implement this trait to customize how roles are determined from incoming
/// requests. This allows integration with various authentication systems.
///
/// Roles are represented as `u32` bitmasks, allowing multiple roles per user.
///
/// The trait is synchronous because role extraction typically involves
/// reading headers or request extensions, which doesn't require async.
///
/// # Example
/// ```
/// use axum_acl::{RoleExtractor, RoleExtractionResult};
/// use http::Request;
///
/// const ROLE_ADMIN: u32 = 0b001;
/// const ROLE_USER: u32 = 0b010;
///
/// /// Extract roles from a custom header as a bitmask.
/// struct CustomRolesExtractor;
///
/// impl<B> RoleExtractor<B> for CustomRolesExtractor {
///     fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
///         match request.headers().get("X-Roles") {
///             Some(value) => {
///                 match value.to_str() {
///                     Ok(s) => {
///                         // Parse comma-separated role names to bitmask
///                         let mut mask = 0u32;
///                         for role in s.split(',') {
///                             match role.trim() {
///                                 "admin" => mask |= ROLE_ADMIN,
///                                 "user" => mask |= ROLE_USER,
///                                 _ => {}
///                             }
///                         }
///                         RoleExtractionResult::Roles(mask)
///                     }
///                     Err(_) => RoleExtractionResult::Anonymous,
///                 }
///             }
///             None => RoleExtractionResult::Anonymous,
///         }
///     }
/// }
/// ```
pub trait RoleExtractor<B>: Send + Sync {
    /// Extract the roles bitmask from an HTTP request.
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult;
}

// Implement for Arc<T> where T: RoleExtractor
impl<B, T: RoleExtractor<B>> RoleExtractor<B> for Arc<T> {
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
        (**self).extract_roles(request)
    }
}

// Implement for Box<T> where T: RoleExtractor
impl<B, T: RoleExtractor<B> + ?Sized> RoleExtractor<B> for Box<T> {
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
        (**self).extract_roles(request)
    }
}

/// Extract roles bitmask from an HTTP header.
///
/// The header value is parsed as a u32 bitmask directly, or you can use
/// a custom parser function to convert header values to bitmasks.
///
/// # Example
/// ```
/// use axum_acl::HeaderRoleExtractor;
///
/// // Extract roles bitmask directly from X-Roles header (as decimal or hex)
/// let extractor = HeaderRoleExtractor::new("X-Roles");
///
/// // With a custom default roles bitmask for missing headers
/// let extractor = HeaderRoleExtractor::new("X-Roles")
///     .with_default_roles(0b100);  // guest role
/// ```
#[derive(Debug, Clone)]
pub struct HeaderRoleExtractor {
    header_name: String,
    default_roles: u32,
}

impl HeaderRoleExtractor {
    /// Create a new header role extractor.
    pub fn new(header_name: impl Into<String>) -> Self {
        Self {
            header_name: header_name.into(),
            default_roles: 0,
        }
    }

    /// Set default roles bitmask to use when the header is missing.
    pub fn with_default_roles(mut self, roles: u32) -> Self {
        self.default_roles = roles;
        self
    }
}

impl<B> RoleExtractor<B> for HeaderRoleExtractor {
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
        match request.headers().get(&self.header_name) {
            Some(value) => match value.to_str() {
                Ok(s) if !s.is_empty() => {
                    // Try parsing as decimal first, then hex (with 0x prefix)
                    let trimmed = s.trim();
                    if let Ok(roles) = trimmed.parse::<u32>() {
                        RoleExtractionResult::Roles(roles)
                    } else if let Some(hex) = trimmed.strip_prefix("0x") {
                        u32::from_str_radix(hex, 16)
                            .map(RoleExtractionResult::Roles)
                            .unwrap_or_else(|_| {
                                if self.default_roles != 0 {
                                    RoleExtractionResult::Roles(self.default_roles)
                                } else {
                                    RoleExtractionResult::Anonymous
                                }
                            })
                    } else if self.default_roles != 0 {
                        RoleExtractionResult::Roles(self.default_roles)
                    } else {
                        RoleExtractionResult::Anonymous
                    }
                }
                _ => {
                    if self.default_roles != 0 {
                        RoleExtractionResult::Roles(self.default_roles)
                    } else {
                        RoleExtractionResult::Anonymous
                    }
                }
            },
            None => {
                if self.default_roles != 0 {
                    RoleExtractionResult::Roles(self.default_roles)
                } else {
                    RoleExtractionResult::Anonymous
                }
            }
        }
    }
}

/// Extract roles from a request extension.
///
/// This extractor looks for roles that were set by a previous middleware
/// (e.g., an authentication middleware) as a request extension.
///
/// # Example
/// ```
/// use axum_acl::ExtensionRoleExtractor;
///
/// // The authentication middleware should insert a Roles struct into extensions
/// #[derive(Clone)]
/// struct UserRoles(u32);
///
/// let extractor = ExtensionRoleExtractor::<UserRoles>::new(|roles| roles.0);
/// ```
pub struct ExtensionRoleExtractor<T> {
    extract_fn: Box<dyn Fn(&T) -> u32 + Send + Sync>,
}

impl<T> ExtensionRoleExtractor<T> {
    /// Create a new extension role extractor.
    ///
    /// The `extract_fn` converts the extension type to a roles bitmask.
    pub fn new<F>(extract_fn: F) -> Self
    where
        F: Fn(&T) -> u32 + Send + Sync + 'static,
    {
        Self {
            extract_fn: Box::new(extract_fn),
        }
    }
}

impl<T> std::fmt::Debug for ExtensionRoleExtractor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionRoleExtractor")
            .field("type", &std::any::type_name::<T>())
            .finish()
    }
}

impl<B, T: Clone + Send + Sync + 'static> RoleExtractor<B> for ExtensionRoleExtractor<T> {
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
        match request.extensions().get::<T>() {
            Some(ext) => RoleExtractionResult::Roles((self.extract_fn)(ext)),
            None => RoleExtractionResult::Anonymous,
        }
    }
}

/// A roles extractor that always returns fixed roles.
///
/// Useful for testing or for routes that should always use specific roles.
#[derive(Debug, Clone)]
pub struct FixedRoleExtractor {
    roles: u32,
}

impl FixedRoleExtractor {
    /// Create a new fixed roles extractor.
    pub fn new(roles: u32) -> Self {
        Self { roles }
    }
}

impl<B> RoleExtractor<B> for FixedRoleExtractor {
    fn extract_roles(&self, _request: &Request<B>) -> RoleExtractionResult {
        RoleExtractionResult::Roles(self.roles)
    }
}

/// A role extractor that always returns anonymous (no roles).
#[derive(Debug, Clone, Default)]
pub struct AnonymousRoleExtractor;

impl AnonymousRoleExtractor {
    /// Create a new anonymous role extractor.
    pub fn new() -> Self {
        Self
    }
}

impl<B> RoleExtractor<B> for AnonymousRoleExtractor {
    fn extract_roles(&self, _request: &Request<B>) -> RoleExtractionResult {
        RoleExtractionResult::Anonymous
    }
}

/// A composite extractor that tries multiple extractors in order.
///
/// Returns the first successful roles extraction, or anonymous if all fail.
/// Roles from multiple extractors are NOT combined - only the first match is used.
pub struct ChainedRoleExtractor<B> {
    extractors: Vec<Box<dyn RoleExtractor<B>>>,
}

impl<B> ChainedRoleExtractor<B> {
    /// Create a new chained role extractor.
    pub fn new() -> Self {
        Self {
            extractors: Vec::new(),
        }
    }

    /// Add an extractor to the chain.
    pub fn add<E: RoleExtractor<B> + 'static>(mut self, extractor: E) -> Self {
        self.extractors.push(Box::new(extractor));
        self
    }
}

impl<B> Default for ChainedRoleExtractor<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> std::fmt::Debug for ChainedRoleExtractor<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainedRoleExtractor")
            .field("extractors_count", &self.extractors.len())
            .finish()
    }
}

impl<B> RoleExtractor<B> for ChainedRoleExtractor<B>
where
    B: Send + Sync,
{
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
        for extractor in &self.extractors {
            match extractor.extract_roles(request) {
                RoleExtractionResult::Roles(roles) => return RoleExtractionResult::Roles(roles),
                RoleExtractionResult::Error(e) => {
                    tracing::warn!(error = %e, "Role extractor failed, trying next");
                }
                RoleExtractionResult::Anonymous => continue,
            }
        }
        RoleExtractionResult::Anonymous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn test_header_extractor_decimal() {
        let extractor = HeaderRoleExtractor::new("X-Roles");

        let req = Request::builder()
            .header("X-Roles", "5")  // 0b101 = roles 0 and 2
            .body(())
            .unwrap();

        match extractor.extract_roles(&req) {
            RoleExtractionResult::Roles(roles) => assert_eq!(roles, 5),
            _ => panic!("Expected Roles"),
        }
    }

    #[test]
    fn test_header_extractor_hex() {
        let extractor = HeaderRoleExtractor::new("X-Roles");

        let req = Request::builder()
            .header("X-Roles", "0x1F")  // 0b11111 = roles 0-4
            .body(())
            .unwrap();

        match extractor.extract_roles(&req) {
            RoleExtractionResult::Roles(roles) => assert_eq!(roles, 0x1F),
            _ => panic!("Expected Roles"),
        }
    }

    #[test]
    fn test_header_extractor_missing() {
        let extractor = HeaderRoleExtractor::new("X-Roles");

        let req = Request::builder().body(()).unwrap();

        match extractor.extract_roles(&req) {
            RoleExtractionResult::Anonymous => {}
            _ => panic!("Expected Anonymous"),
        }
    }

    #[test]
    fn test_header_extractor_default() {
        let extractor = HeaderRoleExtractor::new("X-Roles")
            .with_default_roles(0b100);  // guest role

        let req = Request::builder().body(()).unwrap();

        match extractor.extract_roles(&req) {
            RoleExtractionResult::Roles(roles) => assert_eq!(roles, 0b100),
            _ => panic!("Expected Roles"),
        }
    }

    #[test]
    fn test_fixed_extractor() {
        let extractor = FixedRoleExtractor::new(0b11);  // admin + user

        let req = Request::builder().body(()).unwrap();

        match extractor.extract_roles(&req) {
            RoleExtractionResult::Roles(roles) => assert_eq!(roles, 0b11),
            _ => panic!("Expected Roles"),
        }
    }
}
