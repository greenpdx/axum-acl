//! # axum-acl
//!
//! Flexible Access Control List (ACL) middleware for [axum](https://docs.rs/axum) 0.8.
//!
//! This crate provides a configurable ACL system using a 5-tuple rule system:
//! - **Endpoint**: Request path (HashMap key for O(1) lookup, or prefix/glob patterns)
//! - **Role**: `u32` bitmask for up to 32 roles per user
//! - **Time**: Time windows when rules are active (business hours, weekdays, etc.)
//! - **IP**: Client IP address (single IP, CIDR ranges, or lists)
//! - **ID**: User/session ID matching (exact or wildcard)
//!
//! ## Features
//!
//! - **Fast endpoint lookup** - HashMap for exact matches (O(1)), patterns for prefix/glob
//! - **Efficient role matching** - `u32` bitmask with single AND operation
//! - **Pluggable role extraction** - Headers, extensions, or custom extractors
//! - **Time-based access control** - Business hours, specific days
//! - **IP-based filtering** - Single IP, CIDR notation, lists
//! - **ID matching** - Exact match or wildcard for user/session IDs
//!
//! ## Quick Start
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use axum_acl::{AclLayer, AclTable, AclRuleFilter, AclAction, TimeWindow};
//! use std::net::SocketAddr;
//!
//! // Define role bits
//! const ROLE_ADMIN: u32 = 0b001;
//! const ROLE_USER: u32 = 0b010;
//!
//! async fn public_handler() -> &'static str {
//!     "Public content"
//! }
//!
//! async fn admin_handler() -> &'static str {
//!     "Admin only"
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // Define ACL rules
//!     let acl_table = AclTable::builder()
//!         // Default action when no rules match
//!         .default_action(AclAction::Deny)
//!         // Allow admins to access everything
//!         .add_any(AclRuleFilter::new()
//!             .role_mask(ROLE_ADMIN)
//!             .action(AclAction::Allow)
//!             .description("Admins can access everything"))
//!         // Allow users to access /api/** during business hours
//!         .add_prefix("/api/", AclRuleFilter::new()
//!             .role_mask(ROLE_USER)
//!             .time(TimeWindow::hours_on_days(9, 17, vec![0, 1, 2, 3, 4])) // Mon-Fri 9-5
//!             .action(AclAction::Allow)
//!             .description("Users can access API during business hours"))
//!         // Allow anyone to access /public/** (all roles)
//!         .add_prefix("/public/", AclRuleFilter::new()
//!             .role_mask(u32::MAX)
//!             .action(AclAction::Allow)
//!             .description("Public endpoints"))
//!         .build();
//!
//!     // Build the router with ACL middleware
//!     let app = Router::new()
//!         .route("/public/info", get(public_handler))
//!         .route("/admin/dashboard", get(admin_handler))
//!         .layer(AclLayer::new(acl_table));
//!
//!     // Important: Use into_make_service_with_connect_info for IP extraction
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(
//!         listener,
//!         app.into_make_service_with_connect_info::<SocketAddr>()
//!     ).await.unwrap();
//! }
//! ```
//!
//! ## Rule Evaluation
//!
//! 1. **Endpoint lookup**: Exact matches checked first (O(1) HashMap), then patterns
//! 2. **Filter matching**: For each endpoint match, filters are checked in order:
//!    - ID match: `rule.id == "*"` OR `rule.id == ctx.id`
//!    - Role match: `(rule.role_mask & ctx.roles) != 0`
//!    - IP match: CIDR-style network matching
//!    - Time match: Current time within window
//!
//! First matching rule determines the action. Default action used if no match.
//!
//! ## Role Extraction
//!
//! By default, roles are extracted from the `X-Roles` header as a `u32` bitmask.
//! The header can contain decimal (e.g., `5`) or hex (e.g., `0x1F`) values.
//!
//! ```no_run
//! use axum_acl::{AclLayer, AclTable, HeaderRoleExtractor};
//!
//! let table = AclTable::new();
//!
//! // Use a different header with default roles for anonymous users
//! let layer = AclLayer::new(table)
//!     .with_extractor(HeaderRoleExtractor::new("X-User-Roles").with_default_roles(0b100));
//! ```
//!
//! For more complex scenarios, implement the [`RoleExtractor`] trait:
//!
//! ```
//! use axum_acl::{RoleExtractor, RoleExtractionResult};
//! use http::Request;
//!
//! const ROLE_ADMIN: u32 = 0b001;
//! const ROLE_USER: u32 = 0b010;
//!
//! struct JwtRoleExtractor;
//!
//! impl<B> RoleExtractor<B> for JwtRoleExtractor {
//!     fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
//!         // Extract and validate JWT, return the roles bitmask
//!         if let Some(auth) = request.headers().get("Authorization") {
//!             // Parse JWT and extract roles...
//!             RoleExtractionResult::Roles(ROLE_USER)
//!         } else {
//!             RoleExtractionResult::Anonymous
//!         }
//!     }
//! }
//! ```
//!
//! ## Endpoint Patterns
//!
//! - **Exact**: `EndpointPattern::exact("/api/users")` - matches only `/api/users`
//! - **Prefix**: `EndpointPattern::prefix("/api/")` - matches `/api/users`, `/api/posts`, etc.
//! - **Glob**: `EndpointPattern::glob("/api/*/users")` - matches `/api/v1/users`, `/api/v2/users`
//!   - `*` matches exactly one path segment
//!   - `**` matches zero or more path segments
//! - **Any**: `EndpointPattern::any()` - matches all paths
//!
//! ## Time Windows
//!
//! ```
//! use axum_acl::TimeWindow;
//!
//! // Any time (default)
//! let always = TimeWindow::any();
//!
//! // 9 AM to 5 PM UTC
//! let business_hours = TimeWindow::hours(9, 17);
//!
//! // Monday to Friday, 9 AM to 5 PM UTC
//! let weekday_hours = TimeWindow::hours_on_days(9, 17, vec![0, 1, 2, 3, 4]);
//! ```
//!
//! ## IP Matching
//!
//! ```
//! use axum_acl::IpMatcher;
//!
//! // Any IP
//! let any = IpMatcher::any();
//!
//! // Single IP
//! let single = IpMatcher::parse("192.168.1.1").unwrap();
//!
//! // CIDR range
//! let network = IpMatcher::parse("10.0.0.0/8").unwrap();
//! ```
//!
//! ## Behind a Reverse Proxy
//!
//! When running behind a reverse proxy, configure the middleware to read the
//! client IP from a header:
//!
//! ```no_run
//! use axum_acl::{AclLayer, AclTable};
//!
//! let table = AclTable::new();
//! let layer = AclLayer::new(table)
//!     .with_forwarded_ip_header("X-Forwarded-For");
//! ```
//!
//! ## Custom Denied Response
//!
//! ```
//! use axum_acl::{AclLayer, AclTable, AccessDeniedHandler, AccessDenied, JsonDeniedHandler};
//! use axum::response::{Response, IntoResponse};
//! use http::StatusCode;
//!
//! // Use the built-in JSON handler
//! let layer = AclLayer::new(AclTable::new())
//!     .with_denied_handler(JsonDeniedHandler::new());
//!
//! // Or implement your own
//! struct CustomHandler;
//!
//! impl AccessDeniedHandler for CustomHandler {
//!     fn handle(&self, denied: &AccessDenied) -> Response {
//!         (StatusCode::FORBIDDEN, "Custom denied message").into_response()
//!     }
//! }
//! ```
//!
//! ## Dynamic Rules
//!
//! Implement [`AclRuleProvider`] to load rules from external sources:
//!
//! ```
//! use axum_acl::{AclRuleProvider, RuleEntry, AclRuleFilter, AclTable, AclAction, EndpointPattern};
//!
//! const ROLE_ADMIN: u32 = 0b001;
//!
//! struct DatabaseRuleProvider {
//!     // connection pool, etc.
//! }
//!
//! impl DatabaseRuleProvider {
//!     fn load_rules(&self) -> Result<Vec<RuleEntry>, std::io::Error> {
//!         // Query database for rules
//!         Ok(vec![
//!             RuleEntry::any(AclRuleFilter::new()
//!                 .role_mask(ROLE_ADMIN)
//!                 .action(AclAction::Allow))
//!         ])
//!     }
//! }
//!
//! // Use with the table builder
//! fn build_table(provider: &DatabaseRuleProvider) -> AclTable {
//!     let rules = provider.load_rules().unwrap();
//!     let mut builder = AclTable::builder();
//!     for entry in rules {
//!         builder = builder.add_pattern(entry.pattern, entry.filter);
//!     }
//!     builder.build()
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod extractor;
mod middleware;
mod rule;
mod table;

// Re-export main types
pub use config::{AclConfig as TomlConfig, ConfigError, ConfigSettings, RuleConfig};
pub use error::{AccessDenied, AccessDeniedHandler, AclError, DefaultDeniedHandler, JsonDeniedHandler};
pub use extractor::{
    // Role extraction
    AnonymousRoleExtractor, ChainedRoleExtractor, ExtensionRoleExtractor, FixedRoleExtractor,
    HeaderRoleExtractor, RoleExtractionResult, RoleExtractor,
    // ID extraction
    AnonymousIdExtractor, ExtensionIdExtractor, FixedIdExtractor, HeaderIdExtractor,
    IdExtractionResult, IdExtractor,
};
pub use middleware::{AclConfig, AclLayer, AclMiddleware};
pub use rule::{AclAction, AclRuleFilter, EndpointPattern, IpMatcher, RequestContext, TimeWindow};
pub use table::{AclRuleProvider, AclTable, AclTableBuilder, RuleEntry, StaticRuleProvider};

/// Prelude module for convenient imports.
///
/// ```
/// use axum_acl::prelude::*;
/// ```
pub mod prelude {
    pub use crate::config::ConfigError;
    pub use crate::error::{AccessDenied, AccessDeniedHandler, AclError};
    pub use crate::extractor::{
        HeaderRoleExtractor, RoleExtractionResult, RoleExtractor,
        HeaderIdExtractor, IdExtractionResult, IdExtractor,
    };
    pub use crate::middleware::AclLayer;
    pub use crate::rule::{AclAction, AclRuleFilter, EndpointPattern, IpMatcher, RequestContext, TimeWindow};
    pub use crate::table::{AclRuleProvider, AclTable, RuleEntry};
}
