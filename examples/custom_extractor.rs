//! Example demonstrating custom role extraction.
//!
//! This example shows how to:
//! - Extract roles from request extensions (set by auth middleware)
//! - Use time-based access control
//! - Use IP-based restrictions
//!
//! Run with: `cargo run --example custom_extractor`

use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::get,
    Router,
};
use axum_acl::{
    AclAction, AclLayer, AclRuleFilter, AclTable, IpMatcher, RoleExtractionResult,
    RoleExtractor, TimeWindow,
};
use http::StatusCode;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Role bitmask constants
const ROLE_ADMIN: u32 = 0b001;
const ROLE_USER: u32 = 0b010;

/// User information extracted from authentication.
/// In a real app, this would come from JWT validation, session lookup, etc.
#[derive(Clone, Debug)]
struct AuthenticatedUser {
    id: String,
    roles: u32, // bitmask of roles
}

/// Simulated authentication middleware.
/// In production, this would validate JWTs, session tokens, etc.
async fn auth_middleware(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    // Simulate extracting user from Authorization header
    if let Some(auth_header) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            // Fake auth: "Bearer admin" or "Bearer user"
            if let Some(role_name) = auth_str.strip_prefix("Bearer ") {
                let roles = match role_name {
                    "admin" => ROLE_ADMIN,
                    "user" => ROLE_USER,
                    "both" => ROLE_ADMIN | ROLE_USER,
                    _ => 0,
                };
                let user = AuthenticatedUser {
                    id: format!("{}-123", role_name),
                    roles,
                };
                request.extensions_mut().insert(user);
            }
        }
    }

    Ok(next.run(request).await)
}

/// Custom role extractor that reads from AuthenticatedUser extension.
#[derive(Clone)]
struct AuthUserRoleExtractor;

impl<B> RoleExtractor<B> for AuthUserRoleExtractor {
    fn extract_roles(&self, request: &http::Request<B>) -> RoleExtractionResult {
        match request.extensions().get::<AuthenticatedUser>() {
            Some(user) => {
                tracing::debug!(user_id = %user.id, roles = user.roles, "Extracted roles from auth");
                RoleExtractionResult::Roles(user.roles)
            }
            None => {
                tracing::debug!("No authenticated user found");
                RoleExtractionResult::Anonymous
            }
        }
    }
}

// Handlers
async fn public_endpoint() -> &'static str {
    "Public - no auth required"
}

async fn user_endpoint() -> &'static str {
    "User endpoint - requires 'user' or 'admin' role"
}

async fn admin_endpoint() -> &'static str {
    "Admin endpoint - requires 'admin' role"
}

async fn business_hours_endpoint() -> &'static str {
    "Business hours only endpoint"
}

async fn internal_endpoint() -> &'static str {
    "Internal endpoint - localhost only"
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_acl=debug,custom_extractor=debug".into()),
        )
        .init();

    // Build ACL table with various rule types
    let acl_table = AclTable::builder()
        .default_action(AclAction::Deny)
        // Admins can access everything, anytime, from anywhere
        .add_any(AclRuleFilter::new()
            .role_mask(ROLE_ADMIN)
            .action(AclAction::Allow)
            .description("Admin full access"))
        // Internal endpoints only accessible from localhost
        .add_prefix("/internal/", AclRuleFilter::new()
            .role_mask(u32::MAX)  // any role
            .ip(IpMatcher::parse("127.0.0.1").unwrap())
            .action(AclAction::Allow)
            .description("Internal endpoints - localhost only"))
        // Block internal access from non-localhost (explicit deny - checked after above)
        .add_prefix("/internal/", AclRuleFilter::new()
            .role_mask(u32::MAX)
            .action(AclAction::Deny)
            .description("Block internal from external IPs"))
        // Business hours endpoint - only accessible Mon-Fri 9-17 UTC
        .add_exact("/business", AclRuleFilter::new()
            .role_mask(ROLE_USER)
            .time(TimeWindow::hours_on_days(9, 17, vec![0, 1, 2, 3, 4]))
            .action(AclAction::Allow)
            .description("Business hours access"))
        // Users can access /user/** endpoints
        .add_prefix("/user/", AclRuleFilter::new()
            .role_mask(ROLE_USER)
            .action(AclAction::Allow)
            .description("User endpoints"))
        // Public endpoints
        .add_prefix("/public/", AclRuleFilter::new()
            .role_mask(u32::MAX)
            .action(AclAction::Allow)
            .description("Public access"))
        .build();

    tracing::info!(
        "Configured ACL: {} exact rules, {} pattern rules",
        acl_table.exact_rules().len(),
        acl_table.pattern_rules().len()
    );

    // Build router
    // Note: Auth middleware runs BEFORE ACL layer
    let app = Router::new()
        .route("/public/info", get(public_endpoint))
        .route("/user/profile", get(user_endpoint))
        .route("/admin/settings", get(admin_endpoint))
        .route("/business", get(business_hours_endpoint))
        .route("/internal/metrics", get(internal_endpoint))
        // Apply ACL layer with custom extractor
        .layer(AclLayer::new(acl_table).with_extractor(AuthUserRoleExtractor))
        // Auth middleware runs first (before ACL)
        .layer(middleware::from_fn(auth_middleware));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Starting server on {}", addr);
    tracing::info!("Test with:");
    tracing::info!("  curl http://localhost:3000/public/info");
    tracing::info!("  curl -H 'Authorization: Bearer user' http://localhost:3000/user/profile");
    tracing::info!("  curl -H 'Authorization: Bearer admin' http://localhost:3000/admin/settings");
    tracing::info!("  curl http://localhost:3000/internal/metrics");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
