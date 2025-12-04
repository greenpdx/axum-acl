//! Basic example demonstrating axum-acl middleware.
//!
//! Run with: `cargo run --example basic`
//!
//! Test with:
//! ```sh
//! # Public endpoint (anyone can access)
//! curl http://localhost:3000/public/info
//!
//! # API endpoint as admin (allowed)
//! curl -H "X-Roles: 1" http://localhost:3000/api/users
//!
//! # API endpoint as user (allowed)
//! curl -H "X-Roles: 2" http://localhost:3000/api/users
//!
//! # Admin endpoint as admin (allowed)
//! curl -H "X-Roles: 1" http://localhost:3000/admin/dashboard
//!
//! # Admin endpoint as user (denied)
//! curl -H "X-Roles: 2" http://localhost:3000/admin/dashboard
//!
//! # No role header (denied for protected endpoints)
//! curl http://localhost:3000/api/users
//! ```

use axum::{routing::get, Router};
use axum_acl::{AclAction, AclLayer, AclRuleFilter, AclTable, JsonDeniedHandler};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Role bitmask constants
const ROLE_ADMIN: u32 = 0b001;
const ROLE_USER: u32 = 0b010;

// Handler functions
async fn public_info() -> &'static str {
    "Public information - accessible to everyone"
}

async fn api_users() -> &'static str {
    "API Users endpoint - requires 'user' or 'admin' role"
}

async fn api_posts() -> &'static str {
    "API Posts endpoint - requires 'user' or 'admin' role"
}

async fn admin_dashboard() -> &'static str {
    "Admin Dashboard - requires 'admin' role"
}

async fn admin_settings() -> &'static str {
    "Admin Settings - requires 'admin' role"
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_acl=debug,basic=debug".into()),
        )
        .init();

    // Build the ACL table with rules
    let acl_table = AclTable::builder()
        // Default action: deny if no rule matches
        .default_action(AclAction::Deny)
        // Rule 1: Admins can access everything
        .add_any(AclRuleFilter::new()
            .role_mask(ROLE_ADMIN)
            .action(AclAction::Allow)
            .description("Admins have full access"))
        // Rule 2: Users can access /api/** endpoints
        .add_prefix("/api/", AclRuleFilter::new()
            .role_mask(ROLE_USER)
            .action(AclAction::Allow)
            .description("Users can access API endpoints"))
        // Rule 3: Anyone can access /public/** endpoints
        .add_prefix("/public/", AclRuleFilter::new()
            .role_mask(u32::MAX)  // all roles
            .action(AclAction::Allow)
            .description("Public endpoints accessible to all"))
        // Rule 4: Health check is public
        .add_exact("/health", AclRuleFilter::new()
            .role_mask(u32::MAX)
            .action(AclAction::Allow)
            .description("Health check endpoint"))
        .build();

    // Log info about the table
    tracing::info!(
        "ACL Table configured: {} exact rules, {} pattern rules",
        acl_table.exact_rules().len(),
        acl_table.pattern_rules().len()
    );

    // Build the router with ACL middleware
    let app = Router::new()
        // Public routes
        .route("/public/info", get(public_info))
        .route("/health", get(|| async { "OK" }))
        // API routes (require user or admin role)
        .route("/api/users", get(api_users))
        .route("/api/posts", get(api_posts))
        // Admin routes (require admin role)
        .route("/admin/dashboard", get(admin_dashboard))
        .route("/admin/settings", get(admin_settings))
        // Apply ACL middleware to all routes
        .layer(
            AclLayer::new(acl_table)
                // Use JSON responses for denied requests
                .with_denied_handler(JsonDeniedHandler::new())
                // Set the roles for unauthenticated requests (0 = no roles)
                .with_anonymous_roles(0),
        );

    // Start the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Starting server on {}", addr);
    tracing::info!("Test with:");
    tracing::info!("  curl http://localhost:3000/public/info");
    tracing::info!("  curl -H 'X-Roles: 1' http://localhost:3000/admin/dashboard");
    tracing::info!("  curl -H 'X-Roles: 2' http://localhost:3000/api/users");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // Important: Use into_make_service_with_connect_info for IP extraction
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
