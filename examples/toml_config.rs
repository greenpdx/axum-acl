//! Example demonstrating TOML configuration for ACL rules.
//!
//! This example shows two methods:
//! 1. Compile-time embedded configuration (include_str!)
//! 2. Runtime file loading
//!
//! Run with: `cargo run --example toml_config`
//!
//! Test endpoints:
//! ```sh
//! # Public endpoint (allowed for anyone)
//! curl http://localhost:3000/public/info
//!
//! # Health check (allowed)
//! curl http://localhost:3000/health
//!
//! # API as admin (allowed anytime) - role_mask 1
//! curl -H "X-Roles: 1" http://localhost:3000/api/users
//!
//! # API as user (allowed) - role_mask 2
//! curl -H "X-Roles: 2" http://localhost:3000/api/users
//!
//! # Admin endpoint as admin (allowed)
//! curl -H "X-Roles: 1" http://localhost:3000/admin/dashboard
//!
//! # Admin endpoint as user (403 error)
//! curl -H "X-Roles: 2" http://localhost:3000/admin/dashboard
//!
//! # Internal endpoint from localhost (allowed)
//! curl http://localhost:3000/internal/metrics
//!
//! # Old API redirect
//! curl -v http://localhost:3000/old-api/users
//! ```

use axum::{routing::get, Router};
use axum_acl::AclLayer;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// ============================================================================
// METHOD 1: Compile-time embedded configuration
// ============================================================================
// The configuration is baked into the binary at compile time.
// Changes require recompilation.

const EMBEDDED_CONFIG: &str = r#"
[settings]
default_action = "deny"

# Role masks: 1 = admin, 2 = user, 3 = admin+user

[[rules]]
role_mask = 1
endpoint = "*"
action = "allow"
priority = 10
description = "Admins have full access"

[[rules]]
role_mask = "*"
endpoint = "/admin/**"
action = { type = "error", code = 403, message = "Admin access required" }
priority = 20

[[rules]]
role_mask = 2
endpoint = "/api/**"
action = "allow"
priority = 100

[[rules]]
role_mask = "*"
endpoint = "/public/**"
action = "allow"
priority = 200

[[rules]]
role_mask = "*"
endpoint = "/health"
action = "allow"
priority = 200

[[rules]]
role_mask = "*"
endpoint = "/internal/**"
ip = "127.0.0.1"
action = "allow"
priority = 30

[[rules]]
role_mask = "*"
endpoint = "/internal/**"
action = { type = "error", code = 403, message = "Internal access only" }
priority = 31

[[rules]]
role_mask = "*"
endpoint = "/old-api/**"
action = { type = "reroute", target = "/api/v2" }
priority = 50
"#;

// Alternative: Load from file at compile time
// const EMBEDDED_CONFIG: &str = include_str!("acl.toml");

// ============================================================================
// METHOD 2: Runtime file loading (commented out)
// ============================================================================
// fn load_config_from_file() -> axum_acl::AclTable {
//     axum_acl::AclTable::from_toml_file("config/acl.toml")
//         .expect("Failed to load ACL config")
// }

// Handlers
async fn public_info() -> &'static str {
    "Public information - accessible to everyone"
}

async fn health() -> &'static str {
    "OK"
}

async fn api_users() -> &'static str {
    "API Users - requires 'user' or 'admin' role"
}

async fn api_v2() -> &'static str {
    "API v2 - new version"
}

async fn admin_dashboard() -> &'static str {
    "Admin Dashboard - requires 'admin' role"
}

async fn internal_metrics() -> &'static str {
    "Internal Metrics - localhost only"
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_acl=debug,toml_config=info".into()),
        )
        .init();

    // Load ACL configuration from embedded TOML
    let acl_table = axum_acl::AclTable::from_toml(EMBEDDED_CONFIG)
        .expect("Failed to parse embedded ACL config");

    // Alternative: Load from file at runtime
    // let acl_table = axum_acl::AclTable::from_toml_file("examples/acl.toml")
    //     .expect("Failed to load ACL config file");

    tracing::info!(
        "Loaded ACL: {} exact rules, {} pattern rules",
        acl_table.exact_rules().len(),
        acl_table.pattern_rules().len()
    );
    tracing::info!("Default action: {:?}", acl_table.default_action());

    // Build router
    let app = Router::new()
        .route("/public/info", get(public_info))
        .route("/health", get(health))
        .route("/api/users", get(api_users))
        .route("/api/v2", get(api_v2))
        .route("/admin/dashboard", get(admin_dashboard))
        .route("/internal/metrics", get(internal_metrics))
        .layer(AclLayer::new(acl_table));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Starting server on {}", addr);
    tracing::info!("");
    tracing::info!("Test commands:");
    tracing::info!("  curl http://localhost:3000/public/info          # Public (allowed)");
    tracing::info!("  curl http://localhost:3000/health               # Health check (allowed)");
    tracing::info!("  curl -H 'X-Roles: 1' http://localhost:3000/admin/dashboard  # Admin (allowed)");
    tracing::info!("  curl -H 'X-Roles: 2' http://localhost:3000/api/users         # User API (allowed)");
    tracing::info!("  curl -H 'X-Roles: 2' http://localhost:3000/admin/dashboard   # User->Admin (denied)");
    tracing::info!("  curl http://localhost:3000/internal/metrics     # Internal from localhost (allowed)");
    tracing::info!("  curl -v http://localhost:3000/old-api/users     # Redirect to /api/v2");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
