//! Comprehensive axum-acl Demo
//!
//! This example demonstrates ALL features of the axum-acl library:
//!
//! ## Features Demonstrated
//!
//! 1. **Endpoint Patterns**: Exact, Prefix, Glob, Any
//! 2. **Action Types**: Allow, Deny, Error, Reroute, Log
//! 3. **Role-Based Access Control**: Bitmask roles (admin=1, user=2, viewer=4)
//! 4. **ID Matching**: Exact ID and path parameter `{id}` extraction
//! 5. **IP Filtering**: Single IP, CIDR ranges
//! 6. **Time-Based Restrictions**: Business hours (9-17), weekdays only
//! 7. **Configuration**: Builder API and TOML file loading
//! 8. **Custom Handlers**: JSON denied responses
//!
//! ## Test Commands
//!
//! ```bash
//! # Start the server
//! cargo run
//!
//! # === PUBLIC ENDPOINTS (no auth required) ===
//! curl http://localhost:3000/                          # Public homepage
//! curl http://localhost:3000/api/public/docs           # Public prefix pattern
//! curl http://localhost:3000/api/public/faq
//!
//! # === HEALTH CHECK (Log action - allowed but logged) ===
//! curl http://localhost:3000/api/health
//!
//! # === USER ENDPOINTS (role required) ===
//! curl http://localhost:3000/api/users                           # 403 - no role
//! curl -H "X-Roles: 2" http://localhost:3000/api/users           # OK - user role
//! curl -H "X-Roles: 1" http://localhost:3000/api/users           # OK - admin role
//!
//! # === OWNER-ONLY ENDPOINTS (ID matching with path parameter) ===
//! # Note: ID extraction requires with_id_extractor() which is not yet implemented
//! # See: https://github.com/greenpdx/axum-acl/issues/XX
//!
//! # === ADMIN ENDPOINTS (admin role + localhost IP) ===
//! curl -H "X-Roles: 1" http://localhost:3000/api/admin/dashboard # OK from localhost
//! curl -H "X-Roles: 2" http://localhost:3000/api/admin/dashboard # 403 - not admin
//!
//! # === TIME-RESTRICTED ENDPOINTS (business hours only) ===
//! curl -H "X-Roles: 2" http://localhost:3000/api/reports         # OK during 9-17 Mon-Fri
//!
//! # === REROUTE EXAMPLE ===
//! curl http://localhost:3000/old-api                             # Redirects to /api/v2
//!
//! # === CUSTOM ERROR RESPONSE ===
//! curl http://localhost:3000/deprecated                          # 410 Gone
//!
//! # === GLOB PATTERNS ===
//! curl -H "X-Roles: 2" http://localhost:3000/api/data/users/export    # Export endpoint
//! curl -H "X-Roles: 2" http://localhost:3000/api/data/orders/export   # Export endpoint
//!
//! # === TOML CONFIG ENDPOINT (separate router) ===
//! curl http://localhost:3001/api/health                          # TOML-configured server
//! ```

use axum::{
    extract::Path,
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::get,
    Router,
};
use axum_acl::{
    AccessDenied, AccessDeniedHandler, AclAction, AclLayer, AclRuleFilter, AclTable,
    HeaderRoleExtractor, IpMatcher, JsonDeniedHandler, TimeWindow,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

// =============================================================================
// ROLE DEFINITIONS (bitmask)
// =============================================================================

const ROLE_ADMIN: u32 = 0x01;       // bit 0 - Full access
const ROLE_USER: u32 = 0x02;        // bit 1 - Standard user
const ROLE_VIEWER: u32 = 0x04;      // bit 2 - Read-only access
const ROLE_ANON: u32 = 0x80000000;  // bit 31 - Anonymous/public (reserved)

// =============================================================================
// CUSTOM ACCESS DENIED HANDLER (JSON responses with extra details)
// =============================================================================

#[derive(Clone)]
struct CustomDeniedHandler;

impl AccessDeniedHandler for CustomDeniedHandler {
    fn handle(&self, denied: &AccessDenied) -> Response {
        let body = json!({
            "error": "Access Denied",
            "path": denied.path,
            "roles": format!("0x{:02X}", denied.roles),
            "id": denied.id,
            "message": denied.message.as_deref().unwrap_or("Insufficient permissions"),
        });

        let status = axum::http::StatusCode::FORBIDDEN;
        (status, Json(body)).into_response()
    }
}

// =============================================================================
// ROUTE HANDLERS
// =============================================================================

async fn home() -> Html<&'static str> {
    Html("<h1>Welcome to axum-acl Demo</h1><p>Public homepage - no auth required</p>")
}

async fn health() -> &'static str {
    "OK"
}

async fn public_docs() -> &'static str {
    "Public documentation - accessible to everyone"
}

async fn list_users() -> Json<serde_json::Value> {
    Json(json!({
        "users": ["alice", "bob", "charlie"]
    }))
}

async fn user_profile(Path(user_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "user_id": user_id,
        "name": "User Profile",
        "message": "You can only see this if you own this profile or are admin"
    }))
}

async fn admin_dashboard() -> Json<serde_json::Value> {
    Json(json!({
        "dashboard": "Admin Dashboard",
        "message": "Only admins from allowed IPs can see this"
    }))
}

async fn reports() -> Json<serde_json::Value> {
    Json(json!({
        "reports": ["Q1 Sales", "Q2 Sales"],
        "message": "Only available during business hours (9-17 Mon-Fri UTC)"
    }))
}

async fn export_data(Path((resource, _action)): Path<(String, String)>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": resource,
        "status": "Export initiated",
        "message": "Glob pattern matched /api/data/*/export"
    }))
}

async fn api_v2() -> Json<serde_json::Value> {
    Json(json!({
        "version": "2.0",
        "message": "You were rerouted from /old-api"
    }))
}

async fn deprecated() -> (axum::http::StatusCode, &'static str) {
    // This won't be reached - ACL returns 410 Gone
    (axum::http::StatusCode::GONE, "This endpoint is deprecated")
}

async fn catch_all() -> &'static str {
    "Catch-all route"
}

// =============================================================================
// ACL TABLE BUILDER (Programmatic Configuration)
// =============================================================================

fn build_acl_table() -> AclTable {
    AclTable::builder()
        // Default action when no rules match
        .default_action(AclAction::Deny)
        // ---------------------------------------------------------------------
        // PUBLIC ENDPOINTS - Allow everyone (including anonymous with ROLE_ANON)
        // ---------------------------------------------------------------------
        .add_exact(
            "/",
            AclRuleFilter::new()
                .role_mask(u32::MAX) // All roles including ROLE_ANON
                .action(AclAction::Allow)
                .description("Public homepage"),
        )
        // Prefix pattern: all /api/public/* endpoints
        .add_prefix(
            "/api/public/",
            AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::Allow)
                .description("Public API endpoints"),
        )
        // ---------------------------------------------------------------------
        // HEALTH CHECK - Log and allow (for monitoring)
        // ---------------------------------------------------------------------
        .add_exact(
            "/api/health",
            AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::Log {
                    level: "info".to_string(),
                    message: Some("Health check accessed".to_string()),
                })
                .description("Health check - logged"),
        )
        // ---------------------------------------------------------------------
        // ADMIN OVERRIDE - Admins can access user profiles regardless of ID
        // (Must be before the owner-only rule to take precedence)
        // ---------------------------------------------------------------------
        .add_glob(
            "/api/users/{id}/profile",
            AclRuleFilter::new()
                .role(0) // Admin role (bit 0)
                .action(AclAction::Allow)
                .description("Admin can view any user profile"),
        )
        // ---------------------------------------------------------------------
        // OWNER-ONLY ENDPOINT - User can only access their own profile
        // Uses {id} path parameter matching
        // NOTE: Full ID matching requires with_id_extractor() - see GitHub issue
        // ---------------------------------------------------------------------
        .add_glob(
            "/api/users/{id}/profile",
            AclRuleFilter::new()
                .role(1) // User role (bit 1)
                .id("{id}") // Match path parameter to user ID
                .action(AclAction::Allow)
                .description("User can view own profile only"),
        )
        // ---------------------------------------------------------------------
        // USER ENDPOINTS - Require user or admin role
        // ---------------------------------------------------------------------
        .add_exact(
            "/api/users",
            AclRuleFilter::new()
                .role_mask(ROLE_ADMIN | ROLE_USER) // Either role works
                .action(AclAction::Allow)
                .description("List users - requires user or admin role"),
        )
        // ---------------------------------------------------------------------
        // ADMIN ENDPOINTS - Admin role + localhost IP only
        // ---------------------------------------------------------------------
        .add_prefix(
            "/api/admin/",
            AclRuleFilter::new()
                .role(0) // Admin role
                .ip(IpMatcher::parse("127.0.0.1").unwrap())
                .action(AclAction::Allow)
                .description("Admin endpoints - admin role + localhost only"),
        )
        // Also allow from IPv6 localhost
        .add_prefix(
            "/api/admin/",
            AclRuleFilter::new()
                .role(0)
                .ip(IpMatcher::parse("::1").unwrap())
                .action(AclAction::Allow)
                .description("Admin endpoints - admin role + IPv6 localhost"),
        )
        // ---------------------------------------------------------------------
        // TIME-RESTRICTED ENDPOINT - Business hours only (9-17 Mon-Fri)
        // ---------------------------------------------------------------------
        .add_exact(
            "/api/reports",
            AclRuleFilter::new()
                .role_mask(ROLE_ADMIN | ROLE_USER)
                .time(TimeWindow::hours_on_days(9, 17, vec![0, 1, 2, 3, 4])) // Mon-Fri
                .action(AclAction::Allow)
                .description("Reports - business hours only (Mon-Fri 9-17 UTC)"),
        )
        // ---------------------------------------------------------------------
        // GLOB PATTERN - Export endpoints for any resource
        // Matches /api/data/*/export
        // ---------------------------------------------------------------------
        .add_glob(
            "/api/data/*/export",
            AclRuleFilter::new()
                .role_mask(ROLE_ADMIN | ROLE_USER)
                .action(AclAction::Allow)
                .description("Export any resource"),
        )
        // ---------------------------------------------------------------------
        // REROUTE - Redirect old API to new version
        // Using the helper method AclAction::reroute()
        // ---------------------------------------------------------------------
        .add_exact(
            "/old-api",
            AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::reroute("/api/v2"))
                .description("Redirect old API to v2"),
        )
        // ---------------------------------------------------------------------
        // CUSTOM ERROR - Deprecated endpoint returns 410 Gone
        // Using the helper method AclAction::error()
        // ---------------------------------------------------------------------
        .add_exact(
            "/deprecated",
            AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::error(410, Some("This endpoint has been removed".to_string())))
                .description("Deprecated endpoint"),
        )
        // ---------------------------------------------------------------------
        // API V2 - Public new API endpoint
        // ---------------------------------------------------------------------
        .add_exact(
            "/api/v2",
            AclRuleFilter::new()
                .role_mask(u32::MAX)
                .action(AclAction::Allow)
                .description("API v2 endpoint"),
        )
        .build()
}

// =============================================================================
// TOML CONFIGURATION EXAMPLE
// =============================================================================

fn load_acl_from_toml() -> AclTable {
    // Embed TOML at compile time
    let toml_content = include_str!("../config/acl.toml");
    AclTable::from_toml(toml_content).expect("Failed to parse ACL TOML config")
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("axum_acl=debug,axum_acl_demo=debug")
        .init();

    // Build ACL table programmatically
    let acl_table = Arc::new(build_acl_table());

    // Create ACL middleware layer with custom extractor and handler
    // Anonymous users get ROLE_ANON (0x80) so they can match public endpoint rules
    let acl_layer = AclLayer::new((*acl_table).clone())
        .with_extractor(HeaderRoleExtractor::new("X-Roles").with_default_roles(ROLE_ANON))
        .with_denied_handler(CustomDeniedHandler);

    // Build the router with ACL middleware
    let app = Router::new()
        // Public endpoints
        .route("/", get(home))
        .route("/api/health", get(health))
        .route("/api/public/{*path}", get(public_docs))
        // User endpoints
        .route("/api/users", get(list_users))
        .route("/api/users/{user_id}/profile", get(user_profile))
        // Admin endpoints
        .route("/api/admin/dashboard", get(admin_dashboard))
        // Time-restricted
        .route("/api/reports", get(reports))
        // Glob pattern export
        .route("/api/data/{resource}/{action}", get(export_data))
        // Reroute target
        .route("/api/v2", get(api_v2))
        .route("/old-api", get(|| async { Redirect::to("/api/v2") }))
        // Deprecated (ACL handles the error response)
        .route("/deprecated", get(deprecated))
        // Catch-all
        .fallback(get(catch_all))
        // Apply ACL middleware
        .layer(acl_layer);

    // Also start a TOML-configured server on port 3001
    let toml_acl_table = load_acl_from_toml();
    let toml_acl_layer = AclLayer::new(toml_acl_table)
        .with_extractor(HeaderRoleExtractor::new("X-Roles").with_default_roles(ROLE_ANON))
        .with_denied_handler(JsonDeniedHandler::new().with_details());

    let toml_app = Router::new()
        .route("/", get(home))
        .route("/api/health", get(health))
        .route("/api/users", get(list_users))
        .layer(toml_acl_layer);

    println!("===========================================");
    println!("       axum-acl Comprehensive Demo");
    println!("===========================================");
    println!();
    println!("Builder API server running on: http://localhost:3000");
    println!("TOML config server running on: http://localhost:3001");
    println!();
    println!("Role Definitions:");
    println!("  Admin:  0x01 (bit 0)  - Full access");
    println!("  User:   0x02 (bit 1)  - Standard access");
    println!("  Viewer: 0x04 (bit 2)  - Read-only access");
    println!("  Anon:   0x80000000 (bit 31) - Anonymous (reserved)");
    println!();
    println!("Example curl commands:");
    println!("  curl http://localhost:3000/                     # Public");
    println!("  curl -H 'X-Roles: 2' http://localhost:3000/api/users");
    println!("  curl -H 'X-Roles: 1' http://localhost:3000/api/admin/dashboard");
    println!();

    // Run both servers
    let listener1 = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let listener2 = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();

    tokio::join!(
        async {
            axum::serve(
                listener1,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        },
        async {
            axum::serve(
                listener2,
                toml_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        }
    );
}
