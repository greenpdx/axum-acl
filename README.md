# axum-acl

Flexible Access Control List (ACL) middleware for [axum](https://docs.rs/axum) 0.8.

## Features

- **TOML Configuration** - Define rules in config files (compile-time or runtime)
- **Table-based rules** - No hardcoded rules; all access control is configured at runtime
- **Four-tuple matching** - Rules match on Role + Endpoint + Time + IP
- **Extended actions** - Allow, Deny, Error (custom codes), Reroute, Log
- **Flexible role extraction** - Extract roles from headers, extensions, or custom sources
- **Pattern matching** - Exact, prefix, and glob patterns for endpoints
- **Time windows** - Restrict access to specific hours or days
- **IP filtering** - Single IPs, CIDR ranges, or lists
- **Priority ordering** - Control rule evaluation order via priority field

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
axum-acl = "0.1"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use axum::{Router, routing::get};
use axum_acl::{AclLayer, AclTable, AclRule, AclAction, EndpointPattern};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Define ACL rules
    let acl_table = AclTable::builder()
        .default_action(AclAction::Deny)
        // Admins can access everything
        .add_rule(
            AclRule::new("admin")
                .endpoint(EndpointPattern::any())
                .action(AclAction::Allow)
        )
        // Users can access /api/**
        .add_rule(
            AclRule::new("user")
                .endpoint(EndpointPattern::prefix("/api/"))
                .action(AclAction::Allow)
        )
        // Public endpoints
        .add_rule(
            AclRule::any_role()
                .endpoint(EndpointPattern::prefix("/public/"))
                .action(AclAction::Allow)
        )
        .build();

    let app = Router::new()
        .route("/public/info", get(|| async { "Public" }))
        .route("/api/users", get(|| async { "API" }))
        .route("/admin/dashboard", get(|| async { "Admin" }))
        .layer(AclLayer::new(acl_table));

    // Important: Use into_make_service_with_connect_info for IP extraction
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>()
    ).await.unwrap();
}
```

Test it:

```bash
# Public endpoint (allowed)
curl http://localhost:3000/public/info

# API as user (allowed)
curl -H "X-Role: user" http://localhost:3000/api/users

# Admin as user (denied)
curl -H "X-Role: user" http://localhost:3000/admin/dashboard

# Admin as admin (allowed)
curl -H "X-Role: admin" http://localhost:3000/admin/dashboard
```

## TOML Configuration

Define rules in TOML format - either embedded at compile-time or loaded from a file at runtime.

### Compile-time Embedded Config

```rust
use axum_acl::AclTable;

// Embed configuration at compile time
const CONFIG: &str = include_str!("../acl.toml");

fn main() {
    let table = AclTable::from_toml(CONFIG).unwrap();
}
```

### Runtime File Loading

```rust
use axum_acl::AclTable;

fn main() {
    let table = AclTable::from_toml_file("config/acl.toml").unwrap();
}
```

### TOML Format

```toml
[settings]
default_action = "deny"

# Rules are sorted by priority (lower = higher priority)
[[rules]]
role = "admin"
endpoint = "*"
action = "allow"
priority = 10
description = "Admins have full access"

[[rules]]
role = "user"
endpoint = "/api/**"
time = { start = 9, end = 17, days = [0,1,2,3,4] }  # Mon-Fri 9-5 UTC
action = "allow"
priority = 100

[[rules]]
role = "*"
endpoint = "/admin/**"
action = { type = "error", code = 403, message = "Admin access required" }
priority = 20

[[rules]]
role = "anonymous"
endpoint = "/dashboard/**"
action = { type = "reroute", target = "/login", preserve_path = true }
priority = 30

[[rules]]
role = "*"
endpoint = "/internal/**"
ip = "127.0.0.1"
action = "allow"
priority = 50

[[rules]]
role = "*"
endpoint = "/public/**"
action = "allow"
priority = 200
```

### Action Types

| Action | TOML Syntax | Description |
|--------|-------------|-------------|
| Allow | `"allow"` | Allow the request |
| Deny | `"deny"` or `"block"` | Return 403 Forbidden |
| Error | `{ type = "error", code = 418, message = "..." }` | Custom HTTP error |
| Reroute | `{ type = "reroute", target = "/path" }` | Redirect to another path |
| Log | `{ type = "log", level = "warn", message = "..." }` | Log and allow |

## Rule Structure

Each rule is a tuple of:

| Field | Description | Default |
|-------|-------------|---------|
| `role` | Role name or `*` for any | Required |
| `endpoint` | Path pattern to match | Any |
| `time` | Time window when rule is active | Any time |
| `ip` | Client IP(s) to match | Any IP |
| `action` | Allow or Deny | Allow |

Rules are evaluated **in order**. The first matching rule wins.

## Endpoint Patterns

```rust
use axum_acl::EndpointPattern;

// Match any path
EndpointPattern::any()

// Exact match
EndpointPattern::exact("/api/users")        // Only /api/users

// Prefix match
EndpointPattern::prefix("/api/")            // /api/*, /api/users, etc.

// Glob patterns
EndpointPattern::glob("/api/*/users")       // /api/v1/users, /api/v2/users
EndpointPattern::glob("/api/**/export")     // /api/export, /api/v1/data/export

// Parse from string
EndpointPattern::parse("/api/")             // Prefix (ends with /)
EndpointPattern::parse("/api/users")        // Exact
EndpointPattern::parse("/api/**")           // Glob
EndpointPattern::parse("*")                 // Any
```

## Time Windows

```rust
use axum_acl::TimeWindow;

// Any time (default)
TimeWindow::any()

// Specific hours (UTC)
TimeWindow::hours(9, 17)                    // 9 AM - 5 PM UTC

// Specific hours on specific days
TimeWindow::hours_on_days(
    9, 17,                                  // 9 AM - 5 PM
    vec![0, 1, 2, 3, 4]                     // Mon-Fri (0=Monday)
)
```

## IP Matching

```rust
use axum_acl::IpMatcher;

// Any IP (default)
IpMatcher::any()

// Single IP
IpMatcher::single("192.168.1.1".parse().unwrap())

// CIDR range
IpMatcher::cidr("10.0.0.0/8".parse().unwrap())

// Parse from string
IpMatcher::parse("*").unwrap()              // Any
IpMatcher::parse("192.168.1.1").unwrap()    // Single
IpMatcher::parse("192.168.0.0/16").unwrap() // CIDR
```

## Role Extraction

By default, roles are extracted from the `X-Role` header.

### Using a Different Header

```rust
use axum_acl::{AclLayer, AclTable, HeaderRoleExtractor};

let layer = AclLayer::new(acl_table)
    .with_extractor(HeaderRoleExtractor::new("X-User-Role"));
```

### With Default Role for Missing Header

```rust
use axum_acl::HeaderRoleExtractor;

let extractor = HeaderRoleExtractor::new("X-Role")
    .with_default_role("guest");
```

### From Request Extensions

When using authentication middleware that sets user info:

```rust
use axum_acl::{RoleExtractor, RoleExtractionResult};

#[derive(Clone)]
struct User {
    role: String,
}

struct UserRoleExtractor;

impl<B> RoleExtractor<B> for UserRoleExtractor {
    fn extract_role(&self, request: &http::Request<B>) -> RoleExtractionResult {
        match request.extensions().get::<User>() {
            Some(user) => RoleExtractionResult::Role(user.role.clone()),
            None => RoleExtractionResult::Anonymous,
        }
    }
}

// Use it
let layer = AclLayer::new(acl_table)
    .with_extractor(UserRoleExtractor);
```

## Complete Example with All Features

```rust
use axum::{Router, routing::get};
use axum_acl::{
    AclLayer, AclTable, AclRule, AclAction,
    EndpointPattern, TimeWindow, IpMatcher,
    JsonDeniedHandler,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let acl_table = AclTable::builder()
        .default_action(AclAction::Deny)

        // Admins: full access
        .add_rule(
            AclRule::new("admin")
                .endpoint(EndpointPattern::any())
                .action(AclAction::Allow)
                .description("Admin full access")
        )

        // Internal endpoints: localhost only
        .add_rule(
            AclRule::any_role()
                .endpoint(EndpointPattern::prefix("/internal/"))
                .ip(IpMatcher::parse("127.0.0.1").unwrap())
                .action(AclAction::Allow)
                .description("Internal - localhost only")
        )

        // Users: API access during business hours
        .add_rule(
            AclRule::new("user")
                .endpoint(EndpointPattern::prefix("/api/"))
                .time(TimeWindow::hours_on_days(9, 17, vec![0,1,2,3,4]))
                .action(AclAction::Allow)
                .description("User API access - business hours")
        )

        // Public endpoints
        .add_rule(
            AclRule::any_role()
                .endpoint(EndpointPattern::prefix("/public/"))
                .action(AclAction::Allow)
                .description("Public access")
        )

        .build();

    let app = Router::new()
        .route("/public/health", get(|| async { "OK" }))
        .route("/api/data", get(|| async { "Data" }))
        .route("/internal/metrics", get(|| async { "Metrics" }))
        .route("/admin/config", get(|| async { "Config" }))
        .layer(
            AclLayer::new(acl_table)
                .with_denied_handler(JsonDeniedHandler::new())
                .with_anonymous_role("guest")
                .with_forwarded_ip_header("X-Forwarded-For")
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>()
    ).await.unwrap();
}
```

## Behind a Reverse Proxy

When behind nginx, traefik, or similar:

```rust
let layer = AclLayer::new(acl_table)
    .with_forwarded_ip_header("X-Forwarded-For");
```

## Custom Denied Response

```rust
use axum_acl::{AccessDeniedHandler, AccessDenied, JsonDeniedHandler};
use axum::response::{Response, IntoResponse};
use http::StatusCode;

// Use built-in JSON handler
let layer = AclLayer::new(acl_table)
    .with_denied_handler(JsonDeniedHandler::new());

// Or with details (careful in production!)
let layer = AclLayer::new(acl_table)
    .with_denied_handler(JsonDeniedHandler::new().with_details());

// Or custom handler
struct MyHandler;

impl AccessDeniedHandler for MyHandler {
    fn handle(&self, denied: &AccessDenied) -> Response {
        (
            StatusCode::FORBIDDEN,
            format!("Access denied for {}", denied.role)
        ).into_response()
    }
}
```

## Dynamic Rules from Database

```rust
use axum_acl::{AclRuleProvider, AclRule, AclTable, AclAction};

struct DbRuleProvider { /* db pool */ }

impl AclRuleProvider for DbRuleProvider {
    type Error = std::io::Error;

    fn load_rules(&self) -> Result<Vec<AclRule>, Self::Error> {
        // Query your database
        // SELECT role, endpoint, time_start, time_end, ip_pattern, action FROM acl_rules
        Ok(vec![])
    }
}

// Usage
fn build_table(provider: &DbRuleProvider) -> AclTable {
    let rules = provider.load_rules().unwrap();
    AclTable::builder()
        .default_action(AclAction::Deny)
        .add_rules(rules)
        .build()
}
```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `AclTable` | Container for ACL rules |
| `AclRule` | A single access control rule |
| `AclAction` | Allow or Deny |
| `EndpointPattern` | Path matching pattern |
| `TimeWindow` | Time-based restriction |
| `IpMatcher` | IP address matching |

### Middleware

| Type | Description |
|------|-------------|
| `AclLayer` | Tower layer for adding ACL to router |
| `AclMiddleware` | The middleware service |
| `AclConfig` | Middleware configuration |

### Role Extraction

| Type | Description |
|------|-------------|
| `RoleExtractor` | Trait for extracting roles |
| `HeaderRoleExtractor` | Extract from HTTP header |
| `ExtensionRoleExtractor` | Extract from request extension |
| `FixedRoleExtractor` | Always returns same role |
| `ChainedRoleExtractor` | Try multiple extractors |

### Error Handling

| Type | Description |
|------|-------------|
| `AccessDenied` | Access denied error |
| `AccessDeniedHandler` | Trait for custom responses |
| `DefaultDeniedHandler` | Plain text 403 response |
| `JsonDeniedHandler` | JSON 403 response |

## Examples

Run the examples:

```bash
# Basic usage with builder API
cargo run --example basic

# Custom role extraction from request extensions
cargo run --example custom_extractor

# TOML configuration (compile-time and runtime)
cargo run --example toml_config
```

## License

MIT OR Apache-2.0
