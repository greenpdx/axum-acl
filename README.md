# axum-acl

Flexible Access Control List (ACL) middleware for [axum](https://docs.rs/axum) 0.8.

## Features

- **TOML Configuration** - Define rules in config files (compile-time or startup)
- **Table-based rules** - No hardcoded rules; all access control is configured at startup
- **Five-tuple matching** - Rules match on Endpoint + Role + ID + IP + Time
- **Extended actions** - Allow, Deny, Error (custom codes), Reroute, Log
- **Flexible extractors** - Extract roles (u32 bitmask) and IDs from headers, extensions, or custom sources
- **Path parameters** - Match `{id}` in paths against user ID for ownership-based access
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
use axum_acl::{AclLayer, AclTable, AclRuleFilter, AclAction};
use std::net::SocketAddr;

// Define role bits
const ROLE_ADMIN: u32 = 0b001;
const ROLE_USER: u32 = 0b010;

#[tokio::main]
async fn main() {
    // Define ACL rules
    let acl_table = AclTable::builder()
        .default_action(AclAction::Deny)
        // Admins can access everything
        .add_any(AclRuleFilter::new()
            .role_mask(ROLE_ADMIN)
            .action(AclAction::Allow))
        // Users can access /api/**
        .add_prefix("/api/", AclRuleFilter::new()
            .role_mask(ROLE_USER)
            .action(AclAction::Allow))
        // Public endpoints (any role)
        .add_prefix("/public/", AclRuleFilter::new()
            .role_mask(u32::MAX)
            .action(AclAction::Allow))
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

# API as user (role_mask=2, allowed)
curl -H "X-Roles: 2" http://localhost:3000/api/users

# Admin as user (denied)
curl -H "X-Roles: 2" http://localhost:3000/admin/dashboard

# Admin as admin (role_mask=1, allowed)
curl -H "X-Roles: 1" http://localhost:3000/admin/dashboard
```

## TOML Configuration

Define rules in TOML format - either embedded at compile-time or loaded from a file at startup.

### Compile-time Embedded Config

```rust
use axum_acl::AclTable;

// Embed configuration at compile time
const CONFIG: &str = include_str!("../acl.toml");

fn main() {
    let table = AclTable::from_toml(CONFIG).unwrap();
}
```

### Startup File Loading

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
endpoint = "*"
role_mask = 1              # Admin role bit
action = "allow"
priority = 10
description = "Admins have full access"

[[rules]]
endpoint = "/api/**"
role_mask = 2              # User role bit
time = { start = 9, end = 17, days = [0,1,2,3,4] }  # Mon-Fri 9-5 UTC
action = "allow"
priority = 100

[[rules]]
endpoint = "/admin/**"
role_mask = "*"            # Any role
action = { type = "error", code = 403, message = "Admin access required" }
priority = 20

[[rules]]
endpoint = "/boat/{id}/**"
role_mask = 2
id = "{id}"                # Match path {id} against user ID
action = "allow"
priority = 50

[[rules]]
endpoint = "/internal/**"
role_mask = "*"
ip = "127.0.0.1"
action = "allow"
priority = 50

[[rules]]
endpoint = "/public/**"
role_mask = "*"
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

## Rule Structure (5-Tuple)

Each rule matches on five dimensions:

| Field | Description | Default |
|-------|-------------|---------|
| `endpoint` | Path pattern to match | Any |
| `role_mask` | u32 bitmask or `*` for any | Required |
| `id` | User ID match: exact, `*`, or `{id}` for path param | `*` (any) |
| `ip` | Client IP(s) to match | Any IP |
| `time` | Time window when rule is active | Any time |
| `action` | Allow, Deny, Error, Reroute | Allow |

Rules are evaluated in order. The first matching rule wins.

### Matching Logic

```
endpoint: HashMap lookup (O(1) for exact) or pattern match
role:     (rule.role_mask & request.roles) != 0
id:       rule.id == "*" OR rule.id == request.id OR rule.id == "{id}" (path param)
ip:       CIDR match (ip & mask == network)
time:     start <= now <= end AND day in days
```

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

// Path parameters (matched against user ID)
EndpointPattern::glob("/boat/{id}/details") // {id} matches user's ID

// Parse from string
EndpointPattern::parse("/api/")             // Prefix (ends with /)
EndpointPattern::parse("/api/users")        // Exact
EndpointPattern::parse("/api/**")           // Glob
EndpointPattern::parse("*")                 // Any
```

## Role Extraction

Roles are extracted as a `u32` bitmask, allowing up to 32 roles per user.

### Default: Header as Bitmask

```rust
// X-Roles header parsed as decimal or hex
// X-Roles: 5      -> 0b101 (roles 0 and 2)
// X-Roles: 0x1F   -> 0b11111 (roles 0-4)
```

### Custom Header

```rust
use axum_acl::{AclLayer, AclTable, HeaderRoleExtractor};

let layer = AclLayer::new(acl_table)
    .with_extractor(HeaderRoleExtractor::new("X-User-Roles"));
```

### With Default Roles for Anonymous Users

```rust
use axum_acl::HeaderRoleExtractor;

const ROLE_GUEST: u32 = 0b100;

let extractor = HeaderRoleExtractor::new("X-Roles")
    .with_default_roles(ROLE_GUEST);
```

### Custom Role Translation

Translate your role scheme (strings, enums, etc.) to u32 bitmask:

```rust
use axum_acl::{RoleExtractor, RoleExtractionResult};
use http::Request;

// Your role definitions
const ROLE_ADMIN: u32 = 1 << 0;
const ROLE_USER: u32 = 1 << 1;
const ROLE_GUEST: u32 = 1 << 2;

struct JwtRoleExtractor;

impl<B> RoleExtractor<B> for JwtRoleExtractor {
    fn extract_roles(&self, request: &Request<B>) -> RoleExtractionResult {
        // Decode JWT, lookup database, etc.
        if let Some(auth) = request.headers().get("Authorization") {
            // Parse and translate to bitmask
            let roles = ROLE_USER | ROLE_GUEST;
            return RoleExtractionResult::Roles(roles);
        }
        RoleExtractionResult::Anonymous
    }
}

let layer = AclLayer::new(acl_table)
    .with_extractor(JwtRoleExtractor);
```

## ID Extraction

User IDs are extracted as strings for matching against `{id}` path parameters.

### Header-based ID

```rust
use axum_acl::HeaderIdExtractor;

let layer = AclLayer::new(acl_table)
    .with_id_extractor(HeaderIdExtractor::new("X-User-Id"));
```

### Custom ID Extraction

```rust
use axum_acl::{IdExtractor, IdExtractionResult};
use http::Request;

struct JwtIdExtractor;

impl<B> IdExtractor<B> for JwtIdExtractor {
    fn extract_id(&self, request: &Request<B>) -> IdExtractionResult {
        // Extract user ID from JWT, session, etc.
        if let Some(auth) = request.headers().get("Authorization") {
            return IdExtractionResult::Id("user-123".to_string());
        }
        IdExtractionResult::Anonymous
    }
}
```

### Path Parameter Matching

Match `{id}` in paths against the user's ID for ownership-based access:

```rust
use axum_acl::{AclTable, AclRuleFilter, AclAction, EndpointPattern};

const ROLE_USER: u32 = 0b010;

let table = AclTable::builder()
    .default_action(AclAction::Deny)
    // Users can only access their own boat data
    .add_pattern(
        EndpointPattern::glob("/api/boat/{id}/**"),
        AclRuleFilter::new()
            .role_mask(ROLE_USER)
            .id("{id}")  // Path {id} must match user's ID
            .action(AclAction::Allow)
    )
    .build();

// User with id="boat-123":
//   /api/boat/boat-123/details -> ALLOWED
//   /api/boat/boat-456/details -> DENIED
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

// Or custom handler
struct MyHandler;

impl AccessDeniedHandler for MyHandler {
    fn handle(&self, denied: &AccessDenied) -> Response {
        (
            StatusCode::FORBIDDEN,
            format!("Access denied: roles={}", denied.roles)
        ).into_response()
    }
}
```

## Dynamic Rules from Database

```rust
use axum_acl::{AclRuleProvider, RuleEntry, AclRuleFilter, AclTable, AclAction, EndpointPattern};

struct DbRuleProvider { /* db pool */ }

impl AclRuleProvider for DbRuleProvider {
    type Error = std::io::Error;

    fn load_rules(&self) -> Result<Vec<RuleEntry>, Self::Error> {
        // Query your database
        Ok(vec![
            RuleEntry::any(AclRuleFilter::new()
                .role_mask(0b001)
                .action(AclAction::Allow))
        ])
    }
}

// Usage at startup
fn build_table(provider: &DbRuleProvider) -> AclTable {
    let rules = provider.load_rules().unwrap();
    let mut builder = AclTable::builder().default_action(AclAction::Deny);
    for entry in rules {
        builder = builder.add_pattern(entry.pattern, entry.filter);
    }
    builder.build()
}
```

## Endpoint Parser Tool

Discover endpoints and their ACL rules from your codebase:

```bash
# Build the parser
cargo build --bin endpoint_parser

# Parse endpoints (table format)
cargo run --bin endpoint_parser -- examples/

# Output as CSV
cargo run --bin endpoint_parser -- --csv examples/ > endpoints.csv

# Output as TOML config
cargo run --bin endpoint_parser -- --toml examples/ > acl.toml

# Use AST-based parsing (more accurate, requires feature)
cargo run --bin endpoint_parser --features ast-parser -- --ast examples/
```

### CLI Arguments

```
Usage: endpoint_parser [OPTIONS] <directory>

Options:
  --text    Use text-based parsing (default, fast)
  --ast     Use AST-based parsing (requires --features ast-parser)

  --table   Output as formatted table (default)
  --csv     Output as CSV
  --toml    Output as TOML config file

  --help    Show help message
```

### Output Format

```
ENDPOINT                       METHOD         ROLE,   ID,           IP,     TIME | ACTION  HANDLER              LOCATION
------------------------------------------------------------------------------------------------------------------------
/admin/dashboard               GET      ROLE_ADMIN,    *,            *,        * | allow   admin_dashboard      basic.rs:109
/api/users                     GET       ROLE_USER,    *,            *,        * | allow   api_users            basic.rs:106
/public/info                   GET               *,    *,            *,        * | allow   public_info          basic.rs:103
```

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `AclTable` | Container for ACL rules (HashMap + patterns) |
| `AclRuleFilter` | Filter for 5-tuple matching (role, id, ip, time, action) |
| `AclAction` | Allow, Deny, Error, Reroute, Log |
| `EndpointPattern` | Path matching: Exact, Prefix, Glob, Any |
| `RequestContext` | Request metadata: roles (u32), ip, id |
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
| `RoleExtractor` | Trait for extracting roles (u32 bitmask) |
| `HeaderRoleExtractor` | Extract from HTTP header |
| `ExtensionRoleExtractor` | Extract from request extension |
| `FixedRoleExtractor` | Always returns same roles |
| `ChainedRoleExtractor` | Try multiple extractors |

### ID Extraction

| Type | Description |
|------|-------------|
| `IdExtractor` | Trait for extracting user ID (String) |
| `HeaderIdExtractor` | Extract from HTTP header |
| `ExtensionIdExtractor` | Extract from request extension |
| `FixedIdExtractor` | Always returns same ID |

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

# TOML configuration (compile-time and startup)
cargo run --example toml_config
```

## License

MIT OR Apache-2.0
