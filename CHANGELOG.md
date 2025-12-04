# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-04

### Added

- **ROLE_ANONYMOUS constant** (`0x80000000`) - Reserved bit 31 for anonymous/public access
  - Solves the problem where `roles = 0` could never match any rule
  - Use with `HeaderRoleExtractor::with_default_roles(ROLE_ANONYMOUS)`
  - Exported in prelude
- **`with_id_extractor()` method** on `AclLayer` - Configure custom ID extraction
  - Enables ownership-based access control (e.g., users can only access their own resources)
  - Mirrors the existing `with_role_extractor()` pattern
- **`with_role_extractor()` method** - Renamed from `with_extractor()` for clarity

### Changed

- `AclLayer` now has two type parameters: `AclLayer<E, I>` (role extractor, ID extractor)
- `AclConfig` and `AclMiddleware` updated to match
- Default ID extractor changed from header-based to `HeaderIdExtractor::new("X-User-Id")`
- Renamed `extractor` field to `role_extractor` in `AclConfig`

### Deprecated

- `with_extractor()` - Use `with_role_extractor()` instead

### Removed

- `with_id_header()` method - Use `with_id_extractor(HeaderIdExtractor::new("header-name"))` instead
- `id_header` field from `AclConfig` - Replaced by `id_extractor`

## [0.1.0] - 2024-12-04

### Added

- Initial release of axum-acl middleware for axum 0.8
- **5-tuple rule matching**: endpoint, role, id, ip, time
- **AclTable** with HashMap for O(1) exact endpoint lookup
- **AclRuleFilter** for flexible rule matching
- **Role extraction** as u32 bitmask (up to 32 roles)
  - `HeaderRoleExtractor` - from HTTP header
  - `ExtensionRoleExtractor` - from request extension
  - `FixedRoleExtractor` - constant value
  - `ChainedRoleExtractor` - try multiple extractors
- **ID extraction** for path parameter matching
  - `HeaderIdExtractor` - from HTTP header
  - `ExtensionIdExtractor` - from request extension
  - `FixedIdExtractor` - constant value
- **Path parameter matching** with `{id}` for ownership-based access
- **Endpoint patterns**: Exact, Prefix, Glob, Any
- **Time windows**: business hours, specific days
- **IP matching**: single IP, CIDR ranges, lists
- **Actions**: Allow, Deny, Error (custom code), Reroute, Log
- **TOML configuration** support (compile-time or startup loading)
- **Custom denied handlers**: DefaultDeniedHandler, JsonDeniedHandler
- **AclRuleProvider** trait for dynamic rule loading
- Examples: basic, custom_extractor, toml_config

### Security

- No unsafe code (`#![forbid(unsafe_code)]`)

[0.2.0]: https://github.com/greenpdx/axum-acl/releases/tag/v0.2.0
[0.1.0]: https://github.com/greenpdx/axum-acl/releases/tag/v0.1.0
