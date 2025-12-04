# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/greenpdx/axum-acl/releases/tag/v0.1.0
