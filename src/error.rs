//! Error types for the ACL middleware.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use std::fmt;

/// Error returned when access is denied by the ACL middleware.
#[derive(Debug, Clone)]
pub struct AccessDenied {
    /// The roles bitmask that was denied.
    pub roles: u32,
    /// The path that was requested.
    pub path: String,
    /// The user/session ID.
    pub id: String,
    /// Optional custom message.
    pub message: Option<String>,
}

impl AccessDenied {
    /// Create a new access denied error with roles bitmask.
    pub fn new_with_roles(roles: u32, path: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            roles,
            path: path.into(),
            id: id.into(),
            message: None,
        }
    }

    /// Create a new access denied error (legacy, uses 0 for roles).
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            roles: 0,
            path: path.into(),
            id: "*".to_string(),
            message: None,
        }
    }

    /// Add a custom message to the error.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

impl fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(msg) => write!(f, "{}", msg),
            None => write!(f, "Access denied for roles 0x{:X} to path '{}'", self.roles, self.path),
        }
    }
}

impl std::error::Error for AccessDenied {}

impl IntoResponse for AccessDenied {
    fn into_response(self) -> Response {
        let body = match &self.message {
            Some(msg) => msg.clone(),
            None => "Access denied".to_string(),
        };
        (StatusCode::FORBIDDEN, body).into_response()
    }
}

/// Error type for ACL operations.
#[derive(Debug, thiserror::Error)]
pub enum AclError {
    /// Access was denied by an ACL rule.
    #[error("Access denied: {0}")]
    AccessDenied(#[from] AccessDenied),

    /// Failed to extract the client IP address.
    #[error("Failed to extract client IP address")]
    IpExtractionFailed,

    /// Failed to extract role from the request.
    #[error("Failed to extract role: {0}")]
    RoleExtractionFailed(String),

    /// Invalid rule configuration.
    #[error("Invalid rule configuration: {0}")]
    InvalidRule(String),

    /// Rule provider error.
    #[error("Rule provider error: {0}")]
    ProviderError(String),
}

impl IntoResponse for AclError {
    fn into_response(self) -> Response {
        match self {
            Self::AccessDenied(denied) => denied.into_response(),
            Self::IpExtractionFailed => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to determine client IP").into_response()
            }
            Self::RoleExtractionFailed(_) => {
                (StatusCode::UNAUTHORIZED, "Authentication required").into_response()
            }
            Self::InvalidRule(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Configuration error: {}", msg))
                    .into_response()
            }
            Self::ProviderError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("ACL error: {}", msg)).into_response()
            }
        }
    }
}

/// Custom response handler for access denied errors.
///
/// Implement this trait to customize the response when access is denied.
///
/// # Example
/// ```
/// use axum_acl::{AccessDeniedHandler, AccessDenied};
/// use axum::response::{Response, IntoResponse};
/// use http::StatusCode;
///
/// struct JsonDeniedHandler;
///
/// impl AccessDeniedHandler for JsonDeniedHandler {
///     fn handle(&self, denied: &AccessDenied) -> Response {
///         let body = serde_json::json!({
///             "error": "access_denied",
///             "message": denied.to_string(),
///         });
///         (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
///     }
/// }
/// ```
pub trait AccessDeniedHandler: Send + Sync {
    /// Handle an access denied error and return a response.
    fn handle(&self, denied: &AccessDenied) -> Response;
}

/// Default handler that returns a plain text 403 response.
#[derive(Debug, Clone, Default)]
pub struct DefaultDeniedHandler;

impl AccessDeniedHandler for DefaultDeniedHandler {
    fn handle(&self, denied: &AccessDenied) -> Response {
        denied.clone().into_response()
    }
}

/// Handler that returns a JSON error response.
#[derive(Debug, Clone, Default)]
pub struct JsonDeniedHandler {
    include_details: bool,
}

impl JsonDeniedHandler {
    /// Create a new JSON denied handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Include detailed information in the response.
    ///
    /// When enabled, includes the role and path in the error response.
    /// This may be a security risk in production.
    pub fn with_details(mut self) -> Self {
        self.include_details = true;
        self
    }
}

impl AccessDeniedHandler for JsonDeniedHandler {
    fn handle(&self, denied: &AccessDenied) -> Response {
        use axum::Json;

        let body = if self.include_details {
            serde_json::json!({
                "error": "access_denied",
                "message": denied.message.as_deref().unwrap_or("Access denied"),
                "roles": format!("0x{:X}", denied.roles),
                "id": denied.id,
                "path": denied.path,
            })
        } else {
            serde_json::json!({
                "error": "access_denied",
                "message": denied.message.as_deref().unwrap_or("Access denied"),
            })
        };

        (StatusCode::FORBIDDEN, Json(body)).into_response()
    }
}
