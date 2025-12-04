//! ACL middleware implementation for axum.
//!
//! This module provides the [`AclLayer`] and [`AclMiddleware`] types that
//! integrate with axum's middleware system.

use crate::error::{AccessDenied, AccessDeniedHandler, DefaultDeniedHandler};
use crate::extractor::{HeaderRoleExtractor, RoleExtractor};
use crate::rule::{AclAction, RequestContext};
use crate::table::AclTable;

use axum::extract::ConnectInfo;
use axum::response::Response;
use futures_util::future::BoxFuture;
use http::{Request, StatusCode};
use http_body::Body;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Configuration for the ACL middleware.
pub struct AclConfig<E> {
    /// The ACL table containing the rules.
    pub table: Arc<AclTable>,
    /// The role extractor.
    pub extractor: Arc<E>,
    /// The handler for access denied responses.
    pub denied_handler: Arc<dyn AccessDeniedHandler>,
    /// The roles bitmask to use for anonymous users.
    pub anonymous_roles: u32,
    /// Header to check for forwarded IP (e.g., X-Forwarded-For).
    pub forwarded_ip_header: Option<String>,
    /// Header to extract the user/session ID from.
    pub id_header: Option<String>,
    /// Default ID when header is missing.
    pub default_id: String,
}

// Manual Clone impl to avoid requiring E: Clone (since E is behind Arc)
impl<E> Clone for AclConfig<E> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            extractor: self.extractor.clone(),
            denied_handler: self.denied_handler.clone(),
            anonymous_roles: self.anonymous_roles,
            forwarded_ip_header: self.forwarded_ip_header.clone(),
            id_header: self.id_header.clone(),
            default_id: self.default_id.clone(),
        }
    }
}

/// A Tower layer that adds ACL middleware to a service.
///
/// # Example
/// ```no_run
/// use axum::{Router, routing::get};
/// use axum_acl::{AclLayer, AclTable, AclRuleFilter, AclAction};
/// use std::net::SocketAddr;
///
/// async fn handler() -> &'static str {
///     "Hello, World!"
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let acl_table = AclTable::builder()
///         .default_action(AclAction::Deny)
///         .add_any(AclRuleFilter::new()
///             .role_mask(0b1)  // admin role
///             .action(AclAction::Allow))
///         .build();
///
///     let app = Router::new()
///         .route("/", get(handler))
///         .layer(AclLayer::new(acl_table));
///
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
///     axum::serve(
///         listener,
///         app.into_make_service_with_connect_info::<SocketAddr>()
///     ).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct AclLayer<E> {
    config: AclConfig<E>,
}

impl AclLayer<HeaderRoleExtractor> {
    /// Create a new ACL layer with the given table.
    ///
    /// Uses the default header role extractor (`X-Roles` header) and
    /// default denied handler (plain text 403).
    pub fn new(table: AclTable) -> Self {
        Self {
            config: AclConfig {
                table: Arc::new(table),
                extractor: Arc::new(HeaderRoleExtractor::new("X-Roles")),
                denied_handler: Arc::new(DefaultDeniedHandler),
                anonymous_roles: 0,
                forwarded_ip_header: None,
                id_header: Some("X-Request-ID".to_string()),
                default_id: "*".to_string(),
            },
        }
    }
}

impl<E> AclLayer<E> {
    /// Create a new ACL layer with a custom role extractor.
    pub fn with_extractor<E2>(self, extractor: E2) -> AclLayer<E2> {
        AclLayer {
            config: AclConfig {
                table: self.config.table,
                extractor: Arc::new(extractor),
                denied_handler: self.config.denied_handler,
                anonymous_roles: self.config.anonymous_roles,
                forwarded_ip_header: self.config.forwarded_ip_header,
                id_header: self.config.id_header,
                default_id: self.config.default_id,
            },
        }
    }

    /// Set a custom access denied handler.
    pub fn with_denied_handler(mut self, handler: impl AccessDeniedHandler + 'static) -> Self {
        self.config.denied_handler = Arc::new(handler);
        self
    }

    /// Set the roles bitmask to use for anonymous/unauthenticated users.
    pub fn with_anonymous_roles(mut self, roles: u32) -> Self {
        self.config.anonymous_roles = roles;
        self
    }

    /// Set a header to extract the client IP from (e.g., X-Forwarded-For).
    ///
    /// When behind a reverse proxy, the client IP may be in a header.
    /// This setting tells the middleware which header to check.
    pub fn with_forwarded_ip_header(mut self, header: impl Into<String>) -> Self {
        self.config.forwarded_ip_header = Some(header.into());
        self
    }

    /// Set a header to extract the user/session ID from.
    pub fn with_id_header(mut self, header: impl Into<String>) -> Self {
        self.config.id_header = Some(header.into());
        self
    }

    /// Set the default ID to use when the ID header is missing.
    pub fn with_default_id(mut self, id: impl Into<String>) -> Self {
        self.config.default_id = id.into();
        self
    }

    /// Get a reference to the ACL table.
    pub fn table(&self) -> &AclTable {
        &self.config.table
    }
}

impl<S, E: Clone> Layer<S> for AclLayer<E> {
    type Service = AclMiddleware<S, E>;

    fn layer(&self, inner: S) -> Self::Service {
        AclMiddleware {
            inner,
            config: self.config.clone(),
        }
    }
}

/// The ACL middleware service.
#[derive(Clone)]
pub struct AclMiddleware<S, E> {
    inner: S,
    config: AclConfig<E>,
}

impl<S, E, ReqBody, ResBody> Service<Request<ReqBody>> for AclMiddleware<S, E>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    E: RoleExtractor<ReqBody> + 'static,
    ReqBody: Body + Send + 'static,
    ResBody: Body + Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();

        // Extract roles bitmask synchronously before entering the async block
        let role_result = config.extractor.extract_roles(&request);
        let roles = role_result.roles_or(config.anonymous_roles);

        // Extract client IP synchronously
        let client_ip = extract_client_ip(&request, config.forwarded_ip_header.as_deref());

        // Extract user/session ID
        let id = extract_id(&request, config.id_header.as_deref(), &config.default_id);

        // Get request path
        let path = request.uri().path().to_string();

        Box::pin(async move {
            let Some(client_ip) = client_ip else {
                tracing::warn!("Failed to extract client IP address");
                let response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(ResBody::default())
                    .unwrap();
                return Ok(response);
            };

            // Build request context
            let ctx = RequestContext::new(roles, client_ip, &id);

            // Evaluate ACL
            let action = config.table.evaluate(&path, &ctx);

            match action {
                AclAction::Allow => {
                    tracing::trace!(
                        roles = roles,
                        id = %id,
                        path = %path,
                        ip = %client_ip,
                        "ACL allowed request"
                    );
                    inner.call(request).await
                }
                AclAction::Deny => {
                    tracing::info!(
                        roles = roles,
                        id = %id,
                        path = %path,
                        ip = %client_ip,
                        "ACL denied request"
                    );

                    let denied = AccessDenied::new_with_roles(roles, path, id);
                    let response = config.denied_handler.handle(&denied);

                    // Convert the response body type
                    let (parts, _body) = response.into_parts();
                    let response = Response::from_parts(parts, ResBody::default());

                    Ok(response)
                }
                AclAction::Error { code, ref message } => {
                    tracing::info!(
                        roles = roles,
                        id = %id,
                        path = %path,
                        ip = %client_ip,
                        code = code,
                        message = ?message,
                        "ACL returned error"
                    );

                    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::FORBIDDEN);

                    let response = Response::builder()
                        .status(status)
                        .header("content-type", "text/plain")
                        .body(ResBody::default())
                        .unwrap();

                    Ok(response)
                }
                AclAction::Reroute { ref target, preserve_path } => {
                    tracing::info!(
                        roles = roles,
                        id = %id,
                        path = %path,
                        ip = %client_ip,
                        target = %target,
                        "ACL rerouting request"
                    );

                    // For reroute, we return a redirect response
                    let mut response = Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header("location", target.as_str())
                        .body(ResBody::default())
                        .unwrap();

                    if preserve_path {
                        response.headers_mut().insert(
                            "x-original-path",
                            path.parse().unwrap_or_else(|_| "/".parse().unwrap()),
                        );
                    }

                    Ok(response)
                }
                AclAction::RateLimit { max_requests, window_secs } => {
                    // Rate limiting requires external state management
                    // For now, just log and allow - users should implement their own rate limiter
                    tracing::warn!(
                        roles = roles,
                        id = %id,
                        path = %path,
                        ip = %client_ip,
                        max_requests = max_requests,
                        window_secs = window_secs,
                        "ACL rate limit action - not implemented, allowing request"
                    );
                    inner.call(request).await
                }
                AclAction::Log { ref level, ref message } => {
                    let msg = message.clone().unwrap_or_else(|| {
                        format!("ACL log: roles={}, id={}, path={}, ip={}", roles, id, path, client_ip)
                    });

                    match level.as_str() {
                        "trace" => tracing::trace!("{}", msg),
                        "debug" => tracing::debug!("{}", msg),
                        "warn" => tracing::warn!("{}", msg),
                        "error" => tracing::error!("{}", msg),
                        _ => tracing::info!("{}", msg),
                    }

                    // Log action allows the request to proceed
                    inner.call(request).await
                }
            }
        })
    }
}

/// Extract the client IP address from the request.
fn extract_client_ip<B>(request: &Request<B>, forwarded_header: Option<&str>) -> Option<IpAddr> {
    // First, check the forwarded header if configured
    if let Some(header_name) = forwarded_header {
        if let Some(value) = request.headers().get(header_name) {
            if let Ok(s) = value.to_str() {
                // X-Forwarded-For format: client, proxy1, proxy2, ...
                // Take the first (leftmost) IP
                if let Some(first_ip) = s.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }

    // Fall back to ConnectInfo
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Extract the user/session ID from the request.
fn extract_id<B>(request: &Request<B>, id_header: Option<&str>, default: &str) -> String {
    if let Some(header_name) = id_header {
        if let Some(value) = request.headers().get(header_name) {
            if let Ok(s) = value.to_str() {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    default.to_string()
}

#[cfg(test)]
mod tests {
    // Tests for middleware are integration tests in examples/
    // Unit tests would require mocking axum's Body type
}
