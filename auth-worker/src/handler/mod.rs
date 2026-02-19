//! Route handlers, split by domain.

mod admin_migrate;
mod admin_nodes;
mod admin_templates;
mod admin_traffic;
mod admin_users;
mod me;
mod node_api;
mod sub;

use std::future::Future;
use std::pin::Pin;

use worker::*;

use crate::util::check_admin;

pub use admin_migrate::handle_migrate;
pub use admin_nodes::*;
pub use admin_templates::*;
pub use admin_traffic::handle_list_traffic;
pub use admin_users::*;
pub use me::handle_me;
pub use node_api::*;
pub use sub::handle_sub;

/// Wraps an async handler with admin Bearer token auth check.
/// Substitute for middleware since `worker` v0.7 doesn't support it.
pub fn admin<F, Fut>(
    handler: F,
) -> impl Fn(Request, RouteContext<()>) -> Pin<Box<dyn Future<Output = Result<Response>>>>
where
    F: Fn(Request, RouteContext<()>) -> Fut + Clone + 'static,
    Fut: Future<Output = Result<Response>> + 'static,
{
    move |req, ctx| {
        let handler = handler.clone();
        Box::pin(async move {
            check_admin(&req, &ctx)?;
            handler(req, ctx).await
        })
    }
}
