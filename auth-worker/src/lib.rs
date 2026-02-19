mod handler;
mod types;
mod util;

use worker::*;

use handler::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    Router::new()
        .get("/health", |_, _| Response::ok("ok"))
        .get("/admin/version", |_, _| {
            Response::ok(env!("CARGO_PKG_VERSION"))
        })
        // Node-facing API (Bearer token auth handled inside)
        .post_async("/verify", handle_verify)
        .post_async("/traffic", handle_traffic)
        // Admin — Users
        .get_async("/admin/users", admin(handle_list_users))
        .post_async("/admin/users", admin(handle_add_user))
        .get_async("/admin/users/:id", admin(handle_get_user))
        .patch_async("/admin/users/:id", admin(handle_update_user))
        .delete_async("/admin/users/:id", admin(handle_delete_user))
        // Admin — Nodes
        .get_async("/admin/nodes", admin(handle_list_nodes))
        .post_async("/admin/nodes", admin(handle_add_node))
        .get_async("/admin/nodes/:id", admin(handle_get_node))
        .patch_async("/admin/nodes/:id", admin(handle_update_node))
        .delete_async("/admin/nodes/:id", admin(handle_delete_node))
        .post_async("/admin/nodes/:id/rotate", admin(handle_rotate_node_token))
        // Admin — Traffic logs
        .get_async("/admin/traffic", admin(handle_list_traffic))
        // Admin — Sub templates
        .get_async("/admin/sub-templates", admin(handle_list_sub_templates))
        .post_async("/admin/sub-templates", admin(handle_add_sub_template))
        .get_async("/admin/sub-templates/:id", admin(handle_get_sub_template))
        .patch_async("/admin/sub-templates/:id", admin(handle_update_sub_template))
        .delete_async("/admin/sub-templates/:id", admin(handle_delete_sub_template))
        // Admin — Migration
        .post_async("/admin/migrate", admin(handle_migrate))
        // Public — Subscription
        .get_async("/sub/:name", handle_sub)
        // User self-service
        .get_async("/me", handle_me)
        .run(req, env)
        .await
}
