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
        .post_async("/verify", handle_verify)
        .post_async("/traffic", handle_traffic)
        .get_async("/admin/users", handle_list_users)
        .post_async("/admin/users", handle_add_user)
        .get_async("/admin/users/:id", handle_get_user)
        .patch_async("/admin/users/:id", handle_update_user)
        .delete_async("/admin/users/:id", handle_delete_user)
        // Node management
        .get_async("/admin/nodes", handle_list_nodes)
        .post_async("/admin/nodes", handle_add_node)
        .get_async("/admin/nodes/:id", handle_get_node)
        .patch_async("/admin/nodes/:id", handle_update_node)
        .delete_async("/admin/nodes/:id", handle_delete_node)
        .post_async("/admin/nodes/:id/rotate", handle_rotate_node_token)
        // Traffic logs
        .get_async("/admin/traffic", handle_list_traffic)
        // User self-service
        .get_async("/me", handle_me)
        // Sub templates
        .get_async("/sub/:name", handle_sub)
        .get_async("/admin/sub-templates", handle_list_sub_templates)
        .post_async("/admin/sub-templates", handle_add_sub_template)
        .get_async("/admin/sub-templates/:id", handle_get_sub_template)
        .patch_async("/admin/sub-templates/:id", handle_update_sub_template)
        .delete_async("/admin/sub-templates/:id", handle_delete_sub_template)
        // Migration
        .post_async("/admin/migrate", handle_migrate)
        .run(req, env)
        .await
}
