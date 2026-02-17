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
        .post_async("/verify", handle_verify)
        .post_async("/traffic", handle_traffic)
        .post_async("/admin/users", handle_add_user)
        .get_async("/admin/users/:hash", handle_get_user)
        .delete_async("/admin/users/:hash", handle_delete_user)
        .run(req, env)
        .await
}
