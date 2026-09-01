mod admin;
mod handlers;
mod state;

pub use state::{AppState, LiveSignerState};

use axum::Router;
use axum::routing::{get, post};

pub fn build_router(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/", post(handlers::handle_post))
        .route("/", get(handlers::handle_get_root))
        .route("/{*path}", get(handlers::handle_get))
        .route("/{*path}", post(handlers::handle_post))
        .with_state(state.clone());

    let admin_router = admin::build_admin_router(state.clone());
    app = app.nest("/api/admin", admin_router);

    if let Some(webui_config) = &state.admin.config.server.webui {
        if let Some(static_dir) = &webui_config.static_dir {
            let serve = tower_http::services::ServeDir::new(static_dir)
                .fallback(tower_http::services::ServeFile::new(
                    std::path::Path::new(static_dir).join("index.html"),
                ));
            app = app.nest_service("/ui", serve);
        }
    }

    #[cfg(feature = "embed-webui")]
    {
        if state
            .admin
            .config
            .server
            .webui
            .as_ref()
            .is_some_and(|w| w.static_dir.is_none())
        {
            app = app.nest("/ui", embedded_ui::webui_router());
        }
    }

    app
}

#[cfg(feature = "embed-webui")]
mod embedded_ui {
    use axum::Router;
    use axum::extract::Path;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use include_dir::{Dir, include_dir};

    static WEBUI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../webui/dist");

    pub fn webui_router() -> Router {
        Router::new()
            .route("/", get(serve_index))
            .route("/{*path}", get(serve_file))
    }

    async fn serve_index() -> axum::response::Response {
        serve_path("index.html")
    }

    async fn serve_file(Path(path): Path<String>) -> axum::response::Response {
        serve_path(&path)
    }

    fn serve_path(path: &str) -> axum::response::Response {
        match WEBUI_DIR.get_file(path) {
            Some(file) => {
                let mime = mime_from_path(path);
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, mime)],
                    file.contents().to_vec(),
                )
                    .into_response()
            }
            None => {
                if let Some(index) = WEBUI_DIR.get_file("index.html") {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        index.contents().to_vec(),
                    )
                        .into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
        }
    }

    fn mime_from_path(path: &str) -> &'static str {
        match path.rsplit('.').next() {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            Some("woff") => "font/woff",
            _ => "application/octet-stream",
        }
    }
}
