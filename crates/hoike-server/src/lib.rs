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
            let serve = tower_http::services::ServeDir::new(static_dir).fallback(
                tower_http::services::ServeFile::new(
                    std::path::Path::new(static_dir).join("index.html"),
                ),
            );
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
            app = embedded_ui::mount(app);
        }
    }

    app
}

#[cfg(feature = "embed-webui")]
mod embedded_ui {
    use axum::Router;
    use axum::extract::Path;
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Redirect};
    use axum::routing::get;
    use include_dir::{Dir, include_dir};

    static WEBUI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../webui/dist");

    /// Mount the embedded SPA on the main router.
    ///
    /// The OCSP protocol occupies a greedy `GET /{*path}` catch-all (OCSP-over-GET
    /// carries a base64 request in the path). Nesting a sub-router for the SPA is
    /// unreliable under axum 0.8: `GET /ui/` (the directory root, trailing slash)
    /// loses to the catch-all and returns the 5-byte OCSP `malformedRequest` error.
    /// Registering explicit static routes — which outrank the wildcard in matchit —
    /// keeps the SPA entry point (`/ui`, `/ui/`) and its assets (`/ui/{*path}`)
    /// deterministically routed. `/ui` and `/ui/` redirect to the app index.
    pub fn mount<S>(app: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        app.route("/ui", get(|| async { Redirect::permanent("/ui/") }))
            .route("/ui/", get(serve_index))
            .route("/ui/{*path}", get(serve_file))
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

#[cfg(all(test, feature = "embed-webui"))]
mod embedded_ui_tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt; // for `oneshot`

    /// Reproduce the production route layout: the SPA is mounted alongside the
    /// greedy OCSP-over-GET catch-all (`GET /{*path}`). This guards against two
    /// regressions: (1) a matchit wildcard-conflict panic at router-build time,
    /// and (2) `GET /ui/` falling through to the OCSP handler (which returns the
    /// 5-byte `malformedRequest` DER, not the SPA).
    fn test_router() -> Router {
        async fn ocsp_catch_all() -> &'static [u8] {
            // The static OCSP malformedRequest response is 5 bytes.
            &[0x30, 0x03, 0x0a, 0x01, 0x01]
        }
        let app = Router::new().route("/{*path}", get(ocsp_catch_all));
        super::embedded_ui::mount(app)
    }

    #[tokio::test]
    async fn ui_root_serves_spa_not_ocsp() {
        let resp = test_router()
            .oneshot(Request::get("/ui/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ctype = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ctype.starts_with("text/html"),
            "GET /ui/ must serve the SPA index (text/html), got content-type {ctype:?}"
        );
    }

    #[tokio::test]
    async fn ui_bare_redirects_to_slash() {
        let resp = test_router()
            .oneshot(Request::get("/ui").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "/ui/",
            "GET /ui must redirect to /ui/"
        );
    }

    #[tokio::test]
    async fn non_ui_path_still_hits_ocsp() {
        // A non-/ui path must still reach the OCSP catch-all unchanged.
        let resp = test_router()
            .oneshot(Request::get("/MFQwUj...").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(body.len(), 5, "OCSP-over-GET path must still be served");
    }
}
