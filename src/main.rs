mod hash;
mod wordpress;

use axum::{
    extract::State,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hash::{hash_password, Algorithm, HashOptions};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(not(debug_assertions))]
use include_dir::{include_dir, Dir};

#[cfg(not(debug_assertions))]
static STATIC: Dir = include_dir!("$CARGO_MANIFEST_DIR/static");

#[derive(Clone)]
struct AppState;

#[derive(Debug, Deserialize)]
struct HashRequest {
    password: String,
    #[serde(default)]
    algorithms: Vec<String>,
    #[serde(default)]
    options: HashOptions,
}

#[derive(Debug, Serialize)]
struct HashResultItem {
    algorithm: String,
    label: String,
    hash: String,
    category: String,
}

#[derive(Debug, Serialize)]
struct HashResponse {
    results: Vec<HashResultItem>,
    errors: Vec<HashErrorItem>,
}

#[derive(Debug, Serialize)]
struct HashErrorItem {
    algorithm: String,
    error: String,
}

#[derive(Debug, Serialize)]
struct AlgorithmInfo {
    id: String,
    label: String,
    category: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct AlgorithmsResponse {
    algorithms: Vec<AlgorithmInfo>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hashmaker=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = Arc::new(AppState);

    let app = Router::new()
        .route("/api/algorithms", get(list_algorithms))
        .route("/api/hash", post(generate_hashes))
        .fallback(static_handler)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Hashmaker running at http://localhost:{port}");

    #[cfg(debug_assertions)]
    tracing::info!("dev mode: serving static/ from disk (no recompile needed for UI changes)");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind port");

    axum::serve(listener, app).await.expect("server error");
}

async fn list_algorithms() -> Json<AlgorithmsResponse> {
    let algorithms = Algorithm::all()
        .iter()
        .map(|algo| AlgorithmInfo {
            id: algo.to_string(),
            label: algo.label().to_string(),
            category: algo.category().to_string(),
            description: algo.description().to_string(),
        })
        .collect();

    Json(AlgorithmsResponse { algorithms })
}

async fn generate_hashes(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<HashRequest>,
) -> Result<Json<HashResponse>, AppError> {
    if body.password.is_empty() {
        return Err(AppError::bad_request("Password cannot be empty"));
    }

    let algorithms: Vec<Algorithm> = if body.algorithms.is_empty() {
        Algorithm::all().to_vec()
    } else {
        body.algorithms
            .iter()
            .filter_map(|name| Algorithm::from_str(name))
            .collect()
    };

    if algorithms.is_empty() {
        return Err(AppError::bad_request("No valid algorithms specified"));
    }

    let options = body.options;

    let mut results = Vec::new();
    let mut errors = Vec::new();

    for algo in algorithms {
        match hash_password(&body.password, algo, &options) {
            Ok(hash) => results.push(HashResultItem {
                algorithm: algo.to_string(),
                label: algo.label().to_string(),
                hash,
                category: algo.category().to_string(),
            }),
            Err(e) => errors.push(HashErrorItem {
                algorithm: algo.to_string(),
                error: e.message,
            }),
        }
    }

    Ok(Json(HashResponse { results, errors }))
}

async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    #[cfg(debug_assertions)]
    return serve_from_disk(path).await;

    #[cfg(not(debug_assertions))]
    serve_embedded(path)
}

#[cfg(debug_assertions)]
async fn serve_from_disk(path: &str) -> Response {
    use tokio::fs;

    let static_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
    let file_path = if path.is_empty() || path == "index.html" {
        static_root.join("index.html")
    } else {
        static_root.join(path)
    };

    if file_path.is_file() {
        if let Ok(resolved) = file_path.canonicalize() {
            if let Ok(root) = static_root.canonicalize() {
                if resolved.starts_with(&root) {
                    if let Ok(contents) = fs::read(&resolved).await {
                        let mime = mime_guess(path);
                        return ([(header::CONTENT_TYPE, mime)], contents).into_response();
                    }
                }
            }
        }
    }

    let index = static_root.join("index.html");
    if index.is_file() {
        if let Ok(contents) = fs::read(index).await {
            return (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                contents,
            )
                .into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

#[cfg(not(debug_assertions))]
fn serve_embedded(path: &str) -> Response {
    let file = if path.is_empty() || path == "index.html" {
        STATIC.get_file("index.html")
    } else {
        STATIC.get_file(path)
    };

    match file {
        Some(entry) => {
            let mime = mime_guess(path);
            ([(header::CONTENT_TYPE, mime)], entry.contents()).into_response()
        }
        None => match STATIC.get_file("index.html") {
            Some(entry) => (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                entry.contents(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

fn mime_guess(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "text/html; charset=utf-8",
    }
}

struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}
