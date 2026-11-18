#![cfg(unix)]

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use native_ce::node::oauth::{renew_client, renew_once, RenewOutcome, CONTRACT};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

// The issuer refuses a refresh without an explicit resource instead of minting
// the default application's audience. Exercise the real renewer and saved grant
// through two rotations, not just the form-construction helper.
#[tokio::test]
async fn renewal_preserves_native_resource_across_rotating_grants() {
    async fn token(
        State(hits): State<Arc<AtomicUsize>>,
        body: String,
    ) -> (StatusCode, Json<Value>) {
        let form: HashMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();
        if form.get("resource").map(String::as_str) != Some("https://plugin.withnative.ai/mcp") {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_target"})),
            );
        }
        let prior = hits.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("fixture-client")
        );
        assert_eq!(
            form.get("refresh_token"),
            Some(&format!("rotation-{prior}"))
        );
        (
            StatusCode::OK,
            Json(json!({
                "access_token":format!("scoped-access-{}", prior + 1),
                "refresh_token":format!("rotation-{}", prior + 1),
                "token_type":"Bearer", "expires_in":300
            })),
        )
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/oauth2/token", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/oauth2/token", post(token))
        .with_state(hits.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    // macOS may return /var/... through TMPDIR, whose /var component is a
    // symlink. Use its real path so the fixture obeys credential custody rules.
    let directory_path = directory.path().canonicalize().unwrap();
    let auth_path = directory_path.join("auth.json");
    let token_path = directory_path.join("access.token");
    let mut auth = json!({
        "contract":CONTRACT, "client_id":"fixture-client", "token_endpoint":endpoint,
        "access_token":"initial-access", "refresh_token":"rotation-0", "expires_at":0
    });
    std::fs::write(&auth_path, serde_json::to_vec(&auth).unwrap()).unwrap();
    std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let client = renew_client().unwrap();
    for round in 1..=2 {
        assert_eq!(
            renew_once(&auth_path, &token_path, &endpoint, &client)
                .await
                .unwrap(),
            RenewOutcome::Renewed
        );
        assert_eq!(
            std::fs::read_to_string(&token_path).unwrap(),
            format!("scoped-access-{round}")
        );
        auth = serde_json::from_slice(&std::fs::read(&auth_path).unwrap()).unwrap();
        assert_eq!(auth["refresh_token"], format!("rotation-{round}"));
        assert_eq!(
            std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            renew_once(&auth_path, &token_path, &endpoint, &client)
                .await
                .unwrap(),
            RenewOutcome::Fresh
        );
        assert_eq!(hits.load(Ordering::SeqCst), round);
        auth["expires_at"] = json!(0);
        std::fs::write(&auth_path, serde_json::to_vec(&auth).unwrap()).unwrap();
    }
    server.abort();
}
