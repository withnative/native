//! Portable Alpha asset and record-route classification, shared with hosted serving.
//! No authentication, hosting state, HTTP responses or asset embedding.

/// The shell's own static files, by extension. Unlike the workbench bundle
/// these are not content-hashed — the shell has no build step — so `immutable`
/// would be dishonest and a deploy would not become visible. Assets are
/// served with `no-cache` plus a strong `ETag` over the embedded bytes: the
/// browser revalidates every load and takes a bodyless `304` while the bytes
/// are unchanged, and a deploy (new bytes, new `ETag`) is visible on the next
/// load. The page itself (`alpha_index`) stays `no-store` — it carries
/// per-deployment injection and costs one request.
pub fn is_alpha_static_asset(path: &str) -> bool {
    let Some((_, extension)) = path.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension,
        "js" | "mjs"
            | "css"
            | "map"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "svg"
            | "ico"
            | "woff"
            | "woff2"
            | "ttf"
    )
}

/// The shell's own `recordPath` rule (`RECORD_PATH` in
/// `experiments/demo-shell/public/lib/refs.js`): a hex reference or an opaque
/// `native:` record id. Single-segment: anything with a `/` is a nested path,
/// not a reference. Axum's `Path` extractor decodes `%3A` before this check.
pub fn is_alpha_record_reference(path: &str) -> bool {
    if path.is_empty() || path.contains('/') {
        return false;
    }
    if let Some(name) = path.strip_prefix("native:") {
        return (1..=57).contains(&name.len())
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    }
    is_hex_record_reference(path)
}

pub(crate) fn is_hex_record_reference(reference: &str) -> bool {
    let hex = reference.replace('-', "");
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    if hex.len() == 32 {
        return reference.len() == 36
            && [8, 13, 18, 23]
                .into_iter()
                .all(|index| reference.as_bytes()[index] == b'-');
    }
    (6..32).contains(&hex.len())
}
