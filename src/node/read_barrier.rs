//! Owner-local ordered authority observation. No mutation receipt semantics.
use super::*;

pub(super) const TIMEOUT: Duration = Duration::from_secs(10);
const CONTRACT: &str = "native.reads-barrier.v1";
const METHOD: &str = "native/reads/barrier";

pub(super) fn is_control(message: &Value) -> bool {
    message
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|m| m.starts_with("native/reads/"))
        || message.as_array().is_some_and(|a| a.iter().any(is_control))
}
pub(super) fn valid(message: &Value) -> bool {
    message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && message.get("method").and_then(Value::as_str) == Some(METHOD)
        && message
            .get("id")
            .is_some_and(|id| id.is_string() || id.is_number())
        && message
            .get("params")
            .and_then(Value::as_object)
            .is_some_and(|p| p.is_empty())
        && message.as_object().is_some_and(|p| {
            p.keys()
                .all(|k| matches!(k.as_str(), "jsonrpc" | "method" | "id" | "params"))
        })
}
pub(super) fn error(message: &Value, reason: &'static str) -> Option<String> {
    let id = message
        .get("id")
        .filter(|id| id.is_string() || id.is_number())
        .unwrap_or(&Value::Null);
    let mut data = json!({"contract":CONTRACT,"reason":reason,"read_ready":false});
    let text = if reason == "saved_state_newer" {
        data["next_step"] = json!("Upgrade the node to restore saved read barriers.");
        "Reads go to hosted. Upgrade the node to restore saved read barriers."
    } else {
        "Node read barrier did not establish read readiness"
    };
    frame_error(Some(id), text, data)
}
/// Dropped on success, cancellation, task abort or connection error.
pub(super) struct Tracking(pub Arc<InFlight>, pub String);
impl Drop for Tracking {
    fn drop(&mut self) {
        self.0.finish(&self.1);
    }
}

pub(super) async fn dispatch(
    router: Option<&Router>,
    config: &NodeConfig,
    context: &app_proof::RequestContext,
    message: &Value,
    cancel: &Cancel,
    deadline: tokio::time::Instant,
) -> Option<String> {
    #[cfg(feature = "mcp-executor-prototype")]
    {
        let Some(binding) = context
            .binding(config)
            .filter(|_| config.tracks_local_reads())
        else {
            return error(message, "barrier_unavailable");
        };
        let Some(router) = router else {
            return error(message, "barrier_unavailable");
        };
        let act = tokio::select! {
            biased;
            _ = cancel.cancelled() => return error(message, "barrier_cancelled"),
            _ = tokio::time::sleep_until(deadline) => return error(message, "barrier_timeout"),
            result = router.capture_read_barrier(&binding) => match result {
                Ok(act) => act,
                Err(reason) => return error(message, reason),
            },
        };
        // Capture/persistence may already have happened. These errors never
        // claim rollback or supply an HTTP mutation outcome to clear a latch.
        if cancel.is_cancelled() {
            return error(message, "barrier_cancelled");
        }
        if tokio::time::Instant::now() >= deadline {
            return error(message, "barrier_timeout");
        }
        if context.binding(config).as_ref() != Some(&binding) {
            return error(message, "barrier_unavailable");
        }
        Some(
            json!({"jsonrpc":"2.0","id":message["id"],"result":{
            "contract":CONTRACT,"barrier_id":uuid::Uuid::new_v4().to_string(),
            "binding":binding,"head_act":act,
            "admission":{"floor_persisted":true,"read_ready":false}}})
            .to_string(),
        )
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    {
        let _ = (router, config, context, cancel, deadline);
        error(message, "barrier_unavailable")
    }
}
