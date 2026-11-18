//! Operator-only local journal decisions. These methods are deliberately absent
//! from MCP discovery. The listener admits only peers with the node owner's UID.
use super::*;

pub(super) const PREFIX: &str = "node/journal/";

pub(super) async fn dispatch(
    gate: Option<&Arc<WriteGate>>,
    router: Option<&Router>,
    message: &Value,
    pid: Option<i32>,
) -> Option<String> {
    let id = message.get("id");
    // A maintenance notification cannot make an unobservable decision.
    let id = id.filter(|id| !id.is_null())?;
    #[cfg(feature = "mcp-executor-prototype")]
    let result = async {
        let gate = gate.ok_or_else(|| Error::engine("node write journal unavailable"))?;
        let params = message
            .get("params")
            .ok_or_else(|| Error::engine("missing params"))?;
        let text = |name| {
            params
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| Error::engine(format!("missing {name}")))
        };
        let entry = text("entry_id")?;
        #[cfg(feature = "v2-kernel-probe")]
        if matches!(
            message.get("method").and_then(Value::as_str),
            Some("node/journal/settle_original" | "node/journal/show")
        ) {
            let router =
                router.ok_or_else(|| Error::engine("verified recovery router unavailable"))?;
            return router
                .owner_original_recovery(entry, message["method"] == "node/journal/settle_original")
                .await;
        }
        let reason = text("reason")?;
        let outcome = match message.get("method").and_then(Value::as_str) {
            Some("node/journal/acknowledge") => Some(text("outcome")?),
            Some("node/journal/withdraw") => None,
            _ => return Err(Error::engine("unknown journal maintenance method")),
        };
        if gate.journal.get(entry).is_some() {
            gate.operator_decision(entry, outcome, reason, pid).await
        } else {
            let binding = match router {
                Some(router) => gate::Outage::custody_binding(router.as_ref()).await,
                None => None,
            }
            .ok_or_else(|| {
                Error::engine("verified custody binding unavailable; nothing changed")
            })?;
            let scoped = gate.scoped_v2_gate(&binding)?;
            scoped.operator_decision(entry, outcome, reason, pid).await
        }
    }
    .await;
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let result: Result<Value> = {
        let _ = (gate, router, pid);
        Err(Error::engine("node write journal unavailable"))
    };
    match result {
        Ok(value) => Some(json!({"jsonrpc":"2.0", "id":id, "result":value}).to_string()),
        Err(error) => frame_error(
            Some(id),
            &error.to_string(),
            json!({"outcome":"refused", "changed":false}),
        ),
    }
}

pub(super) async fn cli(socket: &Path, args: &[String]) -> Result<()> {
    let usage = || {
        Error::engine("usage: mcp-stdio node journal --socket <path> acknowledge <entry-id> --outcome landed|not_applied|superseded --reason <text> | withdraw <entry-id> --reason <text> | show <entry-id> | settle_original <entry-id>")
    };
    let [command, entry, flags @ ..] = args else {
        return Err(usage());
    };
    let expected: &[&str] = match command.as_str() {
        "acknowledge" => &["--outcome", "--reason"],
        "withdraw" => &["--reason"],
        "show" | "settle_original" => &[],
        _ => return Err(usage()),
    };
    let mut params = json!({"entry_id":entry});
    for pair in flags.chunks(2) {
        if pair.len() != 2 || !expected.contains(&pair[0].as_str()) {
            return Err(usage());
        }
        let key = pair[0].trim_start_matches("--");
        if params.get(key).is_some() {
            return Err(usage());
        }
        params[key] = json!(pair[1]);
    }
    if expected
        .iter()
        .any(|flag| params.get(flag.trim_start_matches("--")).is_none())
    {
        return Err(usage());
    }
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != owner_uid() {
        return Err(Error::engine("node server UID rejected"));
    }
    let (read, mut write) = stream.into_split();
    let message =
        json!({"jsonrpc":"2.0", "id":1, "method":format!("{PREFIX}{command}"), "params":params});
    write.write_all(format!("{message}\n").as_bytes()).await?;
    let reply = read_reply_line(&mut BufReader::new(read)).await?;
    print_reply(&reply);
    if reply.get("error").is_some() {
        return Err(Error::engine("journal decision refused; see JSON response"));
    }
    Ok(())
}
