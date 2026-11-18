//! Ordinary queue proofs use the real v2 adapter; HTTP only transports it.
use super::*;
use crate::node::journal::{CustodyBinding, V2_EVIDENCE_VERSION};

struct Verified {
    binding: StdMutex<Option<CustodyBinding>>,
    down: AtomicBool,
    wrong_contract: AtomicBool,
    missing_contract: AtomicBool,
    operation_absent: AtomicBool,
    confirm_outage: AtomicBool,
    unframed_maintenance: AtomicBool,
    update_required: AtomicBool,
    compatibility_reads: AtomicUsize,
    contract_override: StdMutex<Option<NodeHoldingContract>>,
    receiver95: AtomicBool,
    published_ordinal: std::sync::atomic::AtomicI64,
    dispatch_exclusions: StdMutex<Option<Vec<String>>>,
    protocols: StdMutex<Vec<Option<String>>>,
    protocol_contracts: StdMutex<std::collections::BTreeMap<String, NodeHoldingContract>>,
    credential: [u8; 32],
    replace_scope_before_send: StdMutex<Option<CustodyBinding>>,
    active_sends: AtomicUsize,
    before_entered: tokio::sync::Notify,
    completed_sends: AtomicUsize,
}
impl Outage for Verified {
    fn working_published<'a>(&'a self, scope: &'a CustodyBinding, ordinal: i64) -> Ready<'a, bool> {
        Box::pin(async move {
            self.binding.lock().unwrap().as_ref() == Some(scope)
                && ordinal > 0
                && self.published_ordinal.load(Ordering::Acquire) == ordinal
        })
    }
    fn working_dispatch_exclusions<'a>(
        &'a self,
        scope: &'a CustodyBinding,
    ) -> Ready<'a, Option<Vec<String>>> {
        Box::pin(async move {
            if self.binding.lock().unwrap().as_ref() != Some(scope) {
                return None;
            }
            self.dispatch_exclusions.lock().unwrap().clone()
        })
    }
    fn confirm_down(&self) -> Ready<'_, bool> {
        Box::pin(async {
            self.confirm_outage.load(Ordering::Acquire) && self.down.load(Ordering::Acquire)
        })
    }
    fn known_unreachable(&self) -> Ready<'_, bool> {
        Box::pin(async { self.down.load(Ordering::Acquire) })
    }
    fn held_replay_allowed(&self) -> Ready<'_, bool> {
        Box::pin(async { false })
    }
    fn custody_binding(&self) -> Ready<'_, Option<CustodyBinding>> {
        Box::pin(async { self.binding.lock().unwrap().clone() })
    }
    fn custody_credential(&self) -> Ready<'_, Option<[u8; 32]>> {
        Box::pin(async { Some(self.credential) })
    }
    fn before_send(&self) -> Ready<'_, bool> {
        Box::pin(async {
            self.active_sends.fetch_add(1, Ordering::AcqRel);
            self.before_entered.notify_one();
            let replacement = self.replace_scope_before_send.lock().unwrap().take();
            if let Some(replacement) = replacement {
                *self.binding.lock().unwrap() = Some(replacement);
            }
            true
        })
    }
    fn after_send(&self, _: bool) -> Ready<'_, ()> {
        Box::pin(async {
            assert!(self.active_sends.fetch_sub(1, Ordering::AcqRel) > 0);
            self.completed_sends.fetch_add(1, Ordering::AcqRel);
        })
    }
    fn holding_operation_absent<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Option<&'a str>,
    ) -> Ready<'a, bool> {
        Box::pin(async {
            self.operation_absent.load(Ordering::Acquire)
                && !self.missing_contract.load(Ordering::Acquire)
        })
    }
    fn holding_contract<'a>(
        &'a self,
        executor: &'a str,
        operation: &'a str,
        protocol: Option<&'a str>,
    ) -> Ready<'a, Option<NodeHoldingContract>> {
        Box::pin(async move {
            self.compatibility_reads.fetch_add(1, Ordering::AcqRel);
            self.protocols
                .lock()
                .unwrap()
                .push(protocol.map(str::to_owned));
            if self.missing_contract.load(Ordering::Acquire)
                || self.operation_absent.load(Ordering::Acquire)
            {
                return None;
            }
            if self.receiver95.load(Ordering::Acquire) {
                return Some(receiver95_contract(operation));
            }
            if let Some(contract) = self
                .protocol_contracts
                .lock()
                .unwrap()
                .get(protocol.unwrap_or(crate::mcp::PROTOCOL_VERSION))
                .cloned()
            {
                return Some(contract);
            }
            if let Some(contract) = self
                .contract_override
                .lock()
                .unwrap()
                .clone()
                .filter(|c| c.description["operation"] == operation)
            {
                return Some(contract);
            }
            let contracts = if operation == "merge_body" {
                crate::mcp::executor_prototype::NodeOperationContracts::local().unwrap()
            } else {
                crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap()
            };
            let mut contract = contracts.holding_contract(executor, operation)?;
            if self.wrong_contract.load(Ordering::Acquire) {
                contract.description["contract_digest"] = json!("0".repeat(64));
                contract.description["input_schema"]["description"] =
                    json!("Incompatible schema description");
            }
            Some(contract)
        })
    }
    fn contract_digest<'a>(
        &'a self,
        executor: &'a str,
        operation: &'a str,
        _: Option<&'a str>,
    ) -> Ready<'a, Option<String>> {
        Box::pin(async move {
            if self.missing_contract.load(Ordering::Acquire)
                || self.operation_absent.load(Ordering::Acquire)
            {
                return None;
            }
            if self.wrong_contract.load(Ordering::Acquire) {
                return Some("0".repeat(64));
            }
            if self.receiver95.load(Ordering::Acquire) {
                return receiver95_contract(operation).description["contract_digest"]
                    .as_str()
                    .map(str::to_owned);
            }
            let contracts = if operation == "merge_body" {
                crate::mcp::executor_prototype::NodeOperationContracts::local().unwrap()
            } else {
                crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap()
            };
            if let Some(contract) = self
                .contract_override
                .lock()
                .unwrap()
                .as_ref()
                .filter(|c| c.description["operation"] == operation)
            {
                return contract.description["contract_digest"]
                    .as_str()
                    .map(str::to_owned);
            }
            contracts.digest(executor, operation).map(str::to_owned)
        })
    }
}

struct ExistingRig {
    home: HomeRig,
    upstream: Arc<Upstream>,
    verified: Arc<Verified>,
    drop_reply: Arc<AtomicBool>,
    outcomes: Arc<StdMutex<Vec<Value>>>,
    wire_protocols: Arc<StdMutex<Vec<Value>>>,
    wire_requests: Arc<StdMutex<Vec<Value>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ExistingRig {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ExistingRig {
    async fn new() -> Self {
        let home = HomeRig::new().await;
        let manifest = crate::v2_standard::relates_to::package();
        let identity = manifest.identity().unwrap();
        kernel::install_package_as(&home.world.db, &home.world.admin, &manifest)
            .await
            .unwrap();
        kernel::adopt_package_at(
            &home.world.db,
            &home.world.admin,
            KERNEL_ROOT_ID,
            &manifest,
            Some(&identity),
            &manifest.declared_reads,
        )
        .await
        .unwrap();
        let binding = CustodyBinding {
            account_id: "acct:admin".into(),
            database_id: "test-workspace".into(),
            origin_database_id: "origin-v2-proof".into(),
            history_lineage: "v2:genesis-proof".into(),
            resource_origin: "https://native.example".into(),
            install_id: None,
        };
        let verified = Arc::new(Verified {
            binding: StdMutex::new(Some(binding)),
            down: AtomicBool::new(true),
            wrong_contract: AtomicBool::new(false),
            missing_contract: AtomicBool::new(false),
            operation_absent: AtomicBool::new(false),
            confirm_outage: AtomicBool::new(true),
            unframed_maintenance: AtomicBool::new(false),
            update_required: AtomicBool::new(false),
            compatibility_reads: AtomicUsize::new(0),
            contract_override: StdMutex::new(None),
            receiver95: AtomicBool::new(false),
            published_ordinal: std::sync::atomic::AtomicI64::new(0),
            dispatch_exclusions: StdMutex::new(None),
            protocols: StdMutex::new(Vec::new()),
            protocol_contracts: StdMutex::new(Default::default()),
            replace_scope_before_send: StdMutex::new(None),
            active_sends: AtomicUsize::new(0),
            before_entered: tokio::sync::Notify::new(),
            completed_sends: AtomicUsize::new(0),
            credential: {
                use sha2::Digest;
                sha2::Sha256::digest(
                    &*read_guarded_credential(&home.upstream.config.credential_file, "node")
                        .unwrap(),
                )
                .into()
            },
        });
        let drop_reply = Arc::new(AtomicBool::new(false));
        let outcomes = Arc::new(StdMutex::new(Vec::new()));
        let wire_protocols = Arc::new(StdMutex::new(Vec::new()));
        let wire_requests = Arc::new(StdMutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        verified
            .binding
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .resource_origin = format!("http://{address}");
        let task = tokio::spawn({
            let world = home.world.clone();
            let verified = verified.clone();
            let drop_reply = drop_reply.clone();
            let outcomes = outcomes.clone();
            let wire_protocols = wire_protocols.clone();
            let wire_requests = wire_requests.clone();
            async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        break;
                    };
                    let world = world.clone();
                    let verified = verified.clone();
                    let drop_reply = drop_reply.clone();
                    let outcomes = outcomes.clone();
                    let wire_protocols = wire_protocols.clone();
                    let wire_requests = wire_requests.clone();
                    tokio::spawn(async move {
                        let Some(request) = read_request(&mut socket).await else {
                            return;
                        };
                        wire_requests.lock().unwrap().push(request.clone());
                        wire_protocols.lock().unwrap().push(
                            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
                                .clone(),
                        );
                        if verified.update_required.load(Ordering::Acquire) {
                            respond(
                                &mut socket,
                                426,
                                "application/json",
                                crate::node::gate::tests::CLIENT_UPDATE,
                            )
                            .await;
                            return;
                        }
                        if verified.down.load(Ordering::Acquire) {
                            if verified.unframed_maintenance.load(Ordering::Acquire) {
                                let refusal = json!({"error":"this Native deployment is temporarily read-only",
                                    "error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retryable":true,
                                    "operation":"update_record","retry_after_secs":30,
                                    "recovery":"This write was not applied or queued"});
                                respond(&mut socket, 503, "application/json", &refusal.to_string())
                                    .await;
                                return;
                            }
                            let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":{
                                "isError":true,"content":[],"structuredContent":{
                                    "error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retryable":true}}});
                            respond(&mut socket, 503, "application/json", &reply.to_string()).await;
                            return;
                        }
                        let operation = request["params"]["arguments"]["operation"]
                            .as_str()
                            .unwrap();
                        let mut args = request["params"]["arguments"]["arguments"].clone();
                        let tool = if operation == "manage_links.add" {
                            args["action"] = json!("add");
                            "manage_links"
                        } else {
                            operation
                        };
                        let answer = registry()
                            .call_engine(
                                EngineHandle::KernelV2(world.db.clone()),
                                world.admin_caller.clone(),
                                tool,
                                args,
                            )
                            .await;
                        let result = match answer {
                            Ok(body) => {
                                outcomes.lock().unwrap().push(body.clone());
                                json!({"content":[],"structuredContent":body,"isError":false})
                            }
                            Err(error) => {
                                json!({"content":[{"type":"text","text":error.to_string()}],"isError":true})
                            }
                        };
                        if drop_reply.swap(false, Ordering::AcqRel) {
                            verified.down.store(true, Ordering::Release);
                            return;
                        }
                        let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
                        respond(&mut socket, 200, "application/json", &reply.to_string()).await;
                    });
                }
            }
        });
        let mut config = home.upstream.config.clone();
        config.hosted_base_url = format!("http://{address}");
        let upstream = Arc::new(Upstream::new(config, Duration::from_secs(30)).unwrap());
        let rig = Self {
            home,
            upstream,
            verified,
            drop_reply,
            outcomes,
            wire_protocols,
            wire_requests,
            task,
        };
        rig.scoped();
        rig
    }
    fn binding(&self) -> CustodyBinding {
        self.verified.binding.lock().unwrap().clone().unwrap()
    }
    fn scoped(&self) -> Arc<WriteGate> {
        let scoped = self.home.gate.scoped_v2_gate(&self.binding()).unwrap();
        for operation in ["update_record", "manage_links.add", "attach_text"] {
            scoped.keyed.lock().unwrap().insert(
                ("records_write".into(), operation.into()),
                Cached {
                    checked: Instant::now(),
                    ttl: Duration::from_secs(3600),
                    value: Keyed::Yes,
                },
            );
        }
        scoped
    }
    async fn send(&self, operation: &str, args: Value) -> Value {
        self.send_protocol(operation, args, None).await
    }
    async fn send_protocol(&self, operation: &str, args: Value, protocol: Option<&str>) -> Value {
        let message = tool_call(
            11,
            "call_executor",
            json!({"executor":"records_write","operation":operation,"arguments":args}),
        );
        let body = message.to_string();
        let caller = Caller::new(None, Cancel::new());
        let report = self
            .home
            .gate
            .forward(
                &self.upstream,
                &WriteRequest {
                    body: &body,
                    message: &message,
                    revision: protocol,
                    caller: &caller,
                    outage: Some(self.verified.as_ref()),
                    no_hold: false,
                },
                true,
            )
            .await;
        serde_json::from_str(&report.reply.unwrap()).unwrap()
    }
    async fn merge(&self, id: &str, draft: &str, key: &str) -> Value {
        let message = json!({"jsonrpc":"2.0","id":12,"method":"tools/call",
            "params":{"name":"call_executor","_meta":{"native/body_merge":{"wait":"none","editor":"mixed-proof"}},
                "arguments":{"executor":"records_write","operation":"merge_body","run_key":"real-home-proof",
                    "arguments":{"record_id":id,"base_version":version(&self.home.world,id).await,
                        "base_text":canonical(&self.home.world,id).await,"my_text":draft,
                        "reason":"mixed queue proof","idempotency_key":key}}}});
        let body = message.to_string();
        let caller = Caller::new(None, Cancel::new());
        let report = self
            .home
            .gate
            .forward(
                &self.upstream,
                &WriteRequest {
                    body: &body,
                    message: &message,
                    revision: None,
                    caller: &caller,
                    outage: Some(self.verified.as_ref()),
                    no_hold: false,
                },
                true,
            )
            .await;
        serde_json::from_str(&report.reply.unwrap()).unwrap()
    }

    async fn drain(&self) -> queue::Halt {
        self.scoped()
            .drain(&self.upstream, Some(self.verified.as_ref()), None, None)
            .await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_queue_restarts_and_replays_append_link_attachment_once() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let other = record(&rig.home.world, "other").await;
    let append_args =
        json!({"id":id,"body_append":"!","reason":"queued append","idempotency_key":"append"});
    for (operation, args) in [
        ("update_record", append_args.clone()),
        (
            "manage_links.add",
            json!({"source_id":id,"target_id":other,"relationship":"relates_to","idempotency_key":"link"}),
        ),
        (
            "attach_text",
            json!({"record_id":id,"text":"proof attachment","name":"proof.txt","idempotency_key":"attach"}),
        ),
    ] {
        let reply = rig.send(operation, args).await;
        assert!(reply.to_string().contains("accepted_pending"), "{reply}");
    }
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
    assert_eq!(rig.scoped().journal.pending_count(), 3);
    assert_eq!(
        rig.home.gate.journal.pending_count(),
        0,
        "legacy queue unchanged"
    );
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    assert_eq!(rig.scoped().journal.pending_count(), 3);
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(rig.outcomes.lock().unwrap().len(), 3);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(rig.outcomes.lock().unwrap().len(), 3);
    let scoped = rig.scoped();
    for file in std::fs::read_dir(scoped.journal.directory()).unwrap() {
        let entry: Value =
            serde_json::from_slice(&std::fs::read(file.unwrap().path()).unwrap()).unwrap();
        assert_eq!(entry["version"], 6);
        assert_eq!(
            entry["kernel_v2_custody"]["binding"],
            serde_json::to_value(rig.binding()).unwrap()
        );
        assert_eq!(entry["state"], "confirmed");
    }
    // Reopen terminal files too: successful settlement dropped private
    // arguments/envelopes, while the v2 binding and receipt must stay readable.
    drop(scoped);
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    assert_eq!(
        rig.scoped().status(&Default::default())["entry_counts"]["confirmed"],
        3
    );
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    let replay = rig.send("update_record", append_args).await;
    assert_eq!(replay["result"]["isError"], false, "{replay}");
    assert_eq!(
        rig.outcomes.lock().unwrap().len(),
        3,
        "terminal repeat never dispatches"
    );
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_lost_reply_uses_canonical_keyed_receipt() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.verified.down.store(false, Ordering::Release);
    rig.drop_reply.store(true, Ordering::Release);
    let reply = rig
        .send(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"lost","idempotency_key":"lost"}),
        )
        .await;
    assert!(reply.to_string().contains("accepted_pending"), "{reply}");
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    let outcomes = rig.outcomes.lock().unwrap();
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0], outcomes[1]);
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_binding_and_contract_changes_preserve_private_custody() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "secret").await;
    let args =
        json!({"id":id,"body_append":"!","reason":"private","idempotency_key":"private-key"});
    assert!(rig
        .send("update_record", args)
        .await
        .to_string()
        .contains("accepted_pending"));
    let original = rig.binding();
    let scoped = rig.scoped();
    *rig.verified.binding.lock().unwrap() = None;
    assert_eq!(
        scoped
            .drain(&rig.upstream, Some(rig.verified.as_ref()), None, None)
            .await,
        queue::Halt::Local
    );
    let status = rig
        .home
        .gate
        .scoped_status(&Default::default(), Some(rig.verified.as_ref()))
        .await;
    assert!(!status.to_string().contains("private-key"));
    assert!(!status.to_string().contains(&id));
    let mut other = original.clone();
    other.account_id = "other-account".into();
    *rig.verified.binding.lock().unwrap() = Some(other);
    assert_eq!(
        scoped
            .drain(&rig.upstream, Some(rig.verified.as_ref()), None, None)
            .await,
        queue::Halt::Local
    );
    *rig.verified.binding.lock().unwrap() = Some(original);
    rig.verified.wrong_contract.store(true, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(scoped.journal.pending_count(), 1);
    assert_eq!(canonical(&rig.home.world, &id).await, "secret");
}

#[test]
fn v2_existing_shape_scope_excludes_creates_guards_apps_and_aliases() {
    let id = "70110000-0000-4000-8000-000000000001";
    let eligible = |operation, args| {
        crate::node::gate::v2_holding::eligible("records_write", operation, &args)
    };
    assert!(eligible(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"append"})
    ));
    assert!(!eligible(
        "create_record",
        json!({"type":"Document","kind":"note"})
    ));
    assert!(!eligible(
        "update_record",
        json!({"id":id,"body_append":"!","if_body_digest":"guard"})
    ));
    assert!(!eligible(
        "update_record",
        json!({"id":"short","body_append":"!"})
    ));
    assert!(!eligible(
        "update_record",
        json!({"id":id,"record_id":id,"body_append":"!"})
    ));
    assert!(!eligible(
        "update_record",
        json!({"id":id,"body_append":"!","name":"unrelated edit"})
    ));
    assert!(!eligible(
        "attach_text",
        json!({"ids":[id],"text":"attachment"})
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_actual_token_replacement_never_sends_saved_custody() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let reply = rig
        .send(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"token race","idempotency_key":"token-race"}),
        )
        .await;
    assert!(reply.to_string().contains("accepted_pending"));
    // Leave the router witness unchanged to simulate replacement after its
    // last check, including OAuth renewal inside the transport attempt.
    fs::write(&rig.upstream.config.credential_file, "new-unverified-token").unwrap();
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Credentials(None));
    assert_eq!(rig.scoped().journal.pending_count(), 1);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
    assert!(rig.outcomes.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_history_changed_during_floor_hook_stops_before_attempt() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let reply = rig
        .send(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"floor race","idempotency_key":"floor-race"}),
        )
        .await;
    assert!(reply.to_string().contains("accepted_pending"));
    let scoped = rig.scoped();
    let entry = scoped.journal.oldest_pending().unwrap();
    let mut replacement = rig.binding();
    replacement.history_lineage = "v2:origin:replacement-genesis".into();
    *rig.verified.replace_scope_before_send.lock().unwrap() = Some(replacement);
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(
        scoped
            .drain(&rig.upstream, Some(rig.verified.as_ref()), None, None)
            .await,
        queue::Halt::Local
    );
    let retained = scoped.journal.get(&entry.id).unwrap();
    assert_eq!(retained.state, EntryState::Pending);
    assert_eq!(retained.attempts, 0);
    assert!(!retained.in_flight);
    assert_eq!(
        rig.verified.active_sends.load(Ordering::Acquire),
        0,
        "floor hook was unwound"
    );
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
    assert!(rig.outcomes.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_append_then_merge_blocks_only_same_record_after_restart() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let other = record(&rig.home.world, "other").await;
    let append = rig.send("update_record", json!({"id":id,"body_append":"!","reason":"first append","idempotency_key":"first-append"})).await;
    assert!(append.to_string().contains("accepted_pending"));
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    let denied = rig
        .merge(&id, "later draft preserved by caller", "later-merge")
        .await;
    assert!(denied.to_string().contains("not_sent"), "{denied}");
    assert!(
        denied.to_string().contains("body append custody"),
        "{denied}"
    );
    assert_eq!(rig.home.gate.journal.pending_count(), 0);
    assert_eq!(rig.scoped().journal.pending_count(), 1);
    let unrelated = rig.merge(&other, "unrelated draft", "other-merge").await;
    assert!(
        unrelated.to_string().contains("saved_on_device"),
        "{unrelated}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_merge_then_append_blocks_open_and_incomplete_merge_states() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let other = record(&rig.home.world, "other").await;
    let merged = rig.merge(&id, "first draft", "first-merge").await;
    assert!(merged.to_string().contains("saved_on_device"), "{merged}");
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    let entry = rig.home.gate.journal.oldest_pending().unwrap();
    for (index, state) in [
        EntryState::Pending,
        EntryState::Sent,
        EntryState::HostedPending,
        EntryState::Uncertain,
        EntryState::CommittedUnrecovered,
        EntryState::ResultUnrecovered,
    ]
    .into_iter()
    .enumerate()
    {
        rig.home
            .gate
            .journal
            .update(&entry.id, |entry| {
                entry.state = state;
                entry.in_flight = true;
            })
            .unwrap();
        let denied = rig.send("update_record",json!({"id":id,"body_append":"later","reason":"blocked","idempotency_key":format!("blocked-{index}")})).await;
        assert!(
            denied.to_string().contains("not_sent"),
            "{state:?}: {denied}"
        );
        assert!(denied.to_string().contains("custody"), "{denied}");
    }
    assert_eq!(
        rig.scoped().journal.pending_count(),
        0,
        "later append never falsely saved"
    );
    let unrelated = rig.send("update_record",json!({"id":other,"body_append":"!","reason":"unrelated","idempotency_key":"unrelated-append"})).await;
    assert!(
        unrelated.to_string().contains("accepted_pending"),
        "{unrelated}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_inflight_append_blocks_merge_admission() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    // Pause after durable Sent insertion and before dispatch. This is a live
    // ordinary request, rather than a hand-made pending queue row.
    rig.verified.down.store(false, Ordering::Release);
    let scoped = rig.scoped();
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *scoped.pause_before_send.lock().unwrap() = Some((entered.clone(), resume.clone()));
    let send = rig.send(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"in flight","idempotency_key":"inflight"}),
    );
    tokio::pin!(send);
    tokio::select! { _ = entered.notified() => {}, result = &mut send => panic!("request finished before pause: {result}") }
    let denied = rig.merge(&id, "later draft", "inflight-merge").await;
    assert!(denied.to_string().contains("not_sent"), "{denied}");
    resume.notify_one();
    let result = send.await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_null_blank_keys_cannot_overtake_root_merge() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    assert!(rig
        .merge(&id, "first draft", "keyless-first")
        .await
        .to_string()
        .contains("saved_on_device"));
    for key in [Value::Null, json!("")] {
        let denied = rig
            .send(
                "update_record",
                json!({"id":id,"body_append":"later","reason":"keyless","idempotency_key":key}),
            )
            .await;
        assert!(denied.to_string().contains("not_sent"), "{denied}");
        assert!(denied.to_string().contains("custody"), "{denied}");
    }
    assert_eq!(rig.scoped().journal.pending_count(), 0);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
    assert!(rig.outcomes.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_keyless_single_attempt_still_binds_actual_token() {
    for key in [Value::Null, json!("")] {
        let rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        rig.verified.down.store(false, Ordering::Release);
        let scoped = rig.scoped();
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *scoped.pause_before_send.lock().unwrap() = Some((entered.clone(), resume.clone()));
        let send = rig.send(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"keyless token race","idempotency_key":key}),
        );
        tokio::pin!(send);
        tokio::select! { _=entered.notified()=>{}, result=&mut send=>panic!("finished before pause: {result}") }
        fs::write(&rig.upstream.config.credential_file, "new-unverified-token").unwrap();
        resume.notify_one();
        let result = send.await;
        assert!(
            result.to_string().contains("custody_credential_changed"),
            "{result}"
        );
        assert_eq!(
            scoped.journal.pending_count(),
            0,
            "key opt-out never creates held custody"
        );
        assert!(rig.outcomes.lock().unwrap().is_empty());
        assert_eq!(canonical(&rig.home.world, &id).await, "base");
        for file in fs::read_dir(scoped.journal.directory()).unwrap() {
            let entry: Value =
                serde_json::from_slice(&fs::read(file.unwrap().path()).unwrap()).unwrap();
            assert!(entry["idempotency_key"].is_null(), "no key invented");
            assert_eq!(entry["record_id"], id, "target identity independent of key");
        }
    }
}

fn opaque_entry(directory: &Path) -> (PathBuf, Vec<u8>) {
    let path = directory.join("70110000-0000-4000-8000-0000000000ff.json");
    let bytes = serde_json::to_vec(&json!({"version":999,"id":"70110000-0000-4000-8000-0000000000ff",
        "state":"pending","received_at":"2026-11-12T00:00:00Z","received_unix_ms":1,
        "updated_at":"2026-11-12T00:00:00Z","executor":"records_write","operation":"update_record",
        "tool":"call_executor","attempts":0,"arguments_digest":"future-digest","arguments_bytes":1,
        "arguments":{"id":"70110000-0000-4000-8000-000000000001","body_append":"future body custody"}})).unwrap();
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (path, bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_opaque_custody_never_proves_absence_in_either_direction() {
    for opaque_root in [false, true] {
        let mut rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        let (path, bytes) = if opaque_root {
            opaque_entry(rig.home.gate.journal.directory())
        } else {
            opaque_entry(rig.scoped().journal.directory())
        };
        let config = rig.home.gate.config.clone();
        rig.home.gate =
            Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
        rig.home.gate.set_kernel_v2_upstream(true);
        let denied = if opaque_root {
            rig.send("update_record",json!({"id":id,"body_append":"!","reason":"opaque predecessor","idempotency_key":"opaque-append"})).await
        } else {
            rig.merge(&id, "draft kept by caller", "opaque-merge").await
        };
        assert!(denied.to_string().contains("not_sent"), "{denied}");
        assert!(denied.to_string().contains("unreadable"), "{denied}");
        assert_eq!(
            fs::read(path).unwrap(),
            bytes,
            "opaque custody retained byte for byte"
        );
        assert!(rig.outcomes.lock().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_namespace_inventory_error_is_unknown_not_empty() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let root = rig.home.upstream.config.socket_directory.join("v2-held");
    let retained = rig
        .home
        .upstream
        .config
        .socket_directory
        .join("v2-held-preserved");
    fs::rename(&root, &retained).unwrap();
    fs::write(&root, "unreadable namespace inventory").unwrap();
    let denied = rig
        .merge(&id, "draft kept by caller", "namespace-error")
        .await;
    assert!(denied.to_string().contains("not_sent"), "{denied}");
    assert!(
        denied.to_string().contains("inventory is unreadable"),
        "{denied}"
    );
    let status = rig
        .home
        .gate
        .scoped_status(&Default::default(), Some(rig.verified.as_ref()))
        .await;
    assert_eq!(
        status["v2_ordinary_custody"]["namespace_inventory_available"],
        false
    );
    assert!(status["v2_ordinary_custody"]["retained_namespaces"].is_null());
    assert!(retained.exists());
    assert!(root.is_file());
    assert!(rig.outcomes.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn v2_existing_combined_lost_reply_maintenance_keeps_formats_and_uncertainty_separate() {
    for evidence in ["exact", "missing", "mismatched"] {
        let mut rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        rig.verified.down.store(false, Ordering::Release);
        // Let the in-call retry receive the actual unframed maintenance body,
        // rather than taking custody immediately after the dropped reply.
        rig.verified.confirm_outage.store(false, Ordering::Release);
        rig.verified
            .unframed_maintenance
            .store(true, Ordering::Release);
        rig.verified
            .missing_contract
            .store(evidence == "missing", Ordering::Release);
        rig.verified
            .wrong_contract
            .store(evidence == "mismatched", Ordering::Release);
        rig.drop_reply.store(true, Ordering::Release);
        let args = json!({"id":id,"body_append":"!","reason":"combined uncertainty","idempotency_key":"combined-maintenance"});
        let reply = rig.send("update_record", args.clone()).await;
        let scoped = rig.scoped();
        let saved: Vec<Entry> = fs::read_dir(scoped.journal.directory())
            .unwrap()
            .map(|file| serde_json::from_slice(&fs::read(file.unwrap().path()).unwrap()).unwrap())
            .collect();
        assert_eq!(saved.len(), 1, "{evidence}: {reply}");
        let entry = &saved[0];
        assert_eq!(entry.version, 6);
        assert!(entry.kernel_v2_custody.is_some());
        assert!(entry.custody_compatibility.is_none());
        assert!(!crate::node::pending_fork::previewable(entry));
        assert_eq!(entry.arguments.as_ref(), Some(&args));
        assert_eq!(entry.attempts, 2);
        assert_eq!(canonical(&rig.home.world, &id).await, "base!");
        assert_eq!(rig.outcomes.lock().unwrap().len(), 1);
        assert!(
            rig.verified.compatibility_reads.load(Ordering::Acquire) > 0,
            "v6 must consult authenticated hosted-v2 evidence even on the maybe-sent path"
        );
        if evidence == "exact" {
            assert_eq!(entry.state, EntryState::Pending);
            let pending = &reply["result"]["structuredContent"];
            assert_eq!(pending["outcome"], "accepted_pending");
            assert_eq!(pending["may_already_be_applied"], true);
            assert!(pending.get("contract_compatibility").is_none());
        } else {
            assert_eq!(entry.state, EntryState::Uncertain);
            let data = &reply["error"]["data"];
            assert_eq!(data["http_status"], 503);
            assert_eq!(
                data["outcome"], "refused",
                "refusal describes only the later attempt"
            );
            assert_eq!(data["retryable"], true);
            assert_eq!(data["retry_after_secs"], 30);
            assert_eq!(data["upstream_body"]["applied"], false);
            assert_eq!(data["node_journal"]["outcome"], "uncertain");
            assert_eq!(
                data["node_journal"]["idempotency_key"],
                "combined-maintenance"
            );
            assert_eq!(
                crate::node::session_writer::classify_send(
                    &crate::node::session_writer::GateVerdict {
                        auth_refused: false,
                        attempt: crate::node::session_writer::AttemptClass::Answered,
                        reply: Some(reply.to_string()),
                        http_status: Some(503),
                    }
                ),
                crate::node::session_writer::SendClass::Uncertain
            );
        }
        let entry_id = entry.id.clone();
        let config = rig.home.gate.config.clone();
        rig.home.gate =
            Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
        rig.home.gate.set_kernel_v2_upstream(true);
        let reloaded = rig.scoped().journal.get(&entry_id).unwrap();
        assert_eq!(reloaded.state, entry.state);
        assert_eq!(reloaded.version, 6);
        assert_eq!(reloaded.arguments, entry.arguments);
        assert!(reloaded.custody_compatibility.is_none());
        rig.verified
            .missing_contract
            .store(false, Ordering::Release);
        rig.verified.wrong_contract.store(false, Ordering::Release);
        rig.verified.down.store(false, Ordering::Release);
        if evidence != "exact" {
            let blocked = rig
                .merge(&id, "later draft kept by caller", "combined-blocked-merge")
                .await;
            assert!(blocked.to_string().contains("not_sent"), "{blocked}");
            assert_eq!(rig.home.gate.journal.pending_count(), 0);
            assert_eq!(rig.drain().await, queue::Halt::Empty);
            assert_eq!(
                rig.outcomes.lock().unwrap().len(),
                1,
                "uncertain custody never automatically replays"
            );
        } else {
            assert_eq!(rig.drain().await, queue::Halt::Empty);
            assert_eq!(canonical(&rig.home.world, &id).await, "base!");
            assert_eq!(
                rig.scoped().journal.get(&entry_id).unwrap().state,
                EntryState::Confirmed
            );
        }
    }
}

fn current_v2_contract(operation: &str) -> NodeHoldingContract {
    crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()
        .unwrap()
        .holding_contract("records_write", operation)
        .unwrap()
}

fn prose_v2_contract() -> NodeHoldingContract {
    let mut c = current_v2_contract("update_record");
    c.description["source"]["tool_description"] = json!("New guidance, same custody behaviour");
    c.description["contract_digest"] = json!("b".repeat(64));
    c
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_prose_drift_flows_at_ingress_eligibility_and_send_after_restart() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    *rig.verified.contract_override.lock().unwrap() = Some(prose_v2_contract());
    let args =
        json!({"id":id,"body_append":"!","reason":"prose drift","idempotency_key":"v6-prose"});
    let reply = rig.send("update_record", args.clone()).await;
    assert_eq!(
        reply["result"]["structuredContent"]["outcome"], "accepted_pending",
        "{reply}"
    );
    let mut before = rig.scoped().journal.pending_entries().remove(0);
    assert_eq!(before.version, 6);
    assert!(before
        .kernel_v2_custody
        .as_ref()
        .unwrap()
        .original
        .as_ref()
        .unwrap()
        .contract
        .description
        .pointer("/source/tool_description")
        .is_none());
    // An older compiled contract had different source prose and therefore digest.
    let custody = before.kernel_v2_custody.as_mut().unwrap();
    custody.contract_digest = "a".repeat(64);
    custody.original.as_mut().unwrap().contract.description["contract_digest"] =
        json!(custody.contract_digest);
    fs::write(
        rig.scoped()
            .journal
            .directory()
            .join(format!("{}.json", before.id)),
        serde_json::to_vec(&before).unwrap(),
    )
    .unwrap();
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    let entry = rig.scoped().journal.get(&before.id).unwrap();
    assert!(rig.scoped().compatible_entry(&entry));
    assert!(!crate::node::pending_fork::previewable(&entry));
    assert_eq!(entry.arguments.as_ref(), Some(&args));
    assert_eq!(entry.arguments_digest, before.arguments_digest);
    assert_eq!(entry.intent_digest, before.intent_digest);
    assert_eq!(entry.kernel_v2_custody, before.kernel_v2_custody);
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(
        rig.scoped().journal.get(&before.id).unwrap().state,
        EntryState::Confirmed
    );
    assert_eq!(
        rig.send("update_record", args).await["result"]["isError"],
        false
    );
    assert_eq!(rig.outcomes.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_prose_drift_maybe_sent_keeps_original_key_and_settles_once() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    *rig.verified.contract_override.lock().unwrap() = Some(prose_v2_contract());
    rig.verified.down.store(false, Ordering::Release);
    rig.drop_reply.store(true, Ordering::Release);
    let args = json!({"id":id,"body_append":"!","reason":"lost reply","idempotency_key":"v6-lost"});
    let reply = rig.send("update_record", args.clone()).await;
    assert_eq!(
        reply["result"]["structuredContent"]["outcome"], "accepted_pending",
        "{reply}"
    );
    let entry = rig.scoped().journal.pending_entries().remove(0);
    assert!(entry.maybe_applied);
    assert_eq!(entry.arguments.as_ref(), Some(&args));
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(
        rig.scoped().journal.get(&entry.id).unwrap().state,
        EntryState::Confirmed
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_refusals_keep_content_visible_and_reversion_self_clears() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let other = record(&rig.home.world, "other").await;
    let args = json!({"id":id,"body_append":"!","reason":"boundary","idempotency_key":"v6-first"});
    rig.send("update_record", args.clone()).await;
    rig.send(
        "update_record",
        json!({"id":other,"body_append":"?","reason":"follower","idempotency_key":"v6-next"}),
    )
    .await;
    let first = rig.scoped().journal.pending_entries().remove(0);
    rig.verified.down.store(false, Ordering::Release);
    let sends = rig.wire_protocols.lock().unwrap().len();
    for (pointer, value) in [
        ("/input_schema/description", json!("Changed schema prose")),
        (
            "/source/selector",
            json!({"field":"action","value":"other"}),
        ),
        ("/contract_version", json!("future")),
        ("/unknown", json!(true)),
    ] {
        let mut contract = current_v2_contract("update_record");
        let field = pointer.strip_prefix('/').unwrap();
        if field.contains('/') {
            let (a, b) = field.split_once('/').unwrap();
            contract.description[a][b] = value;
        } else {
            contract.description[field] = value;
        }
        *rig.verified.contract_override.lock().unwrap() = Some(contract);
        assert_eq!(rig.drain().await, queue::Halt::Local, "{pointer}");
        assert_eq!(
            rig.wire_protocols.lock().unwrap().len(),
            sends,
            "no HTTP dispatch for {pointer}"
        );
        assert!(rig.outcomes.lock().unwrap().is_empty());
        let refused = rig.send("update_record",json!({"id":id,"body_append":"kept by caller","reason":"ingress boundary","idempotency_key":"new-incompatible"})).await;
        assert!(refused.to_string().contains("not_sent"), "{refused}");
        assert_eq!(rig.scoped().journal.pending_count(), 2);
    }
    for (field, value) in [
        ("access", json!("read")),
        ("requires_acceptance", json!(true)),
        ("plan_required", json!(true)),
        ("direct_execution_enabled", json!(false)),
    ] {
        let mut contract = current_v2_contract("update_record");
        contract.catalog[field] = value.clone();
        if matches!(field, "plan_required" | "direct_execution_enabled") {
            contract.description["prototype"][field] = value;
        }
        *rig.verified.contract_override.lock().unwrap() = Some(contract);
        assert_eq!(rig.drain().await, queue::Halt::Local, "{field}");
        assert_eq!(
            rig.wire_protocols.lock().unwrap().len(),
            sends,
            "no HTTP dispatch for {field}"
        );
        assert!(
            rig.outcomes.lock().unwrap().is_empty(),
            "unchanged exact digest must not bypass policy"
        );
        let refused = rig.send("update_record",json!({"id":id,"body_append":"kept by caller","reason":"policy boundary","idempotency_key":"new-policy"})).await;
        assert!(refused.to_string().contains("not_sent"), "{refused}");
        assert_eq!(rig.scoped().journal.pending_count(), 2);
    }
    for malformed in [json!("invalid source"), Value::Null] {
        let mut contract = current_v2_contract("update_record");
        contract.description["source"] = malformed;
        *rig.verified.contract_override.lock().unwrap() = Some(contract);
        assert_eq!(rig.drain().await, queue::Halt::Local);
    }
    let repeat = rig.send("update_record", args).await;
    assert_eq!(
        repeat["result"]["structuredContent"]["status"], "needs_you",
        "{repeat}"
    );
    assert!(repeat.to_string().contains("will be sent when it can be"));
    assert!(repeat.to_string().contains("discard this one first"));
    let scoped = rig.scoped();
    assert_eq!(
        scoped.journal.get(&first.id).unwrap().arguments,
        first.arguments
    );
    scoped.journal.prune();
    let status = rig
        .home
        .gate
        .scoped_status(
            &StatusFilter {
                limit: 10,
                ..Default::default()
            },
            Some(rig.verified.as_ref()),
        )
        .await;
    let rows = &status["v2_ordinary_custody"]["status"]["held_writes"]["writes"];
    assert_eq!(rows[0]["state"], "needs_you", "{status}");
    assert_eq!(rows[1]["state"], "waiting_behind", "{status}");
    assert_eq!(rows[1]["waiting_for"], first.id);
    assert_eq!(
        canonical(&rig.home.world, &id).await,
        "base",
        "read remains usable"
    );
    assert_eq!(scoped.journal.waiting_summary()["waiting"], 2);
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    let scoped = rig.scoped();
    assert_eq!(
        scoped.journal.get(&first.id).unwrap().state,
        EntryState::Pending
    );
    assert!(scoped
        .journal
        .get(&first.id)
        .unwrap()
        .compatibility_block
        .is_some());
    rig.verified.missing_contract.store(true, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(
        scoped.journal.get(&first.id).unwrap().compatibility_block,
        Some(crate::node::journal::CompatibilityBlock::EvidenceMissing)
    );
    rig.verified
        .missing_contract
        .store(false, Ordering::Release);
    *rig.verified.contract_override.lock().unwrap() = None;
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(canonical(&rig.home.world, &other).await, "other?");
    let done = scoped.journal.get(&first.id).unwrap();
    assert!(done.compatibility_block.is_none() && done.waiting_for.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_original_contract_survives_node_and_hosted_agreeing_on_new_contract() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send("update_record", json!({"id":id,"body_append":"!","reason":"older contract","idempotency_key":"v6-original"})).await;
    let mut entry = rig.scoped().journal.pending_entries().remove(0);
    // Model an entry frozen by an older node. Current node and hosted both use B.
    let c = entry.kernel_v2_custody.as_mut().unwrap();
    c.contract_digest = "a".repeat(64);
    let old = &mut c.original.as_mut().unwrap().contract;
    old.description["contract_digest"] = json!(c.contract_digest);
    old.description["contract_version"] = json!("original-contract-A");
    let path = rig
        .scoped()
        .journal
        .directory()
        .join(format!("{}.json", entry.id));
    fs::write(path, serde_json::to_vec(&entry).unwrap()).unwrap();
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert!(rig.outcomes.lock().unwrap().is_empty());
    assert_eq!(
        rig.scoped().journal.get(&entry.id).unwrap().arguments,
        entry.arguments
    );
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_all_binding_boundaries_refuse_and_keep_content_private() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "private").await;
    rig.send(
        "update_record",
        json!({"id":id,"body_append":"secret","reason":"binding","idempotency_key":"v6-private"}),
    )
    .await;
    let original = rig.binding();
    let scoped = rig.scoped();
    for field in [
        "account_id",
        "database_id",
        "origin_database_id",
        "history_lineage",
        "resource_origin",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = json!("changed");
        *rig.verified.binding.lock().unwrap() = Some(serde_json::from_value(value).unwrap());
        assert_eq!(
            scoped
                .drain(&rig.upstream, Some(rig.verified.as_ref()), None, None)
                .await,
            queue::Halt::Local
        );
        let status = rig
            .home
            .gate
            .scoped_status(&Default::default(), Some(rig.verified.as_ref()))
            .await;
        assert!(!status.to_string().contains("v6-private"), "{field}");
        assert!(!status.to_string().contains(&id), "{field}");
        assert!(rig.outcomes.lock().unwrap().is_empty());
    }
    *rig.verified.binding.lock().unwrap() = Some(original);
    assert_eq!(scoped.journal.pending_count(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_replay_compares_the_protocol_it_actually_sends() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let old_protocol = crate::mcp::LEGACY_SUPPORTED_PROTOCOL_VERSIONS[0];
    rig.verified
        .protocol_contracts
        .lock()
        .unwrap()
        .insert(old_protocol.into(), prose_v2_contract());
    let reply = rig
        .send_protocol(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"protocol","idempotency_key":"v6-protocol"}),
            Some(old_protocol),
        )
        .await;
    assert_eq!(
        reply["result"]["structuredContent"]["outcome"], "accepted_pending",
        "{reply}"
    );
    let mut incompatible = current_v2_contract("update_record");
    incompatible.description["contract_version"] = json!("current-protocol-incompatible");
    rig.verified
        .protocol_contracts
        .lock()
        .unwrap()
        .insert(crate::mcp::PROTOCOL_VERSION.into(), incompatible);
    rig.verified.down.store(false, Ordering::Release);
    rig.verified.protocols.lock().unwrap().clear();
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert!(rig.outcomes.lock().unwrap().is_empty());
    assert_eq!(
        *rig.verified.protocols.lock().unwrap(),
        vec![None],
        "queue discovery defaults to current protocol, never stored legacy evidence"
    );
    rig.verified
        .protocol_contracts
        .lock()
        .unwrap()
        .remove(crate::mcp::PROTOCOL_VERSION);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(
        rig.wire_protocols.lock().unwrap().last(),
        Some(&json!(crate::mcp::PROTOCOL_VERSION))
    );
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_resolution_keeps_original_acknowledged_and_requires_new_key() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let args = json!({"id":id,"body_append":"!","reason":"resolve","idempotency_key":"v6-resolve"});
    rig.send("update_record", args.clone()).await;
    let scoped = rig.scoped();
    let original = scoped.journal.pending_entries().remove(0);
    let other = record(&rig.home.world, "other").await;
    rig.send(
        "attach_text",
        json!({"record_id":other,"text":"kept","name":"follower.txt","idempotency_key":"resolve-follower"}),
    )
    .await;
    let mut incompatible = current_v2_contract("update_record");
    incompatible.description["contract_version"] = json!("changed");
    *rig.verified.contract_override.lock().unwrap() = Some(incompatible);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    let follower = scoped.journal.pending_entries().pop().unwrap();
    assert_eq!(follower.waiting_for.as_deref(), Some(original.id.as_str()));
    let acknowledged = scoped
        .journal
        .operator_decision(
            &original.id,
            Some("superseded"),
            "reviewed before resubmitting",
            unsafe { libc::geteuid() },
            None,
        )
        .unwrap();
    assert_eq!(acknowledged.state, EntryState::Acknowledged);
    assert_eq!(acknowledged.arguments, original.arguments);
    assert!(scoped
        .journal
        .get(&follower.id)
        .unwrap()
        .waiting_for
        .is_none());
    scoped.journal.prune();
    *rig.verified.contract_override.lock().unwrap() = None;
    rig.verified.down.store(false, Ordering::Release);
    let repeat = rig.send("update_record", args.clone()).await;
    assert_eq!(
        repeat["result"]["structuredContent"]["outcome"], "acknowledged",
        "{repeat}"
    );
    assert!(rig.outcomes.lock().unwrap().is_empty());
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    let mut fresh = args;
    fresh["idempotency_key"] = json!("v6-resolved-new-key");
    let reply = rig.send("update_record", fresh).await;
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(
        scoped.journal.get(&original.id).unwrap().state,
        EntryState::Acknowledged
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_legacy_drift_count_excludes_missing_evidence_and_other_boundaries() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send("update_record",json!({"id":id,"body_append":"!","reason":"legacy backlog","idempotency_key":"legacy-backlog"})).await;
    let mut entry = rig.scoped().journal.pending_entries().remove(0);
    entry.version = 3;
    entry.kernel_v2_custody.as_mut().unwrap().original = None;
    let directory = rig.scoped().journal.directory().to_owned();
    fs::write(
        directory.join(format!("{}.json", entry.id)),
        serde_json::to_vec(&entry).unwrap(),
    )
    .unwrap();
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    rig.verified.wrong_contract.store(true, Ordering::Release);
    let status = rig
        .home
        .gate
        .scoped_status(&Default::default(), Some(rig.verified.as_ref()))
        .await;
    assert_eq!(
        status["v2_ordinary_custody"]["legacy_v3_digest_drift"], 1,
        "{status}"
    );
    assert_eq!(rig.drain().await, queue::Halt::Local);
    rig.verified.missing_contract.store(true, Ordering::Release);
    let status = rig
        .home
        .gate
        .scoped_status(&Default::default(), Some(rig.verified.as_ref()))
        .await;
    assert_eq!(status["v2_ordinary_custody"]["legacy_v3_digest_drift"], 0);
    rig.verified
        .missing_contract
        .store(false, Ordering::Release);
    rig.verified.wrong_contract.store(false, Ordering::Release);
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_rollback_retains_sent_and_pending_files_blocks_all_appends_until_roll_forward() {
    for state in [EntryState::Sent, EntryState::Pending] {
        let rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        let other = record(&rig.home.world, "other").await;
        rig.send(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"rollback","idempotency_key":"v6-rollback"}),
        )
        .await;
        let scoped = rig.scoped();
        let mut entry = scoped.journal.pending_entries().remove(0);
        entry.state = state;
        let path = scoped
            .journal
            .directory()
            .join(format!("{}.json", entry.id));
        let bytes = serde_json::to_vec(&entry).unwrap();
        fs::write(&path, &bytes).unwrap();
        let empty = tempfile::tempdir().unwrap();
        let mut older =
            WriteGate::open_scoped(empty.path(), scoped.config.clone(), Some(rig.binding()))
                .unwrap();
        // Simulate the previous reader's version ceiling, without running an old binary.
        older.journal = Arc::new(
            crate::node::journal::Journal::open_bound_with_reader(
                scoped.journal.directory().parent().unwrap(),
                Duration::ZERO,
                Duration::ZERO,
                Some(rig.binding()),
                crate::node::journal::read_before_v6,
            )
            .unwrap(),
        );
        older.set_kernel_v2_upstream(true);
        assert!(scoped.status(&Default::default())["rollback"]["warning"]
            .as_str()
            .unwrap()
            .contains("version 6"));
        assert!(older.journal.has_opaque_custody());
        assert_eq!(
            older
                .drain(&rig.upstream, Some(rig.verified.as_ref()), None, None)
                .await,
            queue::Halt::Empty
        );
        older.journal.prune();
        let message = tool_call(
            12,
            "call_executor",
            json!({"executor":"records_write","operation":"update_record","arguments":{
            "id":other,"body_append":"?","reason":"unrelated record must still block","idempotency_key":"rollback-new"}}),
        );
        let body = message.to_string();
        let caller = Caller::new(None, Cancel::new());
        let report = older
            .forward_scoped(
                &rig.upstream,
                &WriteRequest {
                    body: &body,
                    message: &message,
                    revision: None,
                    caller: &caller,
                    outage: Some(rig.verified.as_ref()),
                    no_hold: false,
                },
                true,
            )
            .await;
        assert!(report.reply.unwrap().contains("unreadable"));
        assert!(rig.outcomes.lock().unwrap().is_empty());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        // Roll forward reads Pending unchanged; Sent becomes caller-owned Uncertain.
        let newer = crate::node::journal::Journal::open_bound(
            scoped.journal.directory().parent().unwrap(),
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Some(rig.binding()),
        )
        .unwrap();
        let restored = newer.get(&entry.id).unwrap();
        assert_eq!(restored.arguments, entry.arguments);
        assert_eq!(
            restored.state,
            if state == EntryState::Sent {
                EntryState::Uncertain
            } else {
                EntryState::Pending
            }
        );
        assert_eq!(canonical(&rig.home.world, &other).await, "other");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_prose_never_makes_uncertain_keyless_writes_automatically_replayable() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.verified.down.store(false, Ordering::Release);
    rig.drop_reply.store(true, Ordering::Release);
    *rig.verified.contract_override.lock().unwrap() = Some(prose_v2_contract());
    let reply = rig
        .send(
            "update_record",
            json!({"id":id,"body_append":"!","reason":"keyless lost reply","idempotency_key":null}),
        )
        .await;
    assert_eq!(reply["error"]["data"]["outcome"], "unknown", "{reply}");
    let retained: Vec<Entry> = fs::read_dir(rig.scoped().journal.directory())
        .unwrap()
        .map(|file| serde_json::from_slice(&fs::read(file.unwrap().path()).unwrap()).unwrap())
        .collect();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].state, EntryState::Uncertain);
    assert!(
        retained[0].idempotency_key.is_none(),
        "never invent a key for uncertain unkeyed work"
    );
    assert!(retained[0].arguments.is_some());
    assert_eq!(rig.scoped().journal.pending_count(), 0);
    let observed_after_attempt = canonical(&rig.home.world, &id).await;
    let attempts = rig.wire_protocols.lock().unwrap().len();
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(
        rig.wire_protocols.lock().unwrap().len(),
        attempts,
        "uncertain unkeyed work is never dispatched again"
    );
    assert_eq!(
        canonical(&rig.home.world, &id).await,
        observed_after_attempt
    );
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_unsupported_app_attribution_is_not_held_or_dispatched() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let mut message = tool_call(
        13,
        "call_executor",
        json!({"executor":"records_write","operation":"update_record","arguments":{
        "id":id,"body_append":"!","reason":"app custody forbidden","idempotency_key":"v6-app"}}),
    );
    message["params"]["_meta"] = json!({"native/app":"docs@1; install=evt"});
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let report = rig
        .home
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: Some(rig.verified.as_ref()),
                no_hold: false,
            },
            true,
        )
        .await;
    assert!(report.reply.unwrap().contains("proof unavailable"));
    assert_eq!(rig.scoped().journal.pending_count(), 0);
    assert!(rig.outcomes.lock().unwrap().is_empty());
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

// Histories are append-only: never edit or replace an earlier entry. Regenerate
// after declaring a contract_version/schema change with:
// NATIVE_UPDATE_V2_CUSTODY_HISTORY=1 RUST_MIN_STACK=67108864 cargo test -p native-ce --lib --features v2-kernel-probe v2_custody_contract_change_guard
// The same validator runs before appending, so regeneration cannot bless an
// unversioned non-schema change. Hidden semantic changes still need review.
fn validate_custody_contract_history(
    operation: &str,
    history: &[Value],
) -> std::result::Result<(), String> {
    if history.is_empty() {
        return Err(format!("{operation}: empty contract history"));
    }
    for snapshot in history {
        if snapshot.as_object().is_none_or(|o| o.len() != 2) {
            return Err(format!("{operation}: malformed history snapshot"));
        }
        let mut contract: NodeHoldingContract =
            serde_json::from_value(snapshot.clone()).map_err(|e| e.to_string())?;
        if contract.description.get("contract_digest").is_some() {
            return Err(format!("{operation}: history must omit the global digest"));
        }
        let digest = "f".repeat(64);
        contract.description["contract_digest"] = json!(digest);
        if !contract.valid_evidence("records_write", operation, &digest) {
            return Err(format!("{operation}: invalid contract history evidence"));
        }
    }
    for pair in history.windows(2) {
        let non_schema = |snapshot: &Value| {
            let mut value = snapshot.clone();
            let description = value["description"]
                .as_object_mut()
                .expect("validated description");
            description.remove("input_schema");
            description.remove("contract_version");
            value
        };
        if non_schema(&pair[0]) != non_schema(&pair[1])
            && pair[0]["description"]["contract_version"]
                == pair[1]["description"]["contract_version"]
            && pair[0]["description"]["input_schema"] == pair[1]["description"]["input_schema"]
        {
            return Err(format!(
                "{operation}: behaviour/policy changed without a contract_version or schema change"
            ));
        }
    }
    Ok(())
}

#[test]
fn v2_custody_contract_change_guard() {
    let contracts =
        crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap();
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/node/gate/v2-custody-contracts.json");
    let mut histories: std::collections::BTreeMap<String, Vec<Value>> =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let regenerate = std::env::var("NATIVE_UPDATE_V2_CUSTODY_HISTORY").as_deref() == Ok("1");
    let mut changed = false;
    for operation in ["update_record", "manage_links.add", "attach_text"] {
        let mut c = contracts
            .holding_contract("records_write", operation)
            .unwrap()
            .for_custody()
            .unwrap();
        assert!(
            serde_json::to_vec(&crate::node::journal::OriginalContract {
                rule: 1,
                contract: c.clone()
            })
            .unwrap()
            .len()
                <= crate::node::journal::MAX_CONTRACT_EVIDENCE_BYTES as usize,
            "hosted-v2 {operation} evidence exceeds its reserved journal budget"
        );
        c.description
            .as_object_mut()
            .unwrap()
            .remove("contract_digest");
        let current = serde_json::to_value(c).unwrap();
        let history = histories
            .get_mut(operation)
            .expect("every held operation has a history");
        validate_custody_contract_history(operation, history).unwrap();
        if history.last() != Some(&current) {
            let mut appended = history.clone();
            appended.push(current);
            validate_custody_contract_history(operation, &appended).unwrap();
            assert!(regenerate, "{operation}: append the declared contract change with NATIVE_UPDATE_V2_CUSTODY_HISTORY=1; never replace old history");
            *history = appended;
            changed = true;
        }
    }
    assert_eq!(
        histories.len(),
        3,
        "unexpected operation histories must be reviewed"
    );
    if changed {
        let mut bytes = serde_json::to_vec_pretty(&histories).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    }
}

#[test]
fn v2_custody_contract_history_rejects_unversioned_append() {
    let mut original = current_v2_contract("update_record").for_custody().unwrap();
    original
        .description
        .as_object_mut()
        .unwrap()
        .remove("contract_digest");
    let original = serde_json::to_value(original).unwrap();
    let mut changed = original.clone();
    changed["catalog"]["requires_acceptance"] = json!(true);
    assert!(validate_custody_contract_history(
        "update_record",
        &[original.clone(), changed.clone()]
    )
    .is_err());
    let mut schema_changed = changed.clone();
    schema_changed["description"]["input_schema"]["description"] =
        json!("Declared behaviour change");
    assert!(validate_custody_contract_history(
        "update_record",
        &[original.clone(), schema_changed]
    )
    .is_ok());
    changed["description"]["contract_version"] = json!("native.operation-contract.future");
    assert!(validate_custody_contract_history(
        "update_record",
        &[original.clone(), changed.clone()]
    )
    .is_ok());
    // An invalid historical edge remains invalid even when the current tail is valid.
    let mut invalid_middle = changed.clone();
    invalid_middle["description"]["contract_version"] =
        original["description"]["contract_version"].clone();
    assert!(validate_custody_contract_history(
        "update_record",
        &[original, invalid_middle, changed]
    )
    .is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_waiting_marker_failure_never_undoes_durable_hold() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"head","idempotency_key":"marker-head"}),
    )
    .await;
    let scoped = rig.scoped();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *scoped.pause_before_send.lock().unwrap() = Some((entered.clone(), release.clone()));
    let (reply, sends) = tokio::join!(
        rig.send("attach_text", json!({"record_id":id,"text":"kept","name":"behind.txt","idempotency_key":"marker-follower"})),
        async {
            entered.notified().await;
            // Backlog admission has completed and begin(Sent) is durable.
            // Introduce a blocked head before hold decorates the follower.
            let head = scoped.journal.pending_entries().remove(0);
            scoped.journal.contract_block(&head, Some(crate::node::journal::CompatibilityBlock::Incompatible)).unwrap();
            let sends = rig.wire_protocols.lock().unwrap().len();
            // Pending succeeds, then saving its waiting marker fails once.
            scoped.journal.fail_after.store(1, Ordering::SeqCst);
            release.notify_one();
            sends
        }
    );
    *scoped.pause_before_send.lock().unwrap() = None;
    assert_eq!(scoped.journal.fail_after.load(Ordering::SeqCst), -1);
    assert_eq!(
        reply["result"]["structuredContent"]["outcome"], "accepted_pending",
        "{reply}"
    );
    let held = scoped.journal.pending_entries().pop().unwrap();
    assert_eq!(held.state, EntryState::Pending);
    assert_eq!(held.arguments.as_ref().unwrap()["text"], "kept");
    assert!(!held.maybe_applied);
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    // The maybe-sent call site uses this same hold() result: preserve Pending
    // and uncertainty rather than falling through to finish().
    scoped
        .journal
        .update(&held.id, |e| e.state = EntryState::Uncertain)
        .unwrap();
    scoped.journal.fail_after.store(1, Ordering::SeqCst);
    let reply = scoped
        .hold(
            &held,
            HoldReason::HostedUnreachable,
            true,
            Some(HoldContract::V2),
            Some(&json!(11)),
            true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(scoped.journal.fail_after.load(Ordering::SeqCst), -1);
    assert!(reply.contains("accepted_pending"));
    let held = scoped.journal.get(&held.id).unwrap();
    assert_eq!(held.state, EntryState::Pending);
    assert!(held.maybe_applied);
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_legacy_prose_only_drift_still_refuses_without_dispatch() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"legacy","idempotency_key":"legacy-prose"}),
    )
    .await;
    let mut entry = rig.scoped().journal.pending_entries().remove(0);
    entry.version = 3;
    entry.kernel_v2_custody.as_mut().unwrap().original = None;
    fs::write(
        rig.scoped()
            .journal
            .directory()
            .join(format!("{}.json", entry.id)),
        serde_json::to_vec(&entry).unwrap(),
    )
    .unwrap();
    rig.home.gate = Arc::new(
        WriteGate::open(
            &rig.home.upstream.config.socket_directory,
            rig.home.gate.config.clone(),
        )
        .unwrap(),
    );
    rig.home.gate.set_kernel_v2_upstream(true);
    *rig.verified.contract_override.lock().unwrap() = Some(prose_v2_contract());
    rig.verified.down.store(false, Ordering::Release);
    let sends = rig.wire_protocols.lock().unwrap().len();
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(
        rig.scoped()
            .journal
            .get(&entry.id)
            .unwrap()
            .compatibility_block,
        Some(crate::node::journal::CompatibilityBlock::LegacyDigestDrift)
    );
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

/// Second upgrade PR (d): a legacy v3 entry stays exact-match-only across
/// restart — prose-only drift still refuses without dispatch.
#[tokio::test(flavor = "current_thread")]
async fn upgrade_legacy_v3_exact_match_only_after_restart_prose_drift_still_refused() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"legacy","idempotency_key":"legacy-prose-restart"}),
    )
    .await;
    let seeded = rig.scoped().journal.pending_entries().remove(0);
    let entry_id = seeded.id.clone();
    let mut legacy = seeded;
    legacy.version = 3;
    legacy.kernel_v2_custody.as_mut().unwrap().original = None;
    // Clean shutdown while nothing is in flight: a restart alone must not
    // rewrite the file (`begin_queue_send` sets `in_flight` and bumps
    // `attempts`; only the drain below may rewrite it).
    legacy.in_flight = false;
    let path = rig
        .scoped()
        .journal
        .directory()
        .join(format!("{entry_id}.json"));
    let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
    fs::write(&path, &legacy_bytes).unwrap();
    let legacy_value: Value = serde_json::from_slice(&legacy_bytes).unwrap();
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    assert_eq!(
        fs::read(&path).unwrap(),
        legacy_bytes,
        "restart alone must not rewrite a Pending v3 file"
    );
    let recovered = rig.scoped().journal.get(&entry_id).unwrap();
    assert_eq!(recovered.version, 3);
    assert_eq!(recovered.state, EntryState::Pending);
    assert_eq!(recovered.kernel_v2_custody, legacy.kernel_v2_custody);
    *rig.verified.contract_override.lock().unwrap() = Some(prose_v2_contract());
    rig.verified.down.store(false, Ordering::Release);
    let sends = rig.wire_protocols.lock().unwrap().len();
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(
        rig.scoped()
            .journal
            .get(&entry_id)
            .unwrap()
            .compatibility_block,
        Some(crate::node::journal::CompatibilityBlock::LegacyDigestDrift)
    );
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    // The drain persists its verdict; everything else about the entry is
    // unchanged. Volatile fields are excluded from the comparison.
    let mut on_disk: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["compatibility_block"], "legacy_digest_drift");
    let mut expected = legacy_value;
    for field in [
        "updated_at",
        "in_flight",
        "attempts",
        "maybe_applied",
        "compatibility_block",
    ] {
        on_disk.as_object_mut().unwrap().remove(field);
        expected.as_object_mut().unwrap().remove(field);
    }
    assert_eq!(on_disk, expected);
    // A second restart still refuses with no new send.
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(
        rig.scoped()
            .journal
            .get(&entry_id)
            .unwrap()
            .compatibility_block,
        Some(crate::node::journal::CompatibilityBlock::LegacyDigestDrift)
    );
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_custody_engine_mismatch_refuses_without_dispatch() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"engine","idempotency_key":"engine-mismatch"}),
    )
    .await;
    let scoped = rig.scoped();
    let mut entry = scoped.journal.pending_entries().remove(0);
    entry.kernel_v2_custody.as_mut().unwrap().engine = "different-engine".into();
    let sends = rig.wire_protocols.lock().unwrap().len();
    assert!(matches!(
        scoped
            .send_once(&rig.upstream, Some(rig.verified.as_ref()), &entry, None)
            .await,
        Err(queue::Halt::Local)
    ));
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

#[tokio::test(flavor = "current_thread")]
async fn v2_compat_missing_discovery_waits_but_removed_operation_can_be_reconciled() {
    use crate::node::journal::CompatibilityBlock;
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    rig.send(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"missing","idempotency_key":"absent-head"}),
    )
    .await;
    rig.send(
        "attach_text",
        json!({"record_id":id,"text":"kept","name":"follower.txt","idempotency_key":"absent-follower"}),
    )
    .await;
    let scoped = rig.scoped();
    let mut head = scoped.journal.pending_entries().remove(0);
    head.maybe_applied = true;
    scoped
        .journal
        .update(&head.id, |e| e.maybe_applied = true)
        .unwrap();
    let follower = scoped.journal.pending_entries().pop().unwrap();
    let sends = rig.wire_protocols.lock().unwrap().len();
    rig.verified.missing_contract.store(true, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(
        scoped.journal.get(&head.id).unwrap().compatibility_block,
        Some(CompatibilityBlock::EvidenceMissing)
    );
    assert!(scoped
        .journal
        .operator_decision(
            &head.id,
            Some("superseded"),
            "history checked",
            unsafe { libc::geteuid() },
            None
        )
        .is_err());
    assert!(scoped
        .journal
        .get(&follower.id)
        .unwrap()
        .waiting_for
        .is_none());
    rig.verified
        .missing_contract
        .store(false, Ordering::Release);
    rig.verified.operation_absent.store(true, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert_eq!(
        scoped.journal.get(&head.id).unwrap().compatibility_block,
        Some(CompatibilityBlock::Incompatible)
    );
    assert_eq!(
        scoped
            .journal
            .get(&follower.id)
            .unwrap()
            .waiting_for
            .as_deref(),
        Some(head.id.as_str())
    );
    let repeat = rig
        .send("update_record", head.arguments.clone().unwrap())
        .await;
    assert_eq!(
        repeat["result"]["structuredContent"]["status"], "needs_you",
        "{repeat}"
    );
    assert!(repeat.to_string().contains("may already have gone through"));
    let ack = scoped
        .journal
        .operator_decision(
            &head.id,
            Some("not_applied"),
            "canonical history checked",
            unsafe { libc::geteuid() },
            None,
        )
        .unwrap();
    assert_eq!(ack.state, EntryState::Acknowledged);
    assert_eq!(ack.arguments, head.arguments);
    assert!(ack.maybe_applied);
    assert!(scoped
        .journal
        .get(&follower.id)
        .unwrap()
        .waiting_for
        .is_none());
    scoped.journal.prune();
    assert!(scoped.journal.get(&head.id).is_some());
    assert_eq!(rig.wire_protocols.lock().unwrap().len(), sends);
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

// Format fixtures use the real provider bytes and the installed facade. They
// exercise custody/order, not a substitute for installed-node ACK qualification.
fn installed_binding(scope: CustodyBinding) -> crate::fork::working_v2::WorkingBinding {
    crate::fork::working_v2::WorkingBinding {
        account_id: scope.account_id,
        database_id: scope.database_id,
        origin_database_id: scope.origin_database_id,
        history_lineage: scope.history_lineage,
        resource_origin: scope.resource_origin,
        install_id: scope.install_id.clone(),
    }
}
fn installed_proposal(
    id: &str,
    key: &str,
) -> crate::mcp::kernel_v2::writes::replay::ReplayProposal {
    crate::mcp::kernel_v2::writes::replay::ReplayProposal::from_original(
        "update_record",
        json!({"id":id,"body_append":"!","reason":"Installed custody race fixture","idempotency_key":key}),
        Some(key.into()),
        &Default::default(),
    ).unwrap()
}
#[tokio::test(flavor = "current_thread")]
async fn installed_working_enrollment_rechecks_mixed_body_admission_after_preparation() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    let proposal = installed_proposal(&id, "prepared-working");
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    // The early contract/admission check passes, then async preparation yields.
    drop(
        scoped
            .working_admission(proposal.tool(), proposal.args(), &digest)
            .unwrap(),
    );
    let (entered, prepared) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    let pending = tokio::spawn(async move {
        entered.send(()).unwrap();
        resume.await.unwrap();
        shared
            .persist_original(
                "format-actor".into(),
                &proposal,
                crate::node::working_v2::FirstPartyIdentity::FirstParty,
                digest,
            )
            .await
    });
    prepared.await.unwrap();
    let merge = rig
        .merge(&id, "merge wins admission", "merge-during-working-prepare")
        .await;
    assert!(merge.to_string().contains("saved_on_device"), "{merge}");
    release.send(()).unwrap();
    assert!(matches!(pending.await.unwrap(), Err(Error::Conflict(_))));
    assert_eq!(
        scoped.journal.pending_count(),
        0,
        "no incompatible v7 ticket can reach ACK"
    );
    assert_eq!(canonical(&rig.home.world, &id).await, "base");

    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    shared
        .persist_original(
            "format-actor".into(),
            &installed_proposal(&id, "working-wins"),
            crate::node::working_v2::FirstPartyIdentity::FirstParty,
            digest,
        )
        .await
        .unwrap();
    let merge = rig
        .merge(
            &id,
            "cannot overtake installed custody",
            "merge-after-working",
        )
        .await;
    assert!(merge.to_string().contains("not_sent"), "{merge}");
    assert!(!merge.to_string().contains("saved_on_device"), "{merge}");
    assert_eq!(scoped.journal.pending_count(), 1);
}

// Reverse enrollment: a later typed body merge cannot overtake ANY admitted
// format9 operation on its primary or secondary record. This is a format/order
// fixture, not a Native W application or canonical-verdict authority proof.
#[tokio::test(flavor = "current_thread")]
async fn installed_working_records_reverse_barrier_covers_archive_links_and_secondary_targets() {
    use crate::mcp::kernel_v2::writes::replay::RecordOperation as Op;
    for operation in [Op::Archive, Op::LinkAdd, Op::LinkRemove] {
        let rig = ExistingRig::new().await;
        let source = record(&rig.home.world, "source base").await;
        let target = record(&rig.home.world, "target base").await;
        let unrelated = record(&rig.home.world, "unrelated base").await;
        let scoped = rig.scoped();
        let shared = scoped
            .working_journal(installed_binding(rig.binding()))
            .unwrap();
        let wire = if operation == Op::Archive {
            json!({"id":source,"archived":true,"reason":"earlier archive custody","idempotency_key":"earlier-family"})
        } else {
            json!({"source_id":source,"target_id":target,"relationship":"mentions","idempotency_key":"earlier-family"})
        };
        let digest = scoped
            .hold_contracts(operation.catalog_operation())
            .digest(operation.executor(), operation.catalog_operation())
            .unwrap()
            .to_owned();
        let ticket = shared
            .fixture_record_original("format-actor", operation, wire, digest)
            .await
            .unwrap();
        let retained = scoped.journal.get(ticket.id()).unwrap();
        let before = serde_json::to_value(&retained).unwrap();
        for blocked in if operation == Op::Archive {
            vec![&source]
        } else {
            vec![&source, &target]
        } {
            let refused = rig
                .merge(
                    blocked,
                    "must not overtake earlier record custody",
                    &format!("merge-after-{}", blocked),
                )
                .await;
            assert!(
                refused.to_string().contains("not_sent"),
                "{operation:?}: {refused}"
            );
            assert!(
                !refused.to_string().contains("saved_on_device"),
                "{refused}"
            );
            assert_eq!(
                serde_json::to_value(scoped.journal.get(ticket.id()).unwrap()).unwrap(),
                before
            );
        }
        let allowed = rig
            .merge(
                &unrelated,
                "unrelated editing continues",
                "unrelated-family-merge",
            )
            .await;
        assert!(allowed.to_string().contains("saved_on_device"), "{allowed}");
        assert_eq!(canonical(&rig.home.world, &source).await, "source base");
        // Explicit test-only terminal outcome releases the ordering barrier;
        // it retains the original bytes, and is not a runtime verdict producer.
        shared
            .fixture_accepted_verdict(ticket.id(), json!({"format_fixture":true}))
            .await;
        let after = rig
            .merge(
                &source,
                "terminal custody no longer blocks",
                "merge-after-terminal-family",
            )
            .await;
        assert!(after.to_string().contains("saved_on_device"), "{after}");
        assert_eq!(
            scoped.journal.get(ticket.id()).unwrap().arguments,
            retained.arguments
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn installed_working_operator_decisions_refuse_while_publication_fence_is_held() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    let ticket = shared
        .persist_original(
            "format-actor".into(),
            &installed_proposal(&id, "operator-working"),
            crate::node::working_v2::FirstPartyIdentity::FirstParty,
            digest,
        )
        .await
        .unwrap();
    for outcome in [None, Some("not_applied")] {
        if outcome.is_some() {
            scoped
                .journal
                .update(ticket.id(), |entry| {
                    entry.state = EntryState::Uncertain;
                    entry.maybe_applied = true;
                })
                .unwrap();
        }
        let fence = shared.capture().await.unwrap();
        let revision = fence.view().revision().to_owned();
        let before = serde_json::to_vec(&scoped.journal.get(ticket.id()).unwrap()).unwrap();
        let bytes = fs::read(
            scoped
                .journal
                .directory()
                .join(format!("{}.json", ticket.id())),
        )
        .unwrap();
        let error = scoped
            .operator_decision(ticket.id(), outcome, "operator race fixture", None)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("qualified reconciliation"),
            "{error}"
        );
        assert_eq!(
            serde_json::to_vec(&scoped.journal.get(ticket.id()).unwrap()).unwrap(),
            before
        );
        assert_eq!(
            fs::read(
                scoped
                    .journal
                    .directory()
                    .join(format!("{}.json", ticket.id()))
            )
            .unwrap(),
            bytes
        );
        assert_eq!(fence.view().revision(), revision);
        drop(fence);
        assert_eq!(shared.capture().await.unwrap().view().revision(), revision);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn installed_working_send_rechecks_scope_and_engine_after_publication_fence_wait() {
    for change in ["scope", "history", "engine"] {
        let rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        let scoped = rig.scoped();
        let shared = scoped
            .working_journal(installed_binding(rig.binding()))
            .unwrap();
        let digest = scoped
            .hold_contracts("update_record")
            .digest("records_write", "update_record")
            .unwrap()
            .to_owned();
        let ticket = shared
            .persist_original(
                "format-actor".into(),
                &installed_proposal(&id, "fenced-send"),
                crate::node::working_v2::FirstPartyIdentity::FirstParty,
                digest,
            )
            .await
            .unwrap();
        let entry = scoped.journal.get(ticket.id()).unwrap();
        let before = serde_json::to_vec(&entry).unwrap();
        let fence = shared.capture().await.unwrap();
        let send = scoped.send_once(&rig.upstream, Some(rig.verified.as_ref()), &entry, None);
        tokio::pin!(send);
        tokio::select! {
            _=rig.verified.before_entered.notified()=>{},
            result=&mut send=>panic!("finished before publication fence, succeeded={}", result.is_ok()),
        }
        // Same credential: only an actual scope/history or engine change.
        if change == "scope" {
            rig.verified
                .binding
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .database_id = "other-database".into();
        } else if change == "history" {
            rig.verified
                .binding
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .history_lineage = "new-history".into();
        } else {
            scoped.set_kernel_v2_upstream(false);
        }
        drop(fence);
        assert!(matches!(send.await, Err(Halt::Local)));
        assert_eq!(rig.verified.active_sends.load(Ordering::Acquire), 0);
        assert_eq!(rig.verified.completed_sends.load(Ordering::Acquire), 1);
        assert_eq!(
            serde_json::to_vec(&scoped.journal.get(ticket.id()).unwrap()).unwrap(),
            before
        );
        assert!(
            rig.outcomes.lock().unwrap().is_empty(),
            "no old-scope HTTP send"
        );
        assert_eq!(canonical(&rig.home.world, &id).await, "base");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn installed_working_v7_exact_contract_does_not_inherit_prose_only_custody() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let args = json!({"id":id,"body_append":"!","reason":"working contract composition","idempotency_key":"working-v7-exact"});
    let message = tool_call(
        11,
        "call_executor",
        json!({"executor":"records_write","operation":"update_record","arguments":args}),
    );
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let request = WriteRequest {
        body: &body,
        message: &message,
        revision: None,
        caller: &caller,
        outage: Some(rig.verified.as_ref()),
        no_hold: false,
    };
    let captured = crate::fork::working_v2::manager::WorkingManager::capture_original(
        crate::mcp::Caller::local_owner(rig.home.world.admin.clone()),
        args.clone(),
    )
    .unwrap();
    let exact = scoped.working_contract(&request, &captured).await.unwrap();
    assert_eq!(
        Some(exact.as_str()),
        scoped
            .hold_contracts("update_record")
            .digest("records_write", "update_record")
    );
    // Catalog acceptance is outside the global digest. Exact digest equality
    // must not bypass that independent hosted policy declaration.
    let mut acceptance_changed = current_v2_contract("update_record");
    acceptance_changed.catalog["requires_acceptance"] = json!(true);
    *rig.verified.contract_override.lock().unwrap() = Some(acceptance_changed);
    assert!(scoped.working_contract(&request, &captured).await.is_err());
    assert_eq!(scoped.journal.pending_count(), 0);
    *rig.verified.contract_override.lock().unwrap() = Some(prose_v2_contract());
    assert!(scoped
        .working_contract(&request, &captured)
        .await
        .unwrap_err()
        .to_string()
        .contains("exact compiled v2 contract"));
    assert_eq!(
        scoped.journal.pending_count(),
        0,
        "no working custody from prose-only compatibility"
    );
    let ordinary = rig.send("update_record", args).await;
    assert_eq!(
        ordinary["result"]["structuredContent"]["outcome"],
        "accepted_pending"
    );
    let entry = scoped.journal.oldest_pending().unwrap();
    assert_eq!(entry.version, V2_EVIDENCE_VERSION);
    assert!(scoped.compatible_entry(&entry));
    assert!(!entry.installed_working());
    assert!(rig.outcomes.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn installed_working_inventory_excludes_only_strict_ordinary_v6() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let args = json!({"id":id,"body_append":"!","reason":"inventory fixture","idempotency_key":"ordinary-inventory"});
    let reply = rig.send("update_record", args).await;
    assert_eq!(
        reply["result"]["structuredContent"]["outcome"],
        "accepted_pending"
    );
    let scoped = rig.scoped();
    let ordinary = scoped.journal.oldest_pending().unwrap();
    assert_eq!(ordinary.version, V2_EVIDENCE_VERSION);
    assert!(
        !rig.home.gate.retained_working_may_exist(),
        "ordinary pending evidence alone is not W"
    );
    let terminal = scoped
        .journal
        .settle(&ordinary.id, EntryState::Confirmed, Some("receipt"), None)
        .unwrap();
    let ordinary_path = scoped
        .journal
        .directory()
        .join(format!("{}.json", ordinary.id));
    let ordinary_bytes = fs::read(&ordinary_path).unwrap();
    assert!(
        !rig.home.gate.retained_working_may_exist(),
        "ordinary terminal history alone is not W"
    );

    // Construct a real provider-backed installed original, not a guessed codec
    // shape. This fixture tests inventory only, not authenticated manager ACK.
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    let ticket = shared
        .persist_original(
            "format-actor".into(),
            &installed_proposal(&id, "working-inventory"),
            crate::node::working_v2::FirstPartyIdentity::FirstParty,
            digest,
        )
        .await
        .unwrap();
    let path = scoped
        .journal
        .directory()
        .join(format!("{}.json", ticket.id()));
    let working_bytes = fs::read(&path).unwrap();
    let working: Value = serde_json::from_slice(&working_bytes).unwrap();
    assert_eq!(working["version"], INSTALLED_WORKING_VERSION);
    assert!(
        rig.home.gate.retained_working_may_exist(),
        "mixture of genuine ordinary6 and working7 must retain W possibility"
    );
    let backup = ordinary_path.with_extension("saved");
    fs::rename(&ordinary_path, &backup).unwrap();
    let mut old = working.clone();
    old["version"] = json!(V2_EVIDENCE_VERSION);
    let mut invalid = serde_json::to_value(terminal).unwrap();
    invalid["id"] = json!(ticket.id());
    invalid["kernel_v2_custody"]["original"]["rule"] = json!(0);
    let mut future = working.clone();
    future["version"] = json!(INSTALLED_WORKING_VERSION + 1);
    for (label, bytes) in [
        ("old working6", serde_json::to_vec(&old).unwrap()),
        ("invalid evidence6", serde_json::to_vec(&invalid).unwrap()),
        ("working7", working_bytes.clone()),
        ("future format", serde_json::to_vec(&future).unwrap()),
        ("unknown object", br#"{"unknown":true}"#.to_vec()),
        ("malformed JSON", b"{not-json".to_vec()),
    ] {
        fs::write(&path, &bytes).unwrap();
        assert!(rig.home.gate.retained_working_may_exist(), "{label}");
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "inventory never rewrites {label}"
        );
    }
    fs::rename(&backup, &ordinary_path).unwrap();
    fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
    assert!(
        rig.home.gate.retained_working_may_exist(),
        "valid6 must not hide an opaque working original beside it"
    );
    assert_eq!(fs::read(&ordinary_path).unwrap(), ordinary_bytes);
}

#[test]
fn receiver94_constructor_evidence() {
    let contracts =
        crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap();
    let mut evidence = serde_json::Map::new();
    for (operation, fingerprint) in [
        (
            "update_record",
            "e10eafe3a3be15b62a46a3ed11a543c0df3d81d6c60d7dee149c1ffc67ee2b62",
        ),
        (
            "manage_links.add",
            "7fba13e92d73559f6371a68b803d43db04e638d44ab22ca5ae2605d25e7b90fd",
        ),
        (
            "attach_text",
            "44ecc8a1607dfa0c4549790df90fa99d748af34b525b830ff49df98d0314818a",
        ),
    ] {
        let contract = contracts
            .holding_contract("records_write", operation)
            .unwrap();
        let captured: std::collections::BTreeMap<String, NodeHoldingContract> =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/receiver-shapes/contracts94.json"
            )))
            .unwrap();
        assert_eq!(
            contract, captured[operation],
            "emitted public contract remains byte-for-byte94"
        );
        let mut frozen = serde_json::to_value(contract.for_custody().unwrap()).unwrap();
        frozen["description"]
            .as_object_mut()
            .unwrap()
            .remove("contract_digest");
        assert_eq!(
            crate::canonical_json::digest_json(&frozen),
            fingerprint,
            "emitted94 descriptor drift needs review independently of copy support"
        );
        evidence.insert(operation.into(), serde_json::to_value(contract).unwrap());
    }
    if let Ok(path) = std::env::var("NATIVE_RECEIVER94_CONTRACT_CAPTURE") {
        std::fs::write(path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
}

fn receiver95_contract(operation: &str) -> NodeHoldingContract {
    let contracts: std::collections::BTreeMap<String, NodeHoldingContract> =
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/receiver-shapes/contracts95.json"
        )))
        .unwrap();
    contracts[operation].clone()
}

#[test]
fn receiver_custody_pairs_are_complete_exact_and_argument_bounded() {
    use crate::node::gate::receiver_contracts::{
        no_observation_pair, recorded_v7, RecordedLocalDigest,
    };
    let id = "11111111-1111-4111-8111-111111111111";
    let other = "22222222-2222-4222-8222-222222222222";
    for (operation, args) in [
        (
            "update_record",
            json!({"id":id,"body_append":"!","reason":"qualified pair","idempotency_key":"pair"}),
        ),
        (
            "manage_links.add",
            json!({"source_id":id,"target_id":other,"relationship":"relates_to","idempotency_key":"pair"}),
        ),
        (
            "attach_text",
            json!({"record_id":id,"text":"fixture","name":"pair.txt","idempotency_key":"pair"}),
        ),
    ] {
        let old = current_v2_contract(operation);
        let new = receiver95_contract(operation);
        assert!(!old.matches_custody(&new), "global matcher stays exact");
        assert!(no_observation_pair(
            "records_write",
            operation,
            &args,
            &old,
            &old,
            &new
        ));
        assert!(no_observation_pair(
            "records_write",
            operation,
            &args,
            &old.for_custody().unwrap(),
            &old,
            &new
        ));
        assert!(
            !no_observation_pair("records_write", operation, &args, &old, &new, &new),
            "futureB retained94 execution remains separately blocked"
        );
        for key in ["observed", "observed_act", "observed_basis"] {
            let mut changed = args.clone();
            changed[key] = Value::Null;
            assert!(!no_observation_pair(
                "records_write",
                operation,
                &changed,
                &old,
                &old,
                &new
            ));
        }
        for fault in [
            "digest", "policy", "selector", "schema", "unknown", "original",
        ] {
            let mut hosted = new.clone();
            let mut original = old.clone();
            match fault {
                "digest" => hosted.description["contract_digest"] = json!("f".repeat(64)),
                "policy" => hosted.catalog["requires_acceptance"] = json!(true),
                "selector" => {
                    hosted.description["source"]["selector"] =
                        json!({"field":"action","value":"remove"})
                }
                "schema" => hosted.description["input_schema"]["extra_optional_field"] = json!({}),
                "unknown" => hosted.description["new_authority_meaning"] = json!(true),
                "original" => original.description["contract_digest"] = json!("f".repeat(64)),
                _ => unreachable!(),
            }
            assert!(
                !no_observation_pair("records_write", operation, &args, &original, &old, &hosted),
                "{operation} {fault}"
            );
        }
        let digest = old.description["contract_digest"].as_str().unwrap();
        assert_eq!(
            recorded_v7(
                "records_write",
                operation,
                RecordedLocalDigest(digest),
                &old
            )
            .is_some(),
            operation == "update_record"
        );
        assert!(recorded_v7(
            "records_write",
            operation,
            RecordedLocalDigest("unrecorded"),
            &old
        )
        .is_none());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn receiver_custody_three_ordinary94_calls_restart_and_drain_under95_discovery() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let other = record(&rig.home.world, "other").await;
    let calls = [
        (
            "update_record",
            json!({"id":id,"body_append":"!","reason":"qualified receiver","idempotency_key":"receiver-append"}),
        ),
        (
            "manage_links.add",
            json!({"source_id":id,"target_id":other,"relationship":"relates_to","idempotency_key":"receiver-link"}),
        ),
        (
            "attach_text",
            json!({"record_id":id,"text":"qualified attachment","name":"receiver.txt","idempotency_key":"receiver-attach"}),
        ),
    ];
    for (operation, args) in &calls {
        *rig.verified.contract_override.lock().unwrap() = Some(receiver95_contract(operation));
        let reply = rig.send(operation, args.clone()).await;
        assert!(reply.to_string().contains("accepted_pending"), "{reply}");
    }
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
    assert_eq!(rig.scoped().journal.pending_count(), 3);
    let originals = rig.scoped().journal.pending_entries();
    // Reopen the genuine ordinary codec, preserving its recorded94 evidence.
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    rig.verified.down.store(false, Ordering::Release);
    *rig.verified.contract_override.lock().unwrap() = None;
    rig.verified.receiver95.store(true, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    for original in originals {
        let retained = rig.scoped().journal.get(&original.id).unwrap();
        assert_eq!(retained.state, EntryState::Confirmed);
        assert!(
            retained.arguments.is_none(),
            "ordinary confirmed receipts keep their existing content-erasure policy"
        );
        assert_eq!(retained.kernel_v2_custody, original.kernel_v2_custody);
    }
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(rig.outcomes.lock().unwrap().len(), 3);
    assert_eq!(rig.scoped().journal.pending_count(), 0);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(rig.outcomes.lock().unwrap().len(), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn receiver_v7_original94_digest_none_restart_drain_and_retry_under95_discovery() {
    let mut rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    // Existing installed facade checks working_admission and production
    // persist_captured; no JSON version/digest/original fields are fabricated.
    let ticket = shared
        .persist_original(
            rig.home.world.admin.clone(),
            &installed_proposal(&id, "receiver-v7-old94"),
            crate::node::working_v2::FirstPartyIdentity::FirstParty,
            digest.clone(),
        )
        .await
        .unwrap();
    let original = scoped.journal.get(ticket.id()).unwrap();
    assert_eq!(original.version, INSTALLED_WORKING_VERSION);
    assert!(original
        .kernel_v2_custody
        .as_ref()
        .unwrap()
        .original
        .is_none());
    assert_eq!(
        original.kernel_v2_custody.as_ref().unwrap().contract_digest,
        digest
    );
    let bytes = fs::read(
        scoped
            .journal
            .directory()
            .join(format!("{}.json", original.id)),
    )
    .unwrap();
    drop(shared);
    drop(scoped);
    let config = rig.home.gate.config.clone();
    rig.home.gate =
        Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
    rig.home.gate.set_kernel_v2_upstream(true);
    assert_eq!(
        fs::read(
            rig.scoped()
                .journal
                .directory()
                .join(format!("{}.json", original.id))
        )
        .unwrap(),
        bytes
    );
    *rig.verified.contract_override.lock().unwrap() = Some(receiver95_contract("update_record"));
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(
        rig.drain().await,
        queue::Halt::Local,
        "custody pairing grants no W publication"
    );
    assert!(rig.wire_requests.lock().unwrap().is_empty());
    let ordinal = rig.scoped().journal.working_ordinal(&original.id).unwrap();
    // Isolate the custody contract seam from the existing W publication
    // authority. Its default is false; only this exact scope/ordinal is granted.
    rig.verified
        .published_ordinal
        .store(ordinal, Ordering::Release);
    rig.drop_reply.store(true, Ordering::Release);
    let _ = rig.drain().await;
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    rig.verified.down.store(false, Ordering::Release);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    let retained = rig.scoped().journal.get(&original.id).unwrap();
    assert_eq!(retained.version, original.version);
    assert_eq!(retained.kernel_v2_custody, original.kernel_v2_custody);
    assert_eq!(retained.arguments, original.arguments);
    assert_eq!(retained.state, EntryState::Confirmed);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(canonical(&rig.home.world, &id).await, "base!");
    assert_eq!(
        rig.outcomes.lock().unwrap().len(),
        2,
        "ambiguous first send replays one existing result"
    );
    let requests = rig.wire_requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0], requests[1],
        "retry retains the exact first canonical request"
    );
    for request in requests.iter() {
        assert_eq!(
            request["params"]["arguments"]["arguments"],
            original.arguments.clone().unwrap()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn receiver_retained_v9_update_cannot_use_v7_digest_pair() {
    use crate::mcp::kernel_v2::writes::replay::RecordOperation;
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    let ticket = shared.fixture_record_original(
        "format-actor", RecordOperation::Update,
        json!({"id":id,"body_append":"!","reason":"Retained record codec","idempotency_key":"receiver-v9-retained"}),
        digest.clone(),
    ).await.unwrap();
    let entry = scoped.journal.get(ticket.id()).unwrap();
    assert_eq!(
        entry.version,
        crate::node::journal::INSTALLED_RECORD_VERSION
    );
    assert!(entry.kernel_v2_custody.as_ref().unwrap().original.is_none());
    assert_eq!(
        entry.kernel_v2_custody.as_ref().unwrap().contract_digest,
        digest
    );
    let path = scoped
        .journal
        .directory()
        .join(format!("{}.json", entry.id));
    let before = fs::read(&path).unwrap();
    *rig.verified.contract_override.lock().unwrap() = Some(receiver95_contract("update_record"));
    assert!(matches!(
        scoped
            .v2_contract_block(&entry, Some(rig.verified.as_ref()))
            .await,
        Some(crate::node::journal::CompatibilityBlock::LegacyDigestDrift)
    ));
    assert_eq!(fs::read(path).unwrap(), before);
    assert!(rig.wire_requests.lock().unwrap().is_empty());
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
}

#[tokio::test(flavor = "current_thread")]
async fn receiver_v7_fresh95_discovery_admits_only_local94_no_observation_original() {
    let rig = ExistingRig::new().await;
    let id = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    *rig.verified.contract_override.lock().unwrap() = Some(receiver95_contract("update_record"));
    let args = json!({"id":id,"body_append":"!","reason":"Receiver fresh installed original","idempotency_key":"receiver-v7-fresh"});
    let message = tool_call(
        11,
        "call_executor",
        json!({"executor":"records_write","operation":"update_record","arguments":args}),
    );
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let request = WriteRequest {
        body: &body,
        message: &message,
        revision: None,
        caller: &caller,
        outage: Some(rig.verified.as_ref()),
        no_hold: false,
    };
    let captured = crate::fork::working_v2::manager::WorkingManager::capture_original(
        crate::mcp::Caller::local_owner(rig.home.world.admin.clone()),
        args.clone(),
    )
    .unwrap();
    let digest = scoped.working_contract(&request, &captured).await.unwrap();
    assert_eq!(
        Some(digest.as_str()),
        scoped
            .hold_contracts("update_record")
            .digest("records_write", "update_record")
    );
    assert_ne!(
        digest,
        receiver95_contract("update_record").description["contract_digest"]
            .as_str()
            .unwrap()
    );
    let proposal = crate::mcp::kernel_v2::writes::replay::ReplayProposal::from_original(
        "update_record",
        args,
        Some("receiver-v7-fresh".into()),
        &Default::default(),
    )
    .unwrap();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    let ticket = shared
        .persist_original(
            rig.home.world.admin.clone(),
            &proposal,
            crate::node::working_v2::FirstPartyIdentity::FirstParty,
            digest.clone(),
        )
        .await
        .unwrap();
    let path = scoped
        .journal
        .directory()
        .join(format!("{}.json", ticket.id()));
    let before = fs::read(&path).unwrap();
    let original = scoped.journal.get(ticket.id()).unwrap();
    assert_eq!(original.version, INSTALLED_WORKING_VERSION);
    assert_eq!(
        original.kernel_v2_custody.as_ref().unwrap().contract_digest,
        digest
    );
    assert!(original
        .kernel_v2_custody
        .as_ref()
        .unwrap()
        .original
        .is_none());
    assert_eq!(canonical(&rig.home.world, &id).await, "base");
    assert!(
        rig.wire_requests.lock().unwrap().is_empty(),
        "valid cached95 discovery needs no network at write"
    );
    for fault in ["digest", "policy", "schema", "account"] {
        let mut hosted = receiver95_contract("update_record");
        let original_binding = rig.binding();
        match fault {
            "digest" => hosted.description["contract_digest"] = json!("f".repeat(64)),
            "policy" => hosted.catalog["requires_acceptance"] = json!(true),
            "schema" => hosted.description["input_schema"]["additional_optional"] = json!({}),
            "account" => {
                rig.verified
                    .binding
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .account_id = "acct:other".into()
            }
            _ => unreachable!(),
        }
        *rig.verified.contract_override.lock().unwrap() = Some(hosted);
        assert!(
            scoped.working_contract(&request, &captured).await.is_err(),
            "{fault}"
        );
        *rig.verified.binding.lock().unwrap() = Some(original_binding);
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "refusal preserves the admitted original"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn installed_working_retained_create_append_share_one_target_and_check_each_digest() {
    use crate::mcp::kernel_v2::writes::replay::{ProposalIdentity, ReplayProposal};
    use crate::node::working_v2::FirstPartyIdentity;
    let rig = ExistingRig::new().await;
    let scoped = rig.scoped();
    let shared = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    // Codec/order fixture only: these are real provider fingerprint bytes,
    // not an authenticated ingress or original Caller construction.
    let actor = "format-actor";
    let (id, nonce) = crate::record_id::mint(
        &crate::record_id::qualified_principal(actor),
        "first-party",
        [76; 32],
    );
    let create=ReplayProposal::from_original("create_record",json!({"type":"Document","kind":"note","name":"Retained mixed-operation note","body":"retained content","home_id":"70110000-0000-4000-8000-000000000001","reason":"Per-operation restart contract fixture","idempotency_key":"retained-create","id":id,"id_nonce":nonce}),Some("retained-create".into()),&ProposalIdentity{app:None,mint_context:Some("first-party".into())}).unwrap();
    let create_digest = scoped
        .hold_contracts("create_record")
        .digest("records_write", "create_record")
        .unwrap()
        .to_owned();
    let append_digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    assert_ne!(create_digest, append_digest);
    let created = shared
        .persist_original(
            actor.into(),
            &create,
            FirstPartyIdentity::FirstPartyCreate {
                context: "first-party".into(),
            },
            create_digest,
        )
        .await
        .unwrap();
    assert_eq!(scoped.working_retained_target().unwrap().unwrap().0, id);
    let appended = shared
        .persist_original(
            actor.into(),
            &installed_proposal(&id, "retained-append"),
            FirstPartyIdentity::FirstParty,
            append_digest,
        )
        .await
        .unwrap();
    assert_eq!(scoped.working_retained_target().unwrap().unwrap().0, id);
    let before: Vec<_> = [created.id(), appended.id()]
        .iter()
        .map(|id| fs::read(scoped.journal.directory().join(format!("{id}.json"))).unwrap())
        .collect();
    for ticket in [&created, &appended] {
        let mut old_contract = scoped.journal.get(ticket.id()).unwrap();
        old_contract
            .kernel_v2_custody
            .as_mut()
            .unwrap()
            .contract_digest = "f".repeat(64);
        assert!(!scoped.working_contract_current(&old_contract));
        // Load a historical-contract fixture in its own real scoped journal;
        // the production update API cannot mutate a live immutable digest.
        let stale_root = tempfile::tempdir().unwrap();
        drop(
            WriteGate::open_scoped(
                stale_root.path(),
                scoped.config.clone(),
                Some(rig.binding()),
            )
            .unwrap(),
        );
        let path = stale_root
            .path()
            .join("journal")
            .join(format!("{}.json", old_contract.id));
        let saved = serde_json::to_vec_pretty(&old_contract).unwrap();
        fs::write(&path, &saved).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = Arc::new(
            WriteGate::open_scoped(
                stale_root.path(),
                scoped.config.clone(),
                Some(rig.binding()),
            )
            .unwrap(),
        );
        assert!(loaded.journal.get(ticket.id()).unwrap().installed_working());
        assert!(loaded
            .working_retained_target()
            .unwrap_err()
            .to_string()
            .contains("exact current contract"));
        assert!(loaded
            .working_journal(installed_binding(rig.binding()))
            .is_err());
        loaded.journal.prune();
        assert_eq!(fs::read(&path).unwrap(), saved);
    }
    let after: Vec<_> = [created.id(), appended.id()]
        .iter()
        .map(|id| fs::read(scoped.journal.directory().join(format!("{id}.json"))).unwrap())
        .collect();
    assert_eq!(
        before, after,
        "incompatible descriptors never rewrite retained originals"
    );
    assert_eq!(shared.capture().await.unwrap().view().proposals().len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn installed_working_maintenance_retry_is_durable_and_respects_due() {
    let minimum = crate::mcp::deployment_read_only::DEPLOYMENT_READ_ONLY_RETRY_AFTER_SECS;
    let now = 1_000;
    for hint in [
        Value::Null,
        json!(0),
        json!(-1),
        json!("30"),
        json!(u64::MAX),
    ] {
        let reply = json!({"result":{"isError":true,"structuredContent":{
            "error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retry_after_secs":hint}}});
        assert_eq!(
            hold::deployment_read_only_retry_not_before(&reply.to_string(), now),
            Some(now + minimum * 1000)
        );
    }
    let longer = json!({"result":{"isError":true,"structuredContent":{
        "error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retry_after_secs":60}}});
    assert_eq!(
        hold::deployment_read_only_retry_not_before(&longer.to_string(), now),
        Some(now + 60_000)
    );
    let partial = json!({"result":{"isError":true,"structuredContent":{
        "error_code":"DEPLOYMENT_READ_ONLY","applied":false,"outcome":"unknown","retry_after_secs":30}}});
    assert_eq!(
        hold::deployment_read_only_retry_not_before(&partial.to_string(), now),
        None
    );
    for prior_lost_reply in [false, true] {
        let mut rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        let original = {
            let scoped = rig.scoped();
            let shared = scoped
                .working_journal(installed_binding(rig.binding()))
                .unwrap();
            let digest = scoped
                .hold_contracts("update_record")
                .digest("records_write", "update_record")
                .unwrap()
                .to_owned();
            let ticket = shared
                .persist_original(
                    rig.home.world.admin.clone(),
                    &installed_proposal(&id, "maintenance-schedule"),
                    crate::node::working_v2::FirstPartyIdentity::FirstParty,
                    digest,
                )
                .await
                .unwrap();
            scoped.journal.get(ticket.id()).unwrap()
        };
        let ordinal = rig.scoped().journal.working_ordinal(&original.id).unwrap();
        rig.verified
            .published_ordinal
            .store(ordinal, Ordering::Release);
        if prior_lost_reply {
            rig.verified.down.store(false, Ordering::Release);
            rig.drop_reply.store(true, Ordering::Release);
            assert_eq!(rig.drain().await, queue::Halt::Unreachable);
            assert_eq!(canonical(&rig.home.world, &id).await, "base!");
        }
        rig.verified.down.store(true, Ordering::Release);
        rig.verified
            .unframed_maintenance
            .store(true, Ordering::Release);
        let before = crate::node::unmerged::now_ms();
        assert_eq!(rig.drain().await, queue::Halt::ReadOnly);
        let retained = rig.scoped().journal.get(&original.id).unwrap();
        assert_eq!(
            retained.state,
            if prior_lost_reply {
                EntryState::Uncertain
            } else {
                EntryState::Pending
            }
        );
        assert_eq!(retained.maybe_applied, prior_lost_reply);
        assert!(!retained.in_flight);
        assert!(retained.not_before_ms >= before + minimum * 1000);
        assert!(retained.not_before_ms <= crate::node::unmerged::now_ms() + minimum * 1000);
        assert_eq!(retained.arguments, original.arguments);
        assert_eq!(
            retained.working_original_ref(),
            original.working_original_ref()
        );
        assert_eq!(retained.kernel_v2_custody, original.kernel_v2_custody);
        // Isolate future eligibility from test-runner pauses/wall-clock passage
        // using the existing journal scheduling test seam. The actual response
        // deadline was checked above; no original/outcome is changed here.
        rig.scoped()
            .journal
            .update(&original.id, |entry| entry.not_before_ms = u64::MAX)
            .unwrap();
        let path = rig
            .scoped()
            .journal
            .directory()
            .join(format!("{}.json", original.id));
        let durable = fs::read(&path).unwrap();
        let wire_count = rig.wire_requests.lock().unwrap().len();
        let config = rig.home.gate.config.clone();
        rig.home.gate =
            Arc::new(WriteGate::open(&rig.home.upstream.config.socket_directory, config).unwrap());
        rig.home.gate.set_kernel_v2_upstream(true);
        rig.verified.down.store(false, Ordering::Release);
        // A queue wake/restart cannot erase a future due time or start HTTP.
        assert_eq!(rig.drain().await, queue::Halt::Empty);
        assert_eq!(rig.wire_requests.lock().unwrap().len(), wire_count);
        assert_eq!(fs::read(&path).unwrap(), durable);
        // Even a stale selected entry cannot bypass the final durable due guard.
        let scoped = rig.scoped();
        assert!(matches!(
            scoped
                .send_once(&rig.upstream, Some(rig.verified.as_ref()), &retained, None)
                .await,
            Err(queue::Halt::Local)
        ));
        assert_eq!(rig.verified.active_sends.load(Ordering::Acquire), 0);
        assert_eq!(rig.wire_requests.lock().unwrap().len(), wire_count);
        assert_eq!(fs::read(&path).unwrap(), durable);
        // Existing journal scheduling test seam: represent expiry only, never
        // alter an original, attempt, verdict or receipt to manufacture success.
        scoped
            .journal
            .update(&original.id, |entry| {
                entry.not_before_ms = crate::node::unmerged::now_ms().saturating_sub(1)
            })
            .unwrap();
        assert_eq!(rig.drain().await, queue::Halt::Empty);
        assert_eq!(rig.wire_requests.lock().unwrap().len(), wire_count + 1);
        assert_eq!(canonical(&rig.home.world, &id).await, "base!");
        let settled = rig.scoped().journal.get(&original.id).unwrap();
        assert_eq!(settled.state, EntryState::Confirmed);
        assert_eq!(settled.answer.as_deref(), Some("receipt"));
        assert_eq!(settled.maybe_applied, prior_lost_reply);
        assert_eq!(settled.arguments, original.arguments);
        assert_eq!(
            settled.working_original_ref(),
            original.working_original_ref()
        );
        assert_eq!(settled.kernel_v2_custody, original.kernel_v2_custody);
    }
}

#[tokio::test]
async fn installed_working_update_required_retains_original_and_prior_uncertainty() {
    for prior_lost_reply in [false, true] {
        let rig = ExistingRig::new().await;
        let id = record(&rig.home.world, "base").await;
        let scoped = rig.scoped();
        let shared = scoped
            .working_journal(installed_binding(rig.binding()))
            .unwrap();
        let digest = scoped
            .hold_contracts("update_record")
            .digest("records_write", "update_record")
            .unwrap()
            .to_owned();
        let ticket = shared
            .persist_original(
                rig.home.world.admin.clone(),
                &installed_proposal(&id, "update-working"),
                crate::node::working_v2::FirstPartyIdentity::FirstParty,
                digest,
            )
            .await
            .unwrap();
        let original = scoped.journal.get(ticket.id()).unwrap();
        let ordinal = scoped.journal.working_ordinal(&original.id).unwrap();
        rig.verified
            .published_ordinal
            .store(ordinal, Ordering::Release);
        rig.verified.down.store(false, Ordering::Release);
        if prior_lost_reply {
            rig.drop_reply.store(true, Ordering::Release);
            assert_eq!(rig.drain().await, queue::Halt::Unreachable);
        }
        rig.verified.update_required.store(true, Ordering::Release);
        assert_eq!(rig.drain().await, queue::Halt::ClientUpdateRequired);
        let retained = scoped.journal.get(&original.id).unwrap();
        assert_eq!(
            retained.state,
            if prior_lost_reply {
                EntryState::Uncertain
            } else {
                EntryState::Pending
            }
        );
        assert_eq!(retained.maybe_applied, prior_lost_reply);
        assert!(!retained.in_flight);
        assert!(retained.answer.is_none());
        assert_eq!(
            retained.working_original_ref(),
            original.working_original_ref()
        );
        assert_eq!(retained.kernel_v2_custody, original.kernel_v2_custody);
        assert_eq!(retained.arguments, original.arguments);
        assert_eq!(retained.idempotency_key, original.idempotency_key);
        assert_eq!(
            rig.upstream.compatibility.status()["status"],
            "demand_recorded"
        );
        assert_eq!(
            canonical(&rig.home.world, &id).await,
            if prior_lost_reply { "base!" } else { "base" }
        );
        let error = scoped
            .settle_working_original(
                &rig.upstream,
                rig.verified.as_ref(),
                &original.id,
                &rig.home.world.admin,
                Instant::now() + Duration::from_secs(5),
            )
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("updater unavailable"), "{error}");
        let after = scoped.journal.get(&original.id).unwrap();
        assert_eq!(
            after.working_original_ref(),
            original.working_original_ref()
        );
        assert_eq!(after.kernel_v2_custody, original.kernel_v2_custody);
        assert!(after.working_resolution_ref().unwrap().answer().is_none());
        assert_eq!(after.maybe_applied, prior_lost_reply);
    }
}

#[tokio::test]
async fn enrolled_draft_exclusion_clears_only_the_working_drain_and_preserves_ingress() {
    let mut rig = ExistingRig::new().await;
    let key_file = rig
        .upstream
        .config
        .socket_directory
        .join("fixture-install-key");
    super::super::oauth::atomic_private_write(&key_file, "1".repeat(64).as_bytes()).unwrap();
    let key = crate::node_credential::InstallKey::load(&key_file).unwrap();
    let install = key.id();
    {
        let upstream = Arc::get_mut(&mut rig.upstream).unwrap();
        upstream.install_key = Some(key);
        upstream.config.node_install_id = Some(install.clone());
        upstream.config.working_refusal_drafts = true;
    }
    rig.verified
        .binding
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .install_id = Some(install);
    let record = record(&rig.home.world, "base").await;
    let scoped = rig.scoped();
    let journal = scoped
        .working_journal(installed_binding(rig.binding()))
        .unwrap();
    journal.qualify_enrolled_fixture();
    let digest = scoped
        .hold_contracts("update_record")
        .digest("records_write", "update_record")
        .unwrap()
        .to_owned();
    let ticket = journal
        .persist_original(
            rig.home.world.admin.clone(),
            &installed_proposal(&record, "drafted-record"),
            crate::node::working_v2::FirstPartyIdentity::FirstParty,
            digest,
        )
        .await
        .unwrap();
    journal.fixture_resolution_requested(ticket.id()).await;
    let retained = journal.fixture_entry_bytes(ticket.id());
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert!(rig.wire_requests.lock().unwrap().is_empty());

    // The pinned-working publication is proved by the manager tests. This
    // test supplies its exclusion at the production gate hook.
    *rig.verified.dispatch_exclusions.lock().unwrap() = Some(vec![ticket.id().to_owned()]);
    assert_eq!(rig.drain().await, queue::Halt::Empty);
    assert_eq!(
        scoped.journal.pending_count(),
        1,
        "draft bytes stay in custody"
    );
    let ordinary = rig
        .send(
            "update_record",
            json!({
                "id":record,"body_append":" forbidden","reason":"ordinary ingress proof",
                "idempotency_key":"other-original"
            }),
        )
        .await;
    assert!(ordinary
        .to_string()
        .contains("Enrolled nodes send only admitted keyed working originals"));
    assert!(rig.wire_requests.lock().unwrap().is_empty());
    assert_eq!(journal.fixture_entry_bytes(ticket.id()), retained);

    Arc::get_mut(&mut rig.upstream)
        .unwrap()
        .config
        .working_refusal_drafts = false;
    assert_eq!(rig.drain().await, queue::Halt::Local);
    assert!(rig.wire_requests.lock().unwrap().is_empty());
}
