
// Appended only by qualify-installed-v7.py in the pinned disposable producer.
#[tokio::test]
async fn receiver95_private_runtime() {
    let config: Value = serde_json::from_slice(&std::fs::read(std::env::var("NATIVE_RECEIVER_RUNTIME_CONFIG").unwrap()).unwrap()).unwrap();
    let data = PathBuf::from(config["data"].as_str().unwrap());
    let database = PathBuf::from(config["database"].as_str().unwrap());
    assert!(data.starts_with("/tmp") && data.join("receiver-runtime-fixture.json").is_file());
    assert!(database.starts_with(&data) && database.parent().unwrap().file_name().unwrap() == "databases");
    assert_eq!(native_ce::FULL_GIT_SHA, "79570567dc19b5fd1b91191d302a7a573265073f");
    let codes: Codes = Arc::new(Mutex::new(HashMap::new()));
    let source = JwksSource::new(jwks(SIGNING_KID));
    let mut options = HostingOptions::new(&data, capturing_sink(&codes));
    options.auth.min_resend_interval_ms = Some(0);
    options.resource_server = Some(configured());
    options.jwks_fetch = Some(source.as_fn());
    // Hosting's exclusive volume authority must be acquired before touching
    // the stopped fixture's canonical tenant. No route is listening yet.
    let hosting = Arc::new(Hosting::open(options).await.unwrap());
    native_ce::native_cli::maintenance::prepare_saved_tabs(&database, config["account"].as_str().unwrap()).await.unwrap();
    let db = kernel::open_marked_v2_database(database.to_str().unwrap()).await.unwrap();
    kernel::verify_v2_ready(&db).await.unwrap();
    let head = native_ce::standby::delta_transport::observe_authority_act_head(&db,config["route"].as_str().unwrap()).await.unwrap();
    let head = serde_json::to_value(head).unwrap();
    let coordinates = head["head"]["generation"].clone();
    assert_eq!(coordinates["schema_sha256"], "770fb261b350ed747bb12db56f6b40cccc33c39ab01baaef2b2298d9b6b3ad90");
    db.close().await;
    let mut registry = ToolRegistry::new();
    registry.set_deployment_mutation_barrier(hosting.deployment_mutation_barrier());
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    native_ce::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    native_ce::mcp::register_authority_act_tools(&mut registry, Arc::new(native_held_hosting::hosting::HostedAuthorityActSource::new(hosting.clone()))).unwrap();
    let registry = Arc::new(registry);
    let app = mcp_executor_router(hosting.clone(), registry.clone(), Arc::new(PlanKeys)).await.unwrap()
        .merge(native_held_hosting::tools_router_for_surface_with_origin(hosting.clone(), registry, native_ce::mcp::McpSurfaceMode::Executor, Some("http://localhost")).unwrap())
        .merge(native_held_hosting::hosting::realtime::events_router(hosting.clone()))
        .merge(auth_router(hosting.clone())).merge(export_router(hosting.clone())).merge(oauth_metadata_router(hosting.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    std::fs::write(config["ready"].as_str().unwrap(), serde_json::to_vec(&json!({"addr":listener.local_addr().unwrap(),"source":native_ce::FULL_GIT_SHA,"artifact_sha256":file_digest(&std::env::current_exe().unwrap()),"coordinates":coordinates})).unwrap()).unwrap();
    axum::serve(listener, app).await.unwrap();
}
