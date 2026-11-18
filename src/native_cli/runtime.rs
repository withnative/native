//! Offline compiled declarations. This path never opens installation or device state.
use serde_json::{json, Value};
use std::process::ExitCode;

pub fn run_cli(args: &[String]) -> ExitCode {
    if args == ["describe", "--json"] {
        println!("{}", describe());
        ExitCode::SUCCESS
    } else {
        eprintln!("usage: native runtime describe --json");
        ExitCode::from(2)
    }
}

/// Compiled facts only: neither an inspected installation nor a release edge.
pub fn describe() -> Value {
    #[cfg(unix)]
    let device = crate::node::runtime_declarations();
    #[cfg(not(unix))]
    let device = json!({"compiled":false,"required_platform":"unix"});
    json!({
        "contract":"native.runtime-capabilities.v1",
        "qualification":"compiled_declaration",
        "build_and_wire":serde_json::from_str::<Value>(crate::client_compatibility::advertisement())
            .expect("compiled client advertisement"),
        "device":device,
        "replica":crate::standby::runtime_declarations(),
        "edges":[],
        "authority":"declarations_only_no_installation_or_transition_authority"
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn runtime_declaration_matches_strict_unversioned_configuration_readers() {
        let report = describe();
        let config = json!({"hosted_base_url":"https://example.test","home_id":"home","db_id":"db",
            "credential_file":"/unused/token","socket_directory":"/unused/run"});
        assert!(serde_json::from_value::<crate::node::NodeConfig>(config.clone()).is_ok());
        let mut future = config;
        future["future_optional_setting"] = json!(true);
        assert!(serde_json::from_value::<crate::node::NodeConfig>(future).is_err());
        let standby = json!({"replica_root":"/unused/replica","hosted_route_database_id":"db",
            "origin_database_id":"db:11111111-1111-4111-8111-111111111111"});
        // Exercise the serde reader directly: no filesystem or identity probe.
        assert!(
            serde_json::from_value::<crate::standby::StandbyRuntimeConfig>(standby.clone()).is_ok()
        );
        let mut future = standby;
        future["future_optional_setting"] = json!(true);
        assert!(serde_json::from_value::<crate::standby::StandbyRuntimeConfig>(future).is_err());
        for config in [
            &report["device"]["configuration"],
            &report["replica"]["configuration"],
        ] {
            assert_eq!(config["envelope"], "unversioned");
            assert_eq!(config["unknown_fields"], "reject");
        }
        assert_eq!(
            report["build_and_wire"].to_string(),
            crate::client_compatibility::advertisement()
        );
    }
}
