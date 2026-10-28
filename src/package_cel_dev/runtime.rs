//! Explicitly opted-in checked guest runtime; P1 stays interim. No native fallback.
//! Targeted development containment evidence is not production qualification.
use super::*;
use native_package_cel_wire::{Declaration, Mode, Request};
use serde_json::{json, Value};

const SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Discovery documentation for the existing package-call request and provider
/// result envelope. Source bindings come from the operation's executable
/// declaration, not call arguments. This is not production validation evidence.
pub(crate) fn provider_schema() -> Value {
    json!({
        "language": LANGUAGE,
        "profile": PROFILE,
        "interim": true,
        "interpreter": native_package_cel_host::INTERPRETER,
        "guest_abi": native_package_cel_wire::ABI,
        "request": {
            "type": "object",
            "required": ["record_id"],
            "additionalProperties": false,
            "properties": {
                "record_id": {"type":"string", "description":"Caller-visible record matching the operation's family/kind; namespace, package name and operation select the package call."}
            }
        },
        "source": {
            "description":"The operation's source_field holds a closed JSON object matching executable.bindings. No extra, missing, duplicate or null bindings; int/double/bool/string types only. Integers and finite doubles must be within the safe numeric range.",
            "max_bindings": MAX_BINDINGS,
            "max_json_bytes": MAX_SOURCE_BYTES,
            "max_string_utf8_bytes": MAX_STRING_BYTES,
            "number_minimum": -SAFE_INTEGER,
            "number_maximum": SAFE_INTEGER
        },
        "result": {
            "description":"Provider result, returned alongside the package-operation receipt. Success has error:null; domain failure has value:null. Scalar output is at most 8192 serialized bytes. Authority, activation, invalid declaration, the generic 256 KiB stored-source materialization guard and guest/resource/encoded 32KiB frame failures are outer call refusals without a receipt.",
            "oneOf": [
                {
                    "type":"object", "required":["value","error"], "additionalProperties":false,
                    "properties":{
                        "value":{
                            "type":["null","boolean","number","string"],
                            "minimum":-SAFE_INTEGER, "maximum":SAFE_INTEGER,
                            "maxLength": MAX_STRING_BYTES,
                            "description":"Finite safe-range number, boolean, null, or string of at most 1024 UTF-8 bytes."
                        },
                        "error":{"type":"null"}
                    }
                },
                {
                    "type":"object", "required":["value","error"], "additionalProperties":false,
                    "properties":{
                        "value":{"type":"null"},
                        "error":{
                            "type":"object", "required":["kind","message"], "additionalProperties":false,
                            "properties":{
                                "kind":{"enum":["invalid_bindings","evaluation_failed","invalid_result"]},
                                "message":{"type":"string","maxLength":512}
                            }
                        }
                    }
                }
            ]
        }
    })
}

fn wire(declaration: ExecutableDeclaration) -> Result<Declaration> {
    declaration.validate_shape()?;
    serde_json::from_value(serde_json::to_value(declaration)?)
        .map_err(|e| Error::engine(e.to_string()))
}
#[cfg(test)]
static GUEST_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
async fn guest(request: Request) -> Result<native_package_cel_host::Outcome> {
    #[cfg(test)]
    GUEST_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let host = native_package_cel_host::global()
        .await
        .map_err(|e| Error::engine(format!("CEL guest {e}; explicit retry required")))?;
    let outcome = host
        .submit(&request)
        .map_err(|e| Error::engine(format!("CEL guest {e}; explicit retry required")))?
        .wait_async()
        .await
        .map_err(|e| Error::engine(format!("CEL guest {e}")))?;
    if let Some(error) = outcome.failure {
        return Err(Error::engine(format!(
            "CEL guest {error}; result discarded; explicit retry required"
        )));
    }
    Ok(outcome)
}
/// Called only after Manage read preflight has closed; writer recheck remains in kernel.
pub(crate) async fn admit(manifest: &crate::package_manifest::PackageManifest) -> Result<()> {
    manifest.validate()?;
    for declaration in manifest
        .operations
        .iter()
        .filter_map(|op| op.executable.clone())
    {
        let outcome = guest(Request::Check {
            declaration: wire(declaration)?,
        })
        .await?;
        let report = outcome
            .report
            .ok_or_else(|| Error::engine("CEL guest missing check report"))?;
        if report.mode != Mode::Check || !report.check_ok || report.error.is_some() {
            return Err(Error::engine(format!(
                "CEL guest check refused: {}",
                report.error.as_deref().unwrap_or("invalid report")
            )));
        }
    }
    Ok(())
}
pub(crate) async fn run(
    declaration: ExecutableDeclaration,
    source: String,
) -> Result<(Value, ExecutionReceipt)> {
    let expression_digest =
        crate::meta::definition_artifact::digest_artifact_bytes(declaration.expression.as_bytes());
    let language = declaration.language.clone();
    let profile = declaration.profile.clone();
    let outcome = guest(Request::Evaluate {
        declaration: wire(declaration)?,
        source,
    })
    .await?;
    let report = outcome
        .report
        .ok_or_else(|| Error::engine("CEL guest missing evaluate report"))?;
    if report.mode != Mode::Evaluate {
        return Err(Error::engine("CEL guest wrong report mode"));
    }
    let result = match report.error_stage.as_deref() {
        None => json!({"value":report.value,"error":null}),
        Some("source" | "bindings") => failure(
            "invalid_bindings",
            report.error.as_deref().unwrap_or("invalid bindings"),
        ),
        Some("evaluate") => failure(
            "evaluation_failed",
            report.error.as_deref().unwrap_or("evaluation failed"),
        ),
        Some("result") => failure(
            "invalid_result",
            report.error.as_deref().unwrap_or("invalid scalar result"),
        ),
        _ => return Err(Error::engine("CEL guest declaration check refused")),
    };
    let receipt = ExecutionReceipt {
        language,
        profile,
        expression_digest,
        interpreter: native_package_cel_host::INTERPRETER.into(),
        policy: report.eval_policy.unwrap_or(report.check_policy),
        interim: report.eval_interim.unwrap_or(report.check_interim),
        guest: Some(GuestExecutionReceipt {
            abi: report.abi,
            module_sha256: outcome.module_sha256,
            source_sha256: native_package_cel_host::GUEST_SOURCE_SHA256.into(),
            build_manifest_sha256: native_package_cel_host::BUILD_MANIFEST_SHA256.into(),
            runtime: native_package_cel_host::RUNTIME.into(),
            configuration: outcome.config.into(),
            fuel_budget: outcome.fuel_budget,
            fuel_used: outcome.fuel_used,
            deadline_ms: outcome.deadline_ms,
            phase: format!("{:?}", outcome.phase),
            limits: native_package_cel_host::limits(),
        }),
    };
    Ok((result, receipt))
}
fn failure(kind: &str, message: &str) -> Value {
    json!({"value":null,"error":{"kind":kind,"message":message.chars().take(512).collect::<String>()}})
}
#[cfg(test)]
mod tests;
