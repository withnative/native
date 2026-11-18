//! Custody compatibility is deliberately separate from the public contract digest.
//! Only the source tool's prose may differ; input schemas remain structurally exact.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct NodeHoldingContract {
    pub(crate) description: Value,
    pub(crate) catalog: Value,
}

impl NodeHoldingContract {
    /// Join authenticated discovery replies only when they identify the same
    /// contract. Retain the entire description, so unknown future fields fail
    /// comparison rather than silently disappearing from this boundary.
    pub(crate) fn from_hosted(mut description: Value, catalog: &Value) -> Option<Self> {
        // describe_operation attaches this request/run envelope to its contract.
        // Unknown contract fields are retained and still fail comparison.
        description.as_object_mut()?.remove("run_context");
        let digest = description.get("contract_digest")?.as_str()?;
        if digest.is_empty() || catalog.get("contract_digest")?.as_str()? != digest {
            return None;
        }
        for field in ["executor", "operation", "surface", "contract_version"] {
            if description.get(field)?.as_str()?.is_empty()
                || description.get(field)? != catalog.get(field)?
            {
                return None;
            }
        }
        if description.pointer("/source/tool")?.as_str()? != catalog.get("source_tool")?.as_str()?
            || description
                .pointer("/source/tool_description")?
                .as_str()?
                .trim()
                .is_empty()
            || !description.get("input_schema")?.is_object()
        {
            return None;
        }
        let selector = description.pointer("/source/selector")?;
        for (field, member) in [("selector_field", "field"), ("selector_value", "value")] {
            let value = if selector.is_null() {
                &Value::Null
            } else {
                selector.get(member)?
            };
            if value != catalog.get(field)? {
                return None;
            }
        }
        let flag = |name: &str| -> Option<bool> {
            match catalog.get(name)? {
                Value::Bool(value) => Some(*value),
                value if value.as_i64() == Some(0) => Some(false),
                value if value.as_i64() == Some(1) => Some(true),
                _ => None,
            }
        };
        let plan_required = flag("plan_required")?;
        let direct = flag("direct_execution_enabled")?;
        if description.pointer("/prototype/plan_required")?.as_bool()? != plan_required
            || description
                .pointer("/prototype/direct_execution_enabled")?
                .as_bool()?
                != direct
        {
            return None;
        }
        // Catalog policy is not part of the global digest. Never infer it
        // from a matching description or from the operation's name.
        let catalog = json!({
            "access": catalog.get("access")?.as_str()?,
            "requires_acceptance": flag("requires_acceptance")?,
            "plan_required": plan_required,
            "direct_execution_enabled": direct,
        });
        Some(Self {
            description,
            catalog,
        })
    }

    /// Frozen v2 evidence omits only source prose; the exact digest stays for audit.
    pub(crate) fn for_custody(&self) -> Option<Self> {
        let mut contract = self.clone();
        contract
            .description
            .get_mut("source")?
            .as_object_mut()?
            .remove("tool_description");
        Some(contract)
    }

    /// Validate the stored shape through the same coherent-pair parser as discovery.
    /// A placeholder restores the deliberately omitted prose, never behavioural fields.
    pub(crate) fn valid_evidence(&self, executor: &str, operation: &str, digest: &str) -> bool {
        if !self.description.is_object()
            || !self.description["source"].is_object()
            || digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return false;
        }
        let Some(policy) = self.catalog.as_object() else {
            return false;
        };
        if policy.len() != 4
            || !matches!(self.catalog["access"].as_str(), Some("read" | "mutation"))
            || [
                "requires_acceptance",
                "plan_required",
                "direct_execution_enabled",
            ]
            .iter()
            .any(|key| !self.catalog[*key].is_boolean())
            || self.description["executor"] != executor
            || self.description["operation"] != operation
            || self.description["contract_digest"] != digest
            || self.description.get("run_context").is_some()
            || self
                .description
                .pointer("/source/tool_description")
                .is_some()
        {
            return false;
        }
        let d = &self.description;
        let row = json!({"executor":d["executor"], "operation":d["operation"],
            "surface":d["surface"], "contract_version":d["contract_version"],
            "contract_digest":d["contract_digest"], "source_tool":d["source"]["tool"],
            "selector_field":d["source"]["selector"]["field"],
            "selector_value":d["source"]["selector"]["value"],
            "access":self.catalog["access"], "requires_acceptance":self.catalog["requires_acceptance"],
            "plan_required":self.catalog["plan_required"], "direct_execution_enabled":self.catalog["direct_execution_enabled"]});
        let mut restored = self.description.clone();
        restored["source"]["tool_description"] = json!("Prose omitted from custody evidence");
        Self::from_hosted(restored, &row)
            .and_then(|c| c.for_custody())
            .as_ref()
            == Some(self)
    }

    pub(crate) fn valid_hosted_evidence(&self, executor: &str, operation: &str) -> bool {
        self.description
            .pointer("/source/tool_description")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
            && self.for_custody().is_some_and(|c| {
                c.valid_evidence(
                    executor,
                    operation,
                    self.description["contract_digest"].as_str().unwrap_or(""),
                )
            })
    }

    pub(crate) fn matches_custody(&self, other: &Self) -> bool {
        let normalized = |contract: &Self| -> Option<Value> {
            let mut d = contract.for_custody()?.description;
            d.as_object_mut()?.remove("contract_digest")?;
            Some(d)
        };
        self.catalog == other.catalog
            && normalized(self).is_some_and(|d| Some(d) == normalized(other))
    }

    fn without_prose(&self) -> Option<Value> {
        let mut description = self.description.clone();
        description.as_object_mut()?.remove("contract_digest")?;
        description
            .get_mut("source")?
            .as_object_mut()?
            .remove("tool_description")?;
        Some(description)
    }
}

impl NodeOperationContracts {
    /// The ordinary provider's source-tool/selector projection, for an original
    /// first-party working call. Routing/context is captured separately; it is
    /// never reconstructed from these arguments during replay.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn working_native_arguments(
        &self,
        executor: &str,
        operation: &str,
        arguments: &Value,
    ) -> crate::Result<(String, Value)> {
        let contract = self
            .contracts
            .get(&(executor.into(), operation.into()))
            .ok_or_else(|| crate::Error::engine("working native operation contract missing"))?;
        if !contract.kernel_v2
            || contract.access != OperationAccess::Mutation
            || contract.plan_required
            || !matches!(
                acceptance::declaration(executor, operation),
                Some(acceptance::Acceptance::LocalFirst)
            )
        {
            return Err(crate::Error::engine("operation requires hosted acceptance"));
        }
        Ok((
            contract.source_tool.clone(),
            translate_arguments(contract, &json!({"arguments":arguments}))?,
        ))
    }

    pub(crate) fn holding_contract(
        &self,
        executor: &str,
        operation: &str,
    ) -> Option<NodeHoldingContract> {
        let contract = self.contracts.get(&(executor.into(), operation.into()))?;
        Some(NodeHoldingContract {
            description: contract.payload(),
            catalog: json!({
                "access": match contract.access { OperationAccess::Read => "read", OperationAccess::Mutation => "mutation" },
                "requires_acceptance": acceptance::requires_acceptance(executor, operation),
                "plan_required": contract.plan_required,
                "direct_execution_enabled": !contract.plan_required,
            }),
        })
    }

    pub(crate) fn matches_holding_contract(
        &self,
        executor: &str,
        operation: &str,
        hosted: &NodeHoldingContract,
    ) -> bool {
        let Some(local) = self.holding_contract(executor, operation) else {
            return false;
        };
        hosted.catalog == local.catalog
            && hosted
                .without_prose()
                .is_some_and(|description| Some(description) == local.without_prose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_catalog(contract: &NodeHoldingContract) -> Value {
        let d = &contract.description;
        json!({
            "contract_digest":d["contract_digest"], "contract_version":d["contract_version"],
            "executor":d["executor"], "operation":d["operation"], "surface":d["surface"],
            "source_tool":d["source"]["tool"],
            "selector_field":d["source"]["selector"]["field"],
            "selector_value":d["source"]["selector"]["value"],
            "access":contract.catalog["access"],
            "plan_required":i64::from(contract.catalog["plan_required"].as_bool().unwrap()),
            "direct_execution_enabled":i64::from(contract.catalog["direct_execution_enabled"].as_bool().unwrap()),
            "requires_acceptance":i64::from(contract.catalog["requires_acceptance"].as_bool().unwrap()),
        })
    }

    #[test]
    fn holding_contract_ignores_only_source_prose_and_keeps_policy() {
        let contracts = NodeOperationContracts::local().unwrap();
        let local = contracts
            .holding_contract("records_write", "create_record")
            .unwrap();
        let digest = contracts.digest("records_write", "create_record").unwrap();
        assert_eq!(local.description["contract_digest"], digest);
        let catalog = raw_catalog(&local);
        let mut wire_description = local.description.clone();
        wire_description["run_context"] = json!({"run_key":"hosted-run", "intent":"current run"});
        let hosted = NodeHoldingContract::from_hosted(wire_description, &catalog).unwrap();
        assert!(contracts.matches_holding_contract("records_write", "create_record", &hosted));
        let mut changed = local.clone();
        changed.description["source"]["tool_description"] =
            json!("A new explanation of the same tool");
        changed.description["contract_digest"] = json!("different-hosted-digest");
        let hosted =
            NodeHoldingContract::from_hosted(changed.description.clone(), &raw_catalog(&changed))
                .unwrap();
        assert!(contracts.matches_holding_contract("records_write", "create_record", &hosted));
        assert_eq!(
            contracts.digest("records_write", "create_record"),
            Some(digest)
        );
        for (pointer, value) in [
            (
                "/input_schema/description",
                json!("Schema prose remains part of equality"),
            ),
            (
                "/input_schema/properties/new_optional",
                json!({"type":"string"}),
            ),
            ("/source/tool", json!("different_handler")),
            (
                "/source/selector",
                json!({"field":"action","value":"other"}),
            ),
            ("/prototype/plan_required", json!(true)),
            ("/contract_version", json!("future")),
        ] {
            let mut incompatible = hosted.clone();
            if let Some(slot) = incompatible.description.pointer_mut(pointer) {
                *slot = value;
            } else if pointer == "/input_schema/description" {
                incompatible.description["input_schema"]["description"] = value;
            } else if pointer == "/input_schema/properties/new_optional" {
                incompatible.description["input_schema"]["properties"]["new_optional"] = value;
            } else {
                panic!("missing fixture pointer {pointer}");
            }
            assert!(
                !contracts.matches_holding_contract(
                    "records_write",
                    "create_record",
                    &incompatible
                ),
                "{pointer}"
            );
        }
        for (field, value) in [
            ("access", json!("read")),
            ("requires_acceptance", json!(true)),
            ("direct_execution_enabled", json!(false)),
        ] {
            let mut incompatible = hosted.clone();
            incompatible.catalog[field] = value;
            assert!(
                !contracts.matches_holding_contract(
                    "records_write",
                    "create_record",
                    &incompatible
                ),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn holding_contract_accepts_production_describe_and_sql_catalog_shapes() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let server = ExecutorPrototypeStdioServer::new(
            Arc::new(registry),
            db.clone(),
            Caller::local(),
            None,
        )
        .await
        .unwrap();
        let described = server.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"describe_operation","arguments":{"executor":"records_write","operation":"create_record"}}})).await.unwrap();
        let catalog = server.handle_message(json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"sql_read","arguments":{"operation":"query_sql","arguments":{"sql":"SELECT * FROM catalog_operations WHERE executor = 'records_write' AND operation = 'create_record'"},"format":"json"}}})).await.unwrap();
        let description = described["result"]["structuredContent"].clone();
        assert!(description.get("run_context").is_some(), "{described}");
        let rows = catalog["result"]["structuredContent"]["rows"]
            .as_array()
            .expect("live SQL catalog rows");
        assert_eq!(rows.len(), 1, "{catalog}");
        let evidence = NodeHoldingContract::from_hosted(description, &rows[0])
            .expect("live descriptor and catalog are coherent");
        assert!(NodeOperationContracts::local()
            .unwrap()
            .matches_holding_contract("records_write", "create_record", &evidence));
        db.close().await;
    }

    #[test]
    fn holding_contract_refuses_incoherent_and_incomplete_discovery() {
        let local = NodeOperationContracts::local()
            .unwrap()
            .holding_contract("records_write", "create_record")
            .unwrap();
        for field in [
            "contract_digest",
            "access",
            "requires_acceptance",
            "selector_value",
            "plan_required",
        ] {
            let mut catalog = raw_catalog(&local);
            catalog.as_object_mut().unwrap().remove(field);
            assert!(
                NodeHoldingContract::from_hosted(local.description.clone(), &catalog).is_none(),
                "{field}"
            );
        }
        let mut catalog = raw_catalog(&local);
        catalog["contract_digest"] = json!("other");
        assert!(NodeHoldingContract::from_hosted(local.description.clone(), &catalog).is_none());
        let mut description = local.description.clone();
        description["source"]["tool_description"] = Value::Null;
        assert!(NodeHoldingContract::from_hosted(description, &raw_catalog(&local)).is_none());
        let mut catalog = raw_catalog(&local);
        catalog["requires_acceptance"] = json!(2);
        assert!(NodeHoldingContract::from_hosted(local.description, &catalog).is_none());
    }
}
