//! Target-authorized retained interventions; no delivery or policy re-evaluation.
use super::*;
use crate::mcp::tools::interventions as v1;
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Args {
    Get { intervention_id: String },
}
const UNAVAILABLE: &str = "manage_interventions: intervention unavailable";
pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler_for_selector_values("manage_interventions",EngineKind::KernelV2,"action",&["get"],|engine,caller,args|async move {
        let EngineHandle::KernelV2(db)=engine else {unreachable!()};
        let actor=principal(&db,&caller).await?;
        let Args::Get {intervention_id}=parse("manage_interventions",args)?;
        let mut tx=db.pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx,&actor).await?;
        let events:Vec<String>=sqlx::query_scalar("SELECT e.payload FROM main.kernel_legacy_sql_events h JOIN main.content_events e ON e.seq=h.seq WHERE h.source_stream='content_events' AND h.event_type IN ('intervention.raised.v1','intervention.cancelled.v1','intervention.execution_resumed.v1') AND json_extract(e.payload,'$.legacy.payload.intervention_id')=? ORDER BY h.seq").bind(&intervention_id).fetch_all(&mut *tx).await?;
        let mut raised:Option<(i64,Value)>=None;let mut terminal:Option<(i64,String)>=None;let mut latest_seq:i64=0;
        for raw in events {
            let envelope:Value=serde_json::from_str(&raw)?;let legacy=&envelope["legacy"];
            let seq=legacy["source"]["metadata"]["seq"].as_i64().filter(|n|*n>0).ok_or_else(||Error::auth(UNAVAILABLE))?;
            latest_seq=latest_seq.max(seq);
            match legacy["event_type"].as_str() {
                Some("intervention.raised.v1") if raised.as_ref().is_none_or(|(old,_)|seq<*old)=>raised=Some((seq,legacy.clone())),
                Some(kind@("intervention.cancelled.v1"|"intervention.execution_resumed.v1")) if terminal.as_ref().is_none_or(|(old,_)|seq>*old)=>terminal=Some((seq,kind.to_owned())),
                _=>{}
            }
        }
        let (event_seq,legacy)=raised.ok_or_else(||Error::auth(UNAVAILABLE))?;
        let payload=&legacy["payload"];
        let person=payload["target_person_record_id"].as_str().ok_or_else(||Error::auth(UNAVAILABLE))?;
        let target=payload["target_principal_id"].as_str().ok_or_else(||Error::auth(UNAVAILABLE))?;
        // Authorize before decoding private retained fields, including malformed
        // envelopes; another member sees only the same unavailable refusal.
        if !identity_read::owns_intervention_target_on(&mut tx,&actor,person,target).await? {return Err(Error::auth(UNAVAILABLE));}
        let raised=v1::Raised {message_id:legacy["source"]["metadata"]["record_id"].as_str().ok_or_else(||Error::auth(UNAVAILABLE))?.into(),event_seq,event_created_at:legacy["created_at"].as_str().ok_or_else(||Error::auth(UNAVAILABLE))?.into(),payload:serde_json::from_value(payload.clone())?};
        let origin:Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.origin') FROM main.content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_optional(&mut *tx).await?;
        let database_id=origin.ok_or_else(||Error::engine("manage_interventions: retained resolver database identity unavailable"))?;
        let state=kernel::messaging::on(&mut tx,&raised.message_id).await?.ok_or_else(||Error::engine("manage_interventions: retained Message state unavailable"))?;
        let created=match state.created_at.as_ref() {Some(value)=>value.clone(),None=>sqlx::query_scalar("SELECT created_at FROM main.kernel_legacy_sql_events WHERE record_id=? AND source_stream='snapshot_provenance' ORDER BY seq DESC LIMIT 1").bind(&raised.message_id).fetch_optional(&mut *tx).await?.ok_or_else(||Error::engine("manage_interventions: retained Message creation time unavailable; prepare the original import before H3 activation"))?};
        let mut obligation=super::messaging::expectation_value(&mut tx,&actor,&raised.message_id,&state).await?;
        obligation["recipient_id"]=json!(caller.credential());
        let execution=match terminal.as_ref().map(|(_,k)|k.as_str()) {Some("intervention.cancelled.v1")=>"cancelled",Some("intervention.execution_resumed.v1")=>"resumed",_ if raised.payload.disposition=="block_and_request_authority"=>"blocked",_=>"proceeded"};
        let mut result=v1::view_response(&intervention_id,&raised,&database_id,&created,latest_seq,execution,obligation);
        for affordance in result["affordances"].as_array_mut().into_iter().flatten() {affordance["enabled"]=json!(false);affordance["reason_code"]=json!("retained_read_only");}
        result["action"]=json!("get");
        result["mutations_available"]=json!(false);result["unavailable_message"]=json!("Imported interventions are read-only on this workspace. Resuming delivery and cancelling interventions aren't available yet.");
        Ok(result)
    })
}
