//! Read imported K3 bindings through the same kernel record authority as apps.
use super::*;
use crate::mcp::tools::surface_bindings as v1;
use crate::surface_binding::{
    self as core, Mode, Surface, SurfaceBinding, SurfaceRequest, TargetStatus, Who,
};
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Args {
    Get {
        surface: String,
        subject: Option<String>,
    },
}
#[derive(Deserialize)]
struct Stored {
    id: String,
    source_id: String,
    target_id: String,
    note: Option<String>,
}
pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler_for_selector_values("manage_surface_bindings",EngineKind::KernelV2,"action",&["get"],|engine,caller,args|async move {
        let EngineHandle::KernelV2(db)=engine else {unreachable!()};
        let actor=principal(&db,&caller).await?;
        let Args::Get {surface,subject}=parse("manage_surface_bindings",args)?;
        let surface=v1::parse_surface(&surface)?;
        v1::parse_subject(subject.as_deref())?;
        let mut tx=db.pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx,&actor).await?;
        kernel::v1_state::require_surface_capture_on(&mut tx).await?;
        let person=identity_read::own_person_on(&mut tx,&actor).await?;
        let rows:Vec<String>=sqlx::query_scalar("SELECT payload FROM main.kernel_v1_state WHERE section='surface_bindings' AND (json_extract(payload,'$.source_id')='native:root' OR json_extract(payload,'$.source_id')=?) ORDER BY source_id").bind(person).fetch_all(&mut *tx).await?;
        let mut bindings=vec![];
        for raw in rows {
            let row:Stored=serde_json::from_str(&raw)?;
            let Some(descriptor)=v1::decode_descriptor(row.note.as_deref()) else {continue};
            let Some(subject)=v1::descriptor_subject(&descriptor) else {continue};
            let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_records WHERE id=? AND NOT EXISTS(SELECT 1 FROM main.kernel_import_tombstones WHERE record_id=?))").bind(&row.target_id).bind(&row.target_id).fetch_one(&mut *tx).await?;
            let status=if !present {TargetStatus::Missing} else if let Some(record)=kernel::read_record_on(&mut tx,&actor,&row.target_id).await? {
                let primary:Option<String>=sqlx::query_scalar("SELECT primary_type FROM main.kernel_records WHERE id=?").bind(&row.target_id).fetch_one(&mut *tx).await?;
                if v1_type_and_kind(record.family.as_deref(),record.pin.as_ref().map(|p|p.version),primary.as_deref(),record.kind.as_deref(),&record.fields)!=(Some("Document"),Some("artifact")) {TargetStatus::WrongRecordType}
                else if record.archived {TargetStatus::Archived} else {TargetStatus::Resolvable}
            } else {TargetStatus::Unauthorized};
            bindings.push(SurfaceBinding {binding_id:row.id,who:if row.source_id=="native:root" {Who::Workspace}else{Who::Principal},subject,surface:Surface::Home,mode:if descriptor.mode=="trusted" {Mode::Trusted}else{Mode::Isolated},target:Some(row.target_id),status});
        }
        let request=SurfaceRequest::environment();
        Ok(v1::resolution_json(surface,&request,&core::resolve(surface,&request,&bindings)))
    })
}
