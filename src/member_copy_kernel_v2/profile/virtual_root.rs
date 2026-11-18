//! A source-authorized virtual descriptor, never an ordinary held record.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberVirtualRoot {
    pub id: String,
    pub kernel_root_id: String,
    pub virtual_root: bool,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: String,
    pub name: String,
    pub home_id: Option<String>,
    pub persistence: String,
    pub last_activity_at: String,
    pub archived: bool,
    pub custody_boundary: bool,
    pub containment_path_visible: bool,
}
impl MemberVirtualRoot {
    pub(crate) fn decode(raw: &str) -> std::result::Result<Option<Self>, ()> {
        let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| ())?;
        if value.is_null() {
            return Ok(None);
        }
        if value.as_object().is_none_or(|object| object.len() != 12) {
            return Err(());
        }
        let root: Self = serde_json::from_value(value).map_err(|_| ())?;
        if !root.valid() {
            return Err(());
        }
        Ok(Some(root))
    }
    pub(crate) fn valid(&self) -> bool {
        self.id == crate::schema::ROOT_RECORD_ID
            && self.kernel_root_id == crate::events::KERNEL_ROOT_ID
            && self.virtual_root
            && self.record_type == "Collection"
            && self.kind == "folder"
            && self.home_id.is_none()
            && self.persistence == "enduring"
            && !self.archived
            && self.containment_path_visible
    }
    pub(crate) fn is_alias(id: &str) -> bool {
        [crate::schema::ROOT_RECORD_ID, crate::events::KERNEL_ROOT_ID].contains(&id)
    }
}

pub(super) async fn capture(
    source: &mut sqlx::SqliteConnection,
    actor: &str,
) -> Result<Option<MemberVirtualRoot>> {
    let Some(value) =
        crate::mcp::kernel_v2::member_virtual_root_on(source, actor, crate::schema::ROOT_RECORD_ID)
            .await
            .map_err(|_| Refusal::Authorization)?
    else {
        return Ok(None);
    };
    if value["kernel_v2"]["virtual_root"] != true {
        return Err(Refusal::Content);
    }
    // Select only the descriptor fields needed for member orientation/tree.
    // The source response's owner, versions and stream facts are not shipped.
    let text = |key: &str| {
        value[key]
            .as_str()
            .map(str::to_owned)
            .ok_or(Refusal::Content)
    };
    let root = MemberVirtualRoot {
        id: text("id")?,
        kernel_root_id: crate::events::KERNEL_ROOT_ID.into(),
        virtual_root: true,
        record_type: text("type")?,
        kind: text("kind")?,
        name: text("name")?,
        home_id: serde_json::from_value(value.get("home_id").ok_or(Refusal::Content)?.clone())
            .map_err(|_| Refusal::Content)?,
        persistence: text("persistence")?,
        last_activity_at: text("last_activity_at")?,
        archived: value["archived"].as_bool().ok_or(Refusal::Content)?,
        custody_boundary: crate::mcp::kernel_v2::custody_boundary_on(
            source,
            crate::schema::ROOT_RECORD_ID,
        )
        .await
        .map_err(|_| Refusal::Storage)?,
        containment_path_visible: crate::mcp::kernel_v2::native_containment_path_visible_on(
            source,
            actor,
            crate::schema::ROOT_RECORD_ID,
        )
        .await
        .map_err(|_| Refusal::Authorization)?,
    };
    if !root.valid() {
        return Err(Refusal::Content);
    }
    Ok(Some(root))
}
