//! Caller-selected imported association, never native workspace or authority.
use super::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberSourceContext {
    person_record_id: String,
    root_record_id: String,
}

impl MemberSourceContext {
    pub(crate) fn decode(raw: &str) -> Result<Option<Self>> {
        let selected: Option<Self> = serde_json::from_str(raw).map_err(|_| Refusal::Content)?;
        if selected.as_ref().is_some_and(|value| {
            value.person_record_id.trim().is_empty() || value.root_record_id.trim().is_empty()
        }) {
            return Err(Refusal::Content);
        }
        Ok(selected)
    }

    /// Both exact references must be ordinary live rows in this generation.
    /// A selected source tuple which fails closure is refused, never omitted.
    pub(super) fn validate_held(selected: &Option<Self>, connection: &Connection) -> Result<()> {
        if let Some(value) = selected {
            for id in [&value.person_record_id, &value.root_record_id] {
                let count: i64 = storage(connection.query_row(
                    "SELECT COUNT(*) FROM main.records WHERE id=? AND deleted_at IS NULL",
                    [id],
                    |row| row.get(0),
                ))?;
                if count != 1 {
                    return Err(Refusal::Content);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn response(selected: Option<Self>) -> serde_json::Value {
        match selected {
            None => serde_json::Value::Null,
            Some(value) => serde_json::json!({
                "status":"held",
                "identity_basis":"retained v1 member context",
                "reference_basis":"both references visible at capture and held in this member generation",
                "person_record_id":value.person_record_id,
                "root_record_id":value.root_record_id,
            }),
        }
    }
}
