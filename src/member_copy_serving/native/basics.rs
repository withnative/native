use super::*;
use std::collections::BTreeSet;

pub(super) fn schema_rows(
    file: &AdmittedMemberFile,
) -> Result<Vec<crate::query::cascade::SchemaConfigRow>> {
    let mut rows = Vec::new();
    for row in NativeReader::rows(file, "schema_config")? {
        let text = |key: &str| {
            row[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| unavailable("schema_config"))
        };
        rows.push(crate::query::cascade::SchemaConfigRow {
            id: text("id")?,
            layer: text("layer")?,
            name: row["name"].as_str().map(str::to_owned),
            data: serde_json::from_str(&text("data")?)?,
            applies_to_collection_id: row["applies_to_collection_id"].as_str().map(str::to_owned),
            version_lineage: row["version_lineage"].as_str().map(str::to_owned),
            created_at: text("created_at")?,
        });
    }
    rows.sort_by(|a, b| {
        (a.layer != "pack", &a.created_at, &a.id).cmp(&(b.layer != "pack", &b.created_at, &b.id))
    });
    Ok(rows)
}

/// Schema rows have already passed the shared source authority and exact-ID
/// gates. Pure cascade folds and vocabulary presentation are shared with the
/// ordinary member contract; no canonical policy tables are fabricated.
pub(super) fn path(rows: &[Value], id: &str) -> (Vec<Value>, bool) {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = Some(id.to_owned());
    let mut complete = false;
    while let Some(id) = cursor.take() {
        if !seen.insert(id.clone()) {
            break;
        }
        let Some(row) = rows.iter().find(|row| row["id"] == id) else {
            break;
        };
        path.push(json!({"id":id,"name":row["name"],"type":row["type"]}));
        if id == "native:root" || id == crate::events::KERNEL_ROOT_ID {
            complete = true;
            break;
        }
        cursor = row["home_id"].as_str().map(str::to_owned);
    }
    path.reverse();
    (path, complete)
}
