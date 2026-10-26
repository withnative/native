//! Executable declarative permissions. Parsing and bounds are shared with v1.
use super::*;
use crate::mcp::tools::{alpha_tabs, effect_bounds};

pub(crate) struct Declarative {
    pub sql: Vec<alpha_tabs::SqlNeed>,
    pub needs: Vec<String>,
}

pub(crate) fn declarative(declaration: &Value) -> Result<Declarative> {
    let object = declaration
        .as_object()
        .ok_or_else(|| invalid(NOT_YET_AVAILABLE))?;
    if object.len() != 2 || !object.contains_key("needs") || !object.contains_key("effects") {
        return Err(invalid(NOT_YET_AVAILABLE));
    }
    let parsed = alpha_tabs::require_declaration(declaration)?;
    if parsed
        .needs
        .iter()
        .any(|need| need != alpha_tabs::RECORDS_SEARCH_NEED)
        || parsed.effects.iter().any(|effect| {
            !matches!(
                effect.as_str(),
                "records.body-set.v1" | "records.title-set.v1"
            )
        })
    {
        return Err(invalid(NOT_YET_AVAILABLE));
    }
    effect_bounds::parse_body_set_bounds(declaration).map_err(Error::engine)?;
    effect_bounds::parse_title_set_bounds(declaration).map_err(Error::engine)?;
    let mut sql = declaration["needs"]
        .as_array()
        .ok_or_else(|| invalid(NOT_YET_AVAILABLE))?
        .iter()
        .filter(|entry| entry.is_object())
        .map(alpha_tabs::parse_sql_need_entry)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Error::engine)?;
    sql.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(Declarative {
        sql,
        needs: parsed.needs,
    })
}

pub(crate) fn source_supported(declaration: &Value) -> bool {
    contract_supported(declaration) || declarative(declaration).is_ok()
}

pub(crate) fn consent_names(declaration: &Value) -> Result<(Vec<String>, Vec<String>)> {
    let mut parsed = alpha_tabs::require_declaration(declaration)?;
    parsed.needs.sort();
    parsed.effects.sort();
    Ok((parsed.needs, parsed.effects))
}

pub(super) fn activation_supported(format: u32, declaration: &Value) -> bool {
    contract_supported(declaration) || (format >= 5 && declarative(declaration).is_ok())
}
