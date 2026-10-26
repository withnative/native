//! Reader-only generated-facet payload. No current-state or compiler work here.
use super::{contract, invalid, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Definition {
    pub query: contract::SavedSqlV12,
    pub origin: contract::Origin,
    pub description: String,
    pub scope: contract::Scope,
    pub columns: std::collections::BTreeMap<String, contract::FieldMeaning>,
    pub source_pins: Vec<contract::SourcePin>,
    pub generated: Manifest,
}
impl Definition {
    pub(super) fn common(&self) -> contract::Definition {
        contract::Definition {
            query: self.query.clone(),
            origin: self.origin.clone(),
            description: self.description.clone(),
            scope: self.scope.clone(),
            columns: self.columns.clone(),
            source_pins: self.source_pins.clone(),
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.common().validate_retained()?;
        self.generated.validate()?;
        let contract::Origin::Generated {
            generator,
            version,
            source_identity: _,
            selector,
        } = &self.origin
        else {
            return Err(invalid("v2 requires generated facet origin"));
        };
        let canonical = native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &serde_json::json!({"context":self.generated.context,"selection":self.generated.selection}),
        );
        if generator != "native.declared-relational-defaults"
            || version != "facet-1"
            || selector.as_bytes() != canonical
            || !self.source_pins.is_empty()
        {
            return Err(invalid("v2 generated origin/selector/source pins mismatch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub format: String,
    pub workspace_id: String,
    pub context: Context,
    pub selection: Selection,
    pub sources: Vec<Source>,
    pub slots: Vec<Slot>,
    pub governance_basis: Vec<Governance>,
    pub vocabularies: Vec<Vocabulary>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub r#type: String,
    pub kind: Option<String>,
    pub logical_home_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Selection {
    Keys { keys: Vec<String> },
    All,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(super) enum Section {
    SchemaConfig,
    Vocabularies,
    VocabularyValues,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub section: Section,
    pub source_id: String,
    pub origin: String,
    pub row_id: String,
    pub event_id: String,
    pub event_sha256: String,
    pub anchor: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scope {
    Global,
    Home,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Layer {
    Pack,
    User,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Slot {
    pub scope: Scope,
    pub layer: Layer,
    pub shape_key: String,
    pub fragments: Vec<Fragment>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fragment {
    pub source: usize,
    pub key: String,
    pub decl: Declaration,
    pub lineage: Option<String>,
    pub created_at: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    pub r#type: Option<FieldType>,
    pub description: Option<String>,
    pub required: Option<bool>,
    pub vocab: Option<String>,
    pub vocab_ref: Option<String>,
    pub unit: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FieldType {
    Number,
    Date,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Governance {
    pub source: usize,
    pub shape_key: String,
    pub lineage: Option<String>,
    pub created_at: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Vocabulary {
    pub field: String,
    pub source: usize,
    pub values: Vec<VocabularyValue>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Status {
    Active,
    Proposed,
    Deprecated,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VocabularyValue {
    pub source: usize,
    pub id: String,
    pub token: String,
    pub status: Status,
    pub alias_of: Option<String>,
    pub canonical_id: String,
    pub canonical_token: String,
}
fn text(s: &str, cap: usize) -> Result<()> {
    if s.is_empty() || s.len() > cap || s.contains('\0') {
        return Err(invalid("v2 text bound"));
    }
    Ok(())
}
fn optional(s: &Option<String>, cap: usize) -> Result<()> {
    s.as_deref().map(|s| text(s, cap)).transpose().map(|_| ())
}
impl Manifest {
    fn source(&self, index: usize, section: Section) -> Result<&Source> {
        self.sources
            .get(index)
            .filter(|s| s.section == section)
            .ok_or_else(|| invalid("v2 source cross-reference mismatch"))
    }
    fn validate(&self) -> Result<()> {
        if self.format != "native.generated-facets.v1"
            || self.sources.len() > 288
            || self.slots.len() != 8
        {
            return Err(invalid("v2 manifest format/source/slot bound"));
        }
        text(&self.workspace_id, 128)?;
        text(&self.context.r#type, 128)?;
        optional(&self.context.kind, 128)?;
        text(&self.context.logical_home_id, 128)?;
        let mut source_keys = BTreeSet::new();
        let mut value_count = 0;
        for source in &self.sources {
            value_count += usize::from(source.section == Section::VocabularyValues);
            text(&source.source_id, 1024)?;
            let keys: Vec<String> = serde_json::from_str(&source.source_id)?;
            if keys != [source.row_id.clone()]
                || keys.iter().any(|k| text(k, 128).is_err())
                || serde_json::to_string(&keys)? != source.source_id
                || !source_keys.insert((&source.section, &source.source_id))
                || uuid::Uuid::parse_str(&source.event_id).is_err()
                || !contract::sha256(&source.event_sha256)
            {
                return Err(invalid("v2 source identity mismatch"));
            }
            text(&source.origin, 128)?;
            text(&source.row_id, 128)?;
            optional(&source.anchor, 128)?;
            if source.section != Section::SchemaConfig && source.anchor.is_some() {
                return Err(invalid("v2 vocabulary source has no record ACL anchor"));
            }
        }
        if value_count > 256 || self.sources.len() - value_count > 32 {
            return Err(invalid("v2 source category bound"));
        }
        let selected = match &self.selection {
            Selection::Keys { keys } => {
                if keys.is_empty() || keys.len() > 18 || keys.windows(2).any(|p| p[0] >= p[1]) {
                    return Err(invalid("v2 selected keys bound/order"));
                }
                keys.iter().cloned().collect::<BTreeSet<_>>()
            }
            Selection::All => self
                .slots
                .iter()
                .flat_map(|s| s.fragments.iter().map(|f| f.key.clone()))
                .collect(),
        };
        if selected.is_empty() || selected.len() > 18 {
            return Err(invalid("v2 selected field bound"));
        }
        for key in &selected {
            text(key, 128)?;
        }
        let kind_key = self
            .context
            .kind
            .as_ref()
            .map(|k| format!("{}:{k}", self.context.r#type));
        let mut used = BTreeSet::new();
        let mut declarations = std::collections::BTreeMap::new();
        for (i, slot) in self.slots.iter().enumerate() {
            let expected_shape = if i % 4 < 2 {
                &self.context.r#type
            } else {
                kind_key.as_ref().unwrap_or(&self.context.r#type)
            };
            if slot.scope != if i < 4 { Scope::Global } else { Scope::Home }
                || slot.layer != if i % 2 == 0 { Layer::Pack } else { Layer::User }
                || &slot.shape_key != expected_shape
                || (self.context.kind.is_none() && i % 4 >= 2 && !slot.fragments.is_empty())
                || slot.fragments.len() > 128 * selected.len()
            {
                return Err(invalid("v2 cascade slot mismatch"));
            }
            let mut pairs = BTreeSet::new();
            for fragment in &slot.fragments {
                let source = self.source(fragment.source, Section::SchemaConfig)?;
                if !selected.contains(&fragment.key)
                    || !pairs.insert((fragment.source, &fragment.key))
                    || source.anchor.as_deref()
                        != match slot.scope {
                            Scope::Global => None,
                            Scope::Home => Some(self.context.logical_home_id.as_str()),
                        }
                {
                    return Err(invalid("v2 fragment context mismatch"));
                }
                used.insert(fragment.source);
                optional(&fragment.lineage, 512)?;
                text(&fragment.created_at, 64)?;
                {
                    let decl = &fragment.decl;
                    optional(&decl.description, 256)?;
                    optional(&decl.unit, 128)?;
                    optional(&decl.vocab, 128)?;
                    optional(&decl.vocab_ref, 128)?;
                    if decl.vocab.is_some()
                        && decl.vocab_ref.is_some()
                        && decl.vocab != decl.vocab_ref
                    {
                        return Err(invalid("v2 ambiguous vocabulary declaration"));
                    }
                    declarations.insert(&fragment.key, decl);
                }
            }
        }
        if declarations.len() != selected.len() {
            return Err(invalid("v2 selected declaration absent"));
        }
        if self.governance_basis.is_empty() || self.governance_basis.len() > 64 {
            return Err(invalid("v2 governance bound"));
        }
        let mut governance = BTreeSet::new();
        for row in &self.governance_basis {
            let source = self.source(row.source, Section::SchemaConfig)?;
            if source.anchor.as_deref() != Some(&self.context.logical_home_id)
                || !(row.shape_key == self.context.r#type
                    || kind_key.as_ref() == Some(&row.shape_key))
                || !governance.insert((row.source, &row.shape_key))
            {
                return Err(invalid("v2 governance context mismatch"));
            }
            used.insert(row.source);
            optional(&row.lineage, 512)?;
            text(&row.created_at, 64)?;
        }
        let mut fields = BTreeSet::new();
        for vocab in &self.vocabularies {
            let source = self.source(vocab.source, Section::Vocabularies)?;
            let decl = declarations
                .get(&vocab.field)
                .ok_or_else(|| invalid("v2 vocabulary field absent"))?;
            let reference = decl.vocab_ref.as_ref().or(decl.vocab.as_ref());
            if !fields.insert(&vocab.field)
                || vocab.values.len() > 64
                || decl.r#type.is_some()
                || reference.map(|s| crate::meta::vocabulary::resolve_vocab_ref(s))
                    != Some(source.row_id.as_str())
            {
                return Err(invalid("v2 vocabulary declaration mismatch"));
            }
            used.insert(vocab.source);
            let mut ids = BTreeSet::new();
            let mut tokens = BTreeSet::new();
            for value in &vocab.values {
                let row = self.source(value.source, Section::VocabularyValues)?;
                if row.row_id != value.id || !ids.insert(&value.id) || !tokens.insert(&value.token)
                {
                    return Err(invalid("v2 vocabulary value identity mismatch"));
                }
                for s in [&value.id, &value.canonical_id] {
                    text(s, 128)?;
                }
                for s in [&value.token, &value.canonical_token] {
                    text(s, 512)?;
                }
                optional(&value.alias_of, 128)?;
                used.insert(value.source);
            }
            for value in &vocab.values {
                let mut terminal = value;
                let mut seen = BTreeSet::new();
                while let Some(target) = &terminal.alias_of {
                    if !seen.insert(&terminal.id) {
                        return Err(invalid("v2 vocabulary alias cycle"));
                    }
                    terminal = vocab
                        .values
                        .iter()
                        .find(|v| &v.id == target)
                        .ok_or_else(|| invalid("v2 vocabulary alias missing"))?;
                }
                if terminal.id != value.canonical_id {
                    return Err(invalid("v2 vocabulary alias target mismatch"));
                }
                let canonical = vocab
                    .values
                    .iter()
                    .find(|v| v.id == value.canonical_id)
                    .ok_or_else(|| invalid("v2 canonical vocabulary value missing"))?;
                if canonical.alias_of.is_some()
                    || canonical.canonical_id != canonical.id
                    || canonical.canonical_token != canonical.token
                    || canonical.token != value.canonical_token
                    || value.alias_of.as_ref().is_some_and(|id| !ids.contains(id))
                    || (value.alias_of.is_none() && value.id != canonical.id)
                {
                    return Err(invalid("v2 vocabulary mapping mismatch"));
                }
            }
        }
        if declarations
            .iter()
            .any(|(k, d)| (d.vocab.is_some() || d.vocab_ref.is_some()) && !fields.contains(k))
            || used.len() != self.sources.len()
        {
            return Err(invalid("v2 vocabulary/source coverage mismatch"));
        }
        Ok(())
    }
}
