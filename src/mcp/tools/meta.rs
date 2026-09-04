//! Tools 20–21 — the meta tier (docs/tool-surface.md §Vocabulary & schema
//! config).
//!
//! The meta tier is DIRECT-WRITE by design: `vocabularies`,
//! `vocabulary_values` and `schema_config` sit OUTSIDE the append-event →
//! project invariant (Fork C / 982f4b2), so these two tools call `crate::meta`
//! straight through. That is deliberate, not an omission — `schema_config`
//! carries its own `version_lineage` chain, explicitly distinct from the event
//! log, and rebuild-and-diff replays to `records`/`links`/`facet_values` only.
//!
//! Neither tool re-implements a guard it inherits.
//!
//! **Tool 20** is argument shape, dispatch and error mapping over an existing
//! API. `meta::vocabulary` is the enforcement site for the whole contract: the
//! propose/promote/deprecate/alias lifecycle, the seeded- and referenced-value
//! delete rejections, the dangling-`alias_of` rejection, and — with
//! `store::append`'s write-time resolution check — `facet_values.vocab_ref`
//! integrity. That last one is app-layer PERMANENTLY (e3e14cd), not a cheap
//! default pending a DDL foreign key: replay targets a fresh database whose
//! `vocabularies` table is empty, so an FK would break rebuild-and-diff. This
//! module therefore adds no integrity logic of its own.
//!
//! **Tool 21** carries declared types in addition to the three pre-existing
//! rejection families. They are not all of a kind — only the spine floor and
//! declared-type floor are directional:
//!
//!   - **(b) engine-reserved keys** (`archived`) — already implemented, in
//!     either direction, by `meta::schema_config::assert_no_reserved_facet_keys`
//!     inside `write_user_schema_config`. Wired here, not rebuilt.
//!   - **(c) cardinality on any facet key** (`multi`) — net-new, and symmetric
//!     like (b), for a related reason: the four spine facets project to scalar
//!     COLUMNS on `records` ([`crate::schema::spine_facet_column`]), while open
//!     facets are held by `facet_values` under `UNIQUE (record_id, key)`.
//!     Every facet is therefore single-valued, so `multi` is not loose or
//!     strict, it is INERT. The resolved view would advertise the claim
//!     faithfully and nothing in the engine would ever read it, so what the
//!     config says would not be true. See [`assert_no_facet_cardinality`], and
//!     the "what does NOT count as loosening" list below for why this is a
//!     rejection rather than a fifth limb of (a).
//!   - **(a) spine-facet loosening** — the interop floor (3057bba §4). Net-new,
//!     and the subject of its own section below.
//!   - **declared types** — decision 37de348 as amended. V1 accepts only
//!     `number` on eligible open facets, where a pack declaration is a nominal
//!     base+kind floor. Type declarations on string-carried spine facets are
//!     rejected until a typed sanctioned carrier exists.
//!     Accepted writes report, but never reject on, the count of historical
//!     stored values without a numeric projection; binding is forward-only.
//!
//! # Where each rejection is enforced, and why not all at one depth
//!
//! (b) is enforced in the ENGINE — `meta::schema_config::assert_no_reserved_facet_keys`,
//! inside `write_user_schema_config` — and wired here only for error ordering.
//! (a) and (c) are enforced HERE, at the tool, and nowhere below. That
//! asymmetry is a consequence of a rule, not an accident (ccbe12a):
//!
//! > **The engine guards the keys the engine itself owns; the product surface
//! > guards the promises the product surface makes.**
//!
//! (b) is the first kind. `archived` is written by
//! [`crate::store::archive_record`] / [`crate::store::restore_record`] and its
//! representation is enforced by the engine itself, in the projector fold:
//! `'true'` archives, UNSET restores, and every other value is refused
//! (`project_facet_set`). The key is engine-owned data end to end, and the
//! guard is a key-name test against [`crate::schema::ENGINE_RESERVED_FACET_KEYS`]
//! needing no read layer, so it sits with the engine that owns the key.
//!
//! (a) and (c) are the second kind. The interop floor is a promise that shared
//! skills keep working across installations; (c) is a promise that the resolved
//! view does not advertise a claim nothing reads. Both are owed to consumers of
//! the product surface, and both concern keys the USER layer owns — (a) cannot
//! even be judged without `query::cascade`.
//!
//! **What the rule does NOT claim.** None of the three is load-bearing for the
//! engine's own operation, (b) included. Nothing on any write path reads
//! `schema_config` — not `store::append`, not the projector, and not the
//! default query filters, which test `facet_values` for `key = 'archived'`
//! directly in SQL. So no user shape over `archived` can block or invalidate
//! `archive_record`'s write. What it can do is make the resolved view
//! CONTRADICT an invariant the engine enforces elsewhere: a consumer reading
//! `archived` as configurable emits writes the fold then refuses. That is a
//! sharper failure than (c)'s, where a `multi` claim on a facet key is merely
//! inert — but it is still a claim about the product surface's truthfulness,
//! not a dependency of the engine. The placement question is therefore where
//! these guards SHOULD live, not where they MUST, which is the next paragraph.
//!
//! Nor was the write API ever an enforcement boundary, which is the other half
//! of why placement is a choice. Both
//! `write_user_schema_config` and [`crate::db::Db::pool`] are `pub`, so anyone
//! positioned to call past the first can `INSERT INTO schema_config` through
//! the second, edit the SQLite file, or restore a doctored backup. Pushing (a)
//! and (c) down would buy "the sanctioned Rust API is safe by default" for a
//! library embedder — and e9f4b98 settles that v1 has none: hosted and the
//! self-host container are the supported surfaces, the MCP tool surface is the
//! sole supported API, and no crate is published. For every consumer that
//! exists, the two placements are behaviourally identical.
//!
//! Making the floor hold for a DATABASE rather than for a call path is a
//! different question with a different mechanism — a `conformance` check, which
//! catches the raw-SQL and hand-edited-file cases a call-path guard cannot.
//! Tracked separately (6c80f3e), not folded in here.
//!
//! `docs/tool-surface.md`'s tool 21 row carries the same rule; keep the two in
//! step.
//!
//! # Rejection (a): what "looser than pack" means
//!
//! The *rule* is settled (3057bba §4, confirmed by Richard): the user layer
//! **may** loosen a pack/recommended shape — opting out of a recommendation is
//! a hackable-seed file's prerogative — and **may not** loosen a spine facet
//! (`lifecycle`, `owner`, `persistence`, `maturity`), because shared skills
//! hard-dispatch on those and loosening one *is* forking core. What no artifact
//! settles is the comparison PREDICATE. This module fixes it, on the narrowest
//! reading that still holds the floor, following upstream `fca675c` §5 step 3
//! and §7 (the origin of the tighten-only rule; not in this repo).
//!
//! The judgement is BETWEEN the two cascade views — which is why
//! [`crate::query::cascade::ResolvedCascade`] returns `pack` and `resolved`
//! side by side. The **pack view is the floor**; the incoming user shape is
//! what the resolved view will carry, because `cascade`'s overlay replaces a
//! facet shape WHOLESALE per key (facet shapes are units, not deep-merged). So
//! comparing the incoming shape against the pack shape *is* comparing the
//! prospective resolved view against the floor. Per-row checking is sound for
//! the whole cascade by induction: the resolved value for a spine key is
//! always one user-layer row's shape, or the pack's, and every user row is
//! checked against pack at its own write time.
//!
//! A user facet shape for spine key `k` on type `T` is LOOSER than the pack's
//! shape for `k` on `T` if any of these five limbs holds. Only keys the pack
//! actually shapes are judged — with no pack floor there is nothing to be
//! looser than.
//!
//!   1. **Removal.** The user's shape for `k` is not an object (`null`, a
//!      scalar, a list). There is no other way to un-shape a key: an omitted
//!      key inherits the pack's shape rather than clearing it, so `null` is
//!      the only expressible removal — and it drops the floor entirely.
//!   2. **De-requiring.** Pack has `required: true`; the user's shape does
//!      not. Includes OMITTING `required`: because facet shapes replace
//!      wholesale, an absent `required` is `required: false`, not "unchanged".
//!   3. **Enum widening.** Pack has a `values` array; the user's shape either
//!      carries no `values` array (unconstrained) or names a value outside the
//!      pack's set. A strict subset is a tightening and passes.
//!   4. **Vocabulary dropping or swapping.** Pack names a governing vocabulary
//!      (`vocab` / `vocab_ref`); the user's shape names none, or names a
//!      different one. "Different" is judged on IDENTITY, not spelling: a
//!      vocabulary has several legal designators — bare name, bare id, and
//!      either behind the `rec:` prefix, since `get_vocabulary` matches id OR
//!      name — so both sides resolve through the `vocabularies` table before
//!      they are compared, and a designator naming no row falls back to
//!      itself. String comparison would fire limb 4 on a user layer that
//!      faithfully restates the pack's own vocabulary in a different form,
//!      which is the honest case the floor exists to permit.
//!   5. **Lifecycle-axis dropping or changing.** If the pack shape carries an
//!      `axis`, the user shape must restate that exact descriptor. An axis says
//!      which domain question the vocabulary answers; changing it while
//!      preserving the carrier and vocabulary would silently change meaning.
//!
//! ## Why identity, and not the two vocabularies' value sets
//!
//! The alternative reading of limb 4 is to compare what the two vocabularies
//! currently CONTAIN, and reject when the user's is not a subset of the pack's.
//! It is the more obvious rule, and it is the wrong one, because it mistakes
//! what the floor is.
//!
//! **The floor is a relative constraint between two layers, not a freeze on a
//! vocabulary's contents.** Rejection (a) asks whether the user layer is looser
//! than the pack layer — not whether either is looser than it was yesterday.
//! Once that is clear the rest follows:
//!
//!   - **Shared identity is stable under the vocabulary lifecycle.** When both
//!     layers name the same vocabulary, a `propose_value` + `promote_value` or
//!     a `deprecate_value` moves both sides at once. The pack's shape governs
//!     the same set the user's does, before and after. Nothing about their
//!     RELATIVE constraint has loosened, so there is nothing for the floor to
//!     catch — and a rule that fired here would be forbidding the sanctioned
//!     lifecycle rather than a fork.
//!   - **Equal value sets are only coincidentally equal.** Two distinct
//!     vocabularies can hold identical values today and diverge on the next
//!     promotion, because nothing relates them: there is no `extends` or
//!     subset edge between vocabularies in v1 to make the relationship
//!     persist. A subset check would therefore license the swap on the
//!     strength of a snapshot, and the snapshot expires the moment the user
//!     widens the vocabulary they now wholly control. Identity is what the
//!     engine can actually keep true about a reference.
//!   - **Tightening under a shared identity is still available**, so the
//!     stricter rule costs the user nothing they should have: adding an
//!     explicit `values` subset alongside the pack's vocabulary is a
//!     tightening (limb 3), and passes.
//!
//! So: widening the pack's OWN vocabulary is a different act, governed by tool
//! 20's seeded-value rules; re-pointing a spine facet at a vocabulary the user
//! wholly controls is the fork this limb catches.
//!
//! The corollary is the next section. An identity used as a floor is only as
//! good as its referential integrity — a reference that can be deleted and
//! recreated elsewhere is not an identity, it is a name.
//!
//! What does NOT count as loosening, deliberately:
//!
//!   - **Anything on a non-spine facet key.** That is the whole point of the
//!     spine-floor rule as against production's blanket ban (3057bba §4).
//!   - **Anything on a spine key the pack does not shape**, per above.
//!   - **Adding** facet keys, types or `kinds`. `kinds` is open-additive by
//!     contract (2e5ed3e); it is not a facet constraint and is not judged.
//!   - **Tightening**: `required: false` → `true`, narrowing `values` to a
//!     subset, adding a `values` list alongside the pack's vocabulary.
//!   - **Annotative keys** (`description`, `gloss`, `default`). Changing a
//!     default is additive upstream (`fca675c` §7).
//!   - **Cardinality (`multi`) — not a limb, and not accepted either.**
//!     Upstream encodes cardinality as a second boolean, and `multi: false` →
//!     `true` would be a widening there. It is not a limb HERE because it is
//!     not directional here: spine facets are scalar COLUMNS on `records`, and
//!     open facets are rows in `facet_values` under `UNIQUE (record_id, key)`.
//!     A `multi` flag over either is inert in EITHER direction. A limb would be
//!     asserting a floor under an engine constraint that does not exist. So
//!     `multi` on any facet key is refused outright, by rejection (c) —
//!     [`assert_no_facet_cardinality`] — and this paragraph is precisely why
//!     that refusal is symmetric rather than a fifth limb: a claim nothing can
//!     honour is not loosened by being made, it is empty. Cardinality therefore
//!     decides facet versus link: one value is a facet; many related records
//!     are links.
//!
//! ## Judging an identity means storing one
//!
//! Limb 4 resolves both designators, but the payload is the user's file and is
//! stored as written — so a name-form reference would be re-resolved on every
//! later read. A stored name would rebind to a newer vocabulary of the same
//! name while an id-form pack reference still pinned the old one, moving the
//! floor with no schema_config write at all.
//!
//! So [`canonicalise_spine_vocab_refs`] rewrites spine references into
//! `rec:<row id>` — and it runs BEFORE rejection (a), not after, so that what
//! is judged is byte-for-byte what is stored. Canonicalising afterwards leaves
//! a window: a concurrent delete between the two makes the rewrite a no-op,
//! and a name the judgement had resolved is stored as a name again.
//!
//! The integrity half lives where the enforcement lives (e3e14cd):
//! [`crate::meta::vocabulary::delete_vocabulary`] refuses to delete a
//! vocabulary any `schema_config` shape governs with. That check is load-
//! bearing rather than defensive — its sibling count over `facet_values` is
//! structurally incapable of protecting a SPINE facet's vocabulary, because
//! spine facets project to COLUMNS on `records` and never write a
//! `facet_values` row at all.
//!
//! The two are ordered, not redundant: the guard is what keeps a reference
//! resolvable, and canonicalisation is what makes a dangling one fail SAFE if
//! it ever arises — both sides fall back to the same designator, so the floor
//! holds instead of silently moving. Containment is not a guard, but it is
//! worth keeping behind one.
//!
//! One consequence worth stating, since it makes the predicate stricter in
//! practice than limb-by-limb reading suggests: because the overlay replaces a
//! facet shape wholesale, a user shape for a spine key must RESTATE every pack
//! constraint it means to keep. `{"lifecycle": {"description": "its state"}}`
//! against a pack `{"required": true, "vocab": "lifecycle"}` trips limbs 2 and
//! 4 — dropping a constraint by not repeating it is loosening, and is caught,
//! even though the key the user actually wrote is an annotative one this
//! predicate never judges on its own.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::meta::schema_config::{
    append_prepared_user_schema_config_in, assert_no_authored_kind_arrays,
    assert_no_reserved_facet_keys, assert_no_spine_declared_types, assert_valid_lifecycle_axes,
    assert_valid_object_facet_schemas, prepare_user_schema_config_write, SchemaConfigOptions,
};
use crate::meta::vocabulary::{
    alias_value_in, create_vocabulary_in, delete_value_in, delete_vocabulary_in,
    deprecate_value_with_quarantine_count_in, get_value_on, get_vocabulary, get_vocabulary_on,
    list_values, promote_value_in, propose_value_with_kind_metadata_in, reorder_value_in,
    resolve_vocab_ref, set_gloss_in, set_value_metadata_in, vocab_ref, ListValuesOptions,
    VocabularyValueTerminality,
};
#[cfg(feature = "mcp-executor-prototype")]
use crate::meta::vocabulary::{find_value_on, value_id, vocabulary_id};
use crate::meta::KindMetadataV1;
use crate::query::cascade;
use crate::schema::{ENGINE_RESERVED_FACET_KEYS, SPINE_FACET_KEYS};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::parse_args;

// ---------------------------------------------------------------------------
// Argument shapes (parsed via `super::parse_args`, deny_unknown_fields)
// ---------------------------------------------------------------------------

/// The three `vocabulary_values.status` values. An enum rather than a free
/// string so a typo is a rejection, not a silently empty listing.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ValueStatus {
    Proposed,
    Active,
    Deprecated,
}

impl ValueStatus {
    fn as_str(self) -> &'static str {
        match self {
            ValueStatus::Proposed => "proposed",
            ValueStatus::Active => "active",
            ValueStatus::Deprecated => "deprecated",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConfigLayer {
    Pack,
    User,
}

impl ConfigLayer {
    fn as_str(self) -> &'static str {
        match self {
            ConfigLayer::Pack => "pack",
            ConfigLayer::User => "user",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageVocabulariesArgs {
    /// The read half: a vocabulary's values, status-filtered and
    /// alias-resolved (`meta::vocabulary::list_values`).
    ListValues {
        vocabulary: String,
        status: Option<ValueStatus>,
        resolve_aliases: Option<bool>,
    },
    CreateVocabulary {
        name: String,
        id: Option<String>,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    ProposeValue {
        vocabulary: String,
        value: String,
        gloss: Option<String>,
        #[serde(default)]
        ordinal: f64,
        #[serde(default)]
        terminality: VocabularyValueTerminality,
        metadata: Option<KindMetadataV1>,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    ReorderValue {
        value_id: String,
        ordinal: f64,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    /// Amend an existing value's gloss. `gloss: null` clears it.
    SetGloss {
        value_id: String,
        gloss: Option<String>,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    SetMetadata {
        value_id: String,
        metadata: KindMetadataV1,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    PromoteValue {
        value_id: String,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    DeprecateValue {
        value_id: String,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    AliasValue {
        value_id: String,
        canonical_id: String,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    DeleteValue {
        value_id: String,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
    DeleteVocabulary {
        vocabulary: String,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageSchemaConfigArgs {
    /// Read the resolved two-layer cascade, plus the rows behind it.
    Read { layer: Option<ConfigLayer> },
    /// Write the USER layer — the only editable one.
    Write {
        data: Value,
        id: Option<String>,
        version_lineage: Option<String>,
        applies_to_collection_id: Option<String>,
        #[serde(default)]
        if_schema_state_revision: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Tool 20 — manage_vocabularies
// ---------------------------------------------------------------------------

async fn manage_vocabularies(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ManageVocabulariesArgs = parse_args("manage_vocabularies", arguments)?;
    if !matches!(args, ManageVocabulariesArgs::ListValues { .. }) && !caller.is_host_owner() {
        return Err(Error::auth(
            "manage_vocabularies: database owner host role required",
        ));
    }
    match args {
        ManageVocabulariesArgs::ListValues {
            vocabulary,
            status,
            resolve_aliases,
        } => {
            let values = list_values(
                &db,
                &vocabulary,
                ListValuesOptions {
                    status: status.map(|s| s.as_str().to_string()),
                    resolve_aliases: resolve_aliases.unwrap_or(true),
                },
            )
            .await?;
            // `list_values` errored if the vocabulary were missing, so this is
            // `Some` — but the lookup is what turns a name into an id/ref.
            let vocab = get_vocabulary(&db, &vocabulary).await?;
            Ok(json!({
                "vocabulary": vocab,
                "vocab_ref": vocab.as_ref().map(|v| vocab_ref(&v.id)),
                "status": status.map(ValueStatus::as_str),
                "values": values,
            }))
        }
        mutation => {
            let expected_revision = mutation.schema_state_revision().map(ToString::to_string);
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            assert_schema_state_revision_in(&mut tx, expected_revision.as_deref()).await?;
            let result = apply_vocabulary_mutation_in(&mut tx, &caller, mutation).await?;
            tx.commit().await?;
            Ok(result)
        }
    }
}

impl ManageVocabulariesArgs {
    fn schema_state_revision(&self) -> Option<&str> {
        match self {
            Self::ListValues { .. } => None,
            Self::CreateVocabulary {
                if_schema_state_revision,
                ..
            }
            | Self::ProposeValue {
                if_schema_state_revision,
                ..
            }
            | Self::ReorderValue {
                if_schema_state_revision,
                ..
            }
            | Self::SetGloss {
                if_schema_state_revision,
                ..
            }
            | Self::SetMetadata {
                if_schema_state_revision,
                ..
            }
            | Self::PromoteValue {
                if_schema_state_revision,
                ..
            }
            | Self::DeprecateValue {
                if_schema_state_revision,
                ..
            }
            | Self::AliasValue {
                if_schema_state_revision,
                ..
            }
            | Self::DeleteValue {
                if_schema_state_revision,
                ..
            }
            | Self::DeleteVocabulary {
                if_schema_state_revision,
                ..
            } => if_schema_state_revision.as_deref(),
        }
    }
}

async fn schema_state_revision_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
) -> Result<String> {
    let (meta, content) = schema_state_high_waters_in(tx).await?;
    Ok(format!("schema-state-v1:meta:{meta}:content:{content}"))
}

async fn schema_state_high_waters_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
) -> Result<(i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT COALESCE((SELECT MAX(seq) FROM meta_events), 0), \
                COALESCE((SELECT MAX(seq) FROM content_events), 0)",
    )
    .fetch_one(&mut **tx)
    .await?)
}

async fn assert_schema_state_revision_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    expected: Option<&str>,
) -> Result<String> {
    let current = schema_state_revision_in(tx).await?;
    if expected.is_some_and(|expected| expected != current) {
        return Err(Error::engine(format!(
            "schema state revision conflict: expected {}, current {current}",
            expected.expect("expected revision was present")
        )));
    }
    Ok(current)
}

async fn apply_vocabulary_mutation_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    args: ManageVocabulariesArgs,
) -> Result<Value> {
    match args {
        ManageVocabulariesArgs::ListValues { .. } => Err(Error::engine(
            "manage_vocabularies list_values is not a mutation",
        )),
        ManageVocabulariesArgs::CreateVocabulary { name, id, .. } => {
            let id = create_vocabulary_in(tx, &name, id.as_deref(), Some(caller.actor())).await?;
            Ok(json!({
                "vocabulary_id": id,
                "name": name,
                "vocab_ref": vocab_ref(&id),
            }))
        }
        ManageVocabulariesArgs::ProposeValue {
            vocabulary,
            value,
            gloss,
            ordinal,
            terminality,
            metadata,
            ..
        } => {
            let value_id = propose_value_with_kind_metadata_in(
                tx,
                &vocabulary,
                &value,
                gloss.as_deref(),
                ordinal,
                terminality,
                metadata.clone(),
                Some(caller.actor()),
            )
            .await?;
            let status = get_value_on(tx, &value_id).await?.status;
            Ok(json!({
                "value_id": value_id,
                "vocabulary": vocabulary,
                "value": value,
                "status": status,
                "ordinal": ordinal,
                "terminality": terminality,
                "metadata": metadata,
            }))
        }
        ManageVocabulariesArgs::SetMetadata {
            value_id, metadata, ..
        } => {
            set_value_metadata_in(tx, &value_id, metadata.clone(), Some(caller.actor())).await?;
            Ok(json!({ "value_id": value_id, "metadata": metadata }))
        }
        ManageVocabulariesArgs::ReorderValue {
            value_id, ordinal, ..
        } => {
            reorder_value_in(tx, &value_id, ordinal, Some(caller.actor())).await?;
            Ok(json!({ "value_id": value_id, "ordinal": ordinal, "reordered": true }))
        }
        ManageVocabulariesArgs::SetGloss {
            value_id, gloss, ..
        } => {
            set_gloss_in(tx, &value_id, gloss.as_deref(), Some(caller.actor())).await?;
            Ok(json!({ "value_id": value_id, "gloss": gloss, "gloss_set": true }))
        }
        ManageVocabulariesArgs::PromoteValue { value_id, .. } => {
            promote_value_in(tx, &value_id, Some(caller.actor())).await?;
            Ok(json!({ "value_id": value_id, "status": "active" }))
        }
        ManageVocabulariesArgs::DeprecateValue { value_id, .. } => {
            let quarantined_records =
                deprecate_value_with_quarantine_count_in(tx, &value_id, Some(caller.actor()))
                    .await?;
            Ok(json!({
                "value_id": value_id,
                "status": "deprecated",
                "records_quarantined": quarantined_records,
            }))
        }
        ManageVocabulariesArgs::AliasValue {
            value_id,
            canonical_id,
            ..
        } => {
            alias_value_in(tx, &value_id, &canonical_id, Some(caller.actor())).await?;
            Ok(json!({
                "value_id": value_id,
                "alias_of": canonical_id,
                "status": "deprecated",
            }))
        }
        ManageVocabulariesArgs::DeleteValue { value_id, .. } => {
            delete_value_in(tx, &value_id, Some(caller.actor())).await?;
            Ok(json!({ "value_id": value_id, "deleted": true }))
        }
        ManageVocabulariesArgs::DeleteVocabulary { vocabulary, .. } => {
            delete_vocabulary_in(tx, &vocabulary, Some(caller.actor())).await?;
            Ok(json!({ "vocabulary": vocabulary, "deleted": true }))
        }
    }
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) struct SchemaMutationPreparation {
    pub revalidation_arguments: Value,
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub effect_summary: String,
    pub operation_evidence: Value,
}

#[cfg(feature = "mcp-executor-prototype")]
enum VocabularyMutationScope {
    Vocabulary(String),
    Values(Vec<String>),
}

#[cfg(feature = "mcp-executor-prototype")]
fn schema_value_digest(value: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};

    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(value)?)))
}

#[cfg(feature = "mcp-executor-prototype")]
fn vocabulary_mutation_action(args: &ManageVocabulariesArgs) -> &'static str {
    match args {
        ManageVocabulariesArgs::ListValues { .. } => "list_values",
        ManageVocabulariesArgs::CreateVocabulary { .. } => "create_vocabulary",
        ManageVocabulariesArgs::ProposeValue { .. } => "propose_value",
        ManageVocabulariesArgs::ReorderValue { .. } => "reorder_value",
        ManageVocabulariesArgs::SetGloss { .. } => "set_gloss",
        ManageVocabulariesArgs::SetMetadata { .. } => "set_metadata",
        ManageVocabulariesArgs::PromoteValue { .. } => "promote_value",
        ManageVocabulariesArgs::DeprecateValue { .. } => "deprecate_value",
        ManageVocabulariesArgs::AliasValue { .. } => "alias_value",
        ManageVocabulariesArgs::DeleteValue { .. } => "delete_value",
        ManageVocabulariesArgs::DeleteVocabulary { .. } => "delete_vocabulary",
    }
}

#[cfg(feature = "mcp-executor-prototype")]
fn vocabulary_source_arguments(expected_action: &str, arguments: Value) -> Result<Value> {
    let mut object = arguments.as_object().cloned().ok_or_else(|| {
        Error::engine(format!(
            "manage_vocabularies.{expected_action} arguments must be an object"
        ))
    })?;
    if object.contains_key("if_schema_state_revision") {
        return Err(Error::engine(
            "schema state revision is source-owned and cannot be supplied by the caller",
        ));
    }
    object.insert("action".into(), json!(expected_action));
    Ok(Value::Object(object))
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn validate_vocabulary_mutation(expected_action: &str, arguments: Value) -> Result<()> {
    let source = vocabulary_source_arguments(expected_action, arguments)?;
    let parsed: ManageVocabulariesArgs = parse_args("manage_vocabularies", source)?;
    if vocabulary_mutation_action(&parsed) != expected_action
        || matches!(parsed, ManageVocabulariesArgs::ListValues { .. })
    {
        return Err(Error::engine(format!(
            "manage_vocabularies.{expected_action} has no exact mutation route"
        )));
    }
    Ok(())
}

#[cfg(feature = "mcp-executor-prototype")]
async fn vocabulary_mutation_scope_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    args: &ManageVocabulariesArgs,
) -> Result<(VocabularyMutationScope, String, String)> {
    match args {
        ManageVocabulariesArgs::CreateVocabulary { name, id, .. } => {
            let id = id.clone().unwrap_or_else(|| vocabulary_id(name));
            Ok((
                VocabularyMutationScope::Vocabulary(id.clone()),
                id,
                format!("vocabulary '{name}'"),
            ))
        }
        ManageVocabulariesArgs::ProposeValue {
            vocabulary, value, ..
        } => {
            let vocab = get_vocabulary_on(tx, vocabulary)
                .await?
                .ok_or_else(|| Error::engine(format!("vocabulary {vocabulary} does not exist")))?;
            let value_id = value_id(&vocab.id, value);
            Ok((
                VocabularyMutationScope::Vocabulary(vocab.id.clone()),
                value_id,
                format!("value '{value}' in vocabulary '{}'", vocab.name),
            ))
        }
        ManageVocabulariesArgs::AliasValue {
            value_id,
            canonical_id,
            ..
        } => {
            let value = get_value_on(tx, value_id).await?;
            let canonical = get_value_on(tx, canonical_id).await?;
            Ok((
                VocabularyMutationScope::Values(vec![value_id.clone(), canonical_id.clone()]),
                value_id.clone(),
                format!(
                    "vocabulary value '{}' aliasing to '{}'",
                    value.value, canonical.value
                ),
            ))
        }
        ManageVocabulariesArgs::ReorderValue { value_id, .. }
        | ManageVocabulariesArgs::SetGloss { value_id, .. }
        | ManageVocabulariesArgs::SetMetadata { value_id, .. }
        | ManageVocabulariesArgs::PromoteValue { value_id, .. }
        | ManageVocabulariesArgs::DeprecateValue { value_id, .. }
        | ManageVocabulariesArgs::DeleteValue { value_id, .. } => {
            let value = get_value_on(tx, value_id).await?;
            Ok((
                VocabularyMutationScope::Values(vec![value_id.clone()]),
                value_id.clone(),
                format!("vocabulary value '{}' ({value_id})", value.value),
            ))
        }
        ManageVocabulariesArgs::DeleteVocabulary { vocabulary, .. } => {
            let vocab = get_vocabulary_on(tx, vocabulary)
                .await?
                .ok_or_else(|| Error::engine(format!("vocabulary {vocabulary} does not exist")))?;
            Ok((
                VocabularyMutationScope::Vocabulary(vocab.id.clone()),
                vocab.id.clone(),
                format!("vocabulary '{}' ({})", vocab.name, vocab.id),
            ))
        }
        ManageVocabulariesArgs::ListValues { .. } => Err(Error::engine(
            "manage_vocabularies list_values is not a mutation",
        )),
    }
}

#[cfg(feature = "mcp-executor-prototype")]
async fn vocabulary_scope_snapshot_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    scope: &VocabularyMutationScope,
) -> Result<Value> {
    match scope {
        VocabularyMutationScope::Vocabulary(id) => {
            let vocabulary = get_vocabulary_on(tx, id).await?;
            let value_ids: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM vocabulary_values WHERE vocabulary_id = ? ORDER BY ordinal,value,id",
            )
            .bind(id)
            .fetch_all(&mut **tx)
            .await?;
            let mut values = Vec::with_capacity(value_ids.len());
            for value_id in value_ids {
                values.push(get_value_on(tx, &value_id).await?);
            }
            Ok(json!({"vocabulary":vocabulary,"values":values}))
        }
        VocabularyMutationScope::Values(ids) => {
            let mut values = Vec::with_capacity(ids.len());
            for id in ids {
                values.push(find_value_on(tx, id).await?);
            }
            Ok(json!({"values":values}))
        }
    }
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_vocabulary_mutation(
    db: &Db,
    caller: &Caller,
    expected_action: &str,
    operation_arguments: Value,
) -> Result<SchemaMutationPreparation> {
    if !caller.is_host_owner() {
        return Err(Error::auth(
            "manage_vocabularies: database owner host role required",
        ));
    }
    let canonical_without_revision =
        vocabulary_source_arguments(expected_action, operation_arguments.clone())?;
    let parsed: ManageVocabulariesArgs =
        parse_args("manage_vocabularies", canonical_without_revision.clone())?;
    if vocabulary_mutation_action(&parsed) != expected_action
        || matches!(parsed, ManageVocabulariesArgs::ListValues { .. })
    {
        return Err(Error::engine(format!(
            "manage_vocabularies.{expected_action} has no exact mutation route"
        )));
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let state_revision = schema_state_revision_in(&mut tx).await?;
    let (scope, target_id, target) = vocabulary_mutation_scope_in(&mut tx, &parsed).await?;
    let before = vocabulary_scope_snapshot_in(&mut tx, &scope).await?;
    let (meta_before, _) = schema_state_high_waters_in(&mut tx).await?;
    let result = apply_vocabulary_mutation_in(&mut tx, caller, parsed).await?;
    let (meta_after, _) = schema_state_high_waters_in(&mut tx).await?;
    let after = vocabulary_scope_snapshot_in(&mut tx, &scope).await?;
    tx.rollback().await?;

    let changed = meta_after != meta_before;
    let mut canonical_source_arguments = canonical_without_revision;
    canonical_source_arguments["if_schema_state_revision"] = json!(state_revision);
    let effect_summary = if !changed {
        format!(
            "leave {} unchanged on {target}",
            expected_action.replace('_', " ")
        )
    } else if expected_action == "deprecate_value" {
        format!(
            "deprecate {target}; quarantine {} decided record(s)",
            result["records_quarantined"].as_i64().unwrap_or_default()
        )
    } else {
        format!("apply {} on {target}", expected_action.replace('_', " "))
    };
    Ok(SchemaMutationPreparation {
        revalidation_arguments: operation_arguments,
        canonical_source_arguments,
        target_id,
        target,
        state_revision: state_revision.clone(),
        target_state_digest: schema_value_digest(&before)?,
        effect_summary,
        effect: json!({
            "action":expected_action,
            "changed":changed,
            "projection_changed":before != after,
            "source_event_appended":changed,
            "before":before,
            "after":after,
            "result":result,
        }),
        operation_evidence: json!({
            "kind":"vocabulary_mutation",
            "schema_state_revision":state_revision,
        }),
    })
}

// ---------------------------------------------------------------------------
// Tool 21 — manage_schema_config, and rejection (a)
// ---------------------------------------------------------------------------

/// The governing vocabulary a facet shape names, past the optional `rec:`
/// prefix so `rec:voc:x` and `voc:x` agree. Still a DESIGNATOR, not an
/// identity: `get_vocabulary` matches id OR name, so one row has two legal
/// spellings. [`canonical_vocab`] is what closes that gap.
fn governing_vocab(shape: &Value) -> Option<&str> {
    shape
        .get("vocab")
        .or_else(|| shape.get("vocab_ref"))
        .and_then(Value::as_str)
        .map(resolve_vocab_ref)
}

/// Resolve a vocabulary designator to its row id, so limb 4 compares identity
/// rather than spelling.
///
/// A designator naming no row falls back to itself. That keeps the limb
/// working on a config written ahead of the vocabulary it names: the same
/// unknown name still compares equal to itself, a different one still trips
/// the swap. It cannot mask a real swap — two designators only collapse to
/// one id by resolving to one row.
async fn canonical_vocab(conn: &mut sqlx::SqliteConnection, designator: &str) -> Result<String> {
    Ok(get_vocabulary_on(conn, designator)
        .await?
        .map(|row| row.id)
        .unwrap_or_else(|| designator.to_string()))
}

/// Is `user` looser than `pack` for one facet key? Returns the limb that
/// fired, as the clause that goes in the rejection message.
///
/// The floor limbs, and everything deliberately excluded from them, are
/// specified in this module's header — read that before changing this.
///
/// Async for limb 4 alone, which resolves both sides through the
/// `vocabularies` table; limbs 1–3 are pure.
async fn loosens(
    conn: &mut sqlx::SqliteConnection,
    pack: &Value,
    user: &Value,
) -> Result<Option<String>> {
    // No object on the pack side is no floor: nothing to be looser than.
    if !pack.is_object() {
        return Ok(None);
    }
    // Limb 1 — removal.
    if !user.is_object() {
        return Ok(Some("the user layer clears the shape (only `null` can un-shape a key; an omitted key inherits the pack's shape)".into()));
    }
    // Limb 2 — de-requiring. An absent `required` IS `required: false`: facet
    // shapes replace wholesale, so a shape must restate what it means to keep.
    if pack.get("required") == Some(&Value::Bool(true))
        && user.get("required") != Some(&Value::Bool(true))
    {
        return Ok(Some("the pack requires it and the user layer does not (`required: true` -> false, or `required` dropped)".into()));
    }
    // Limb 3 — enum widening.
    if let Some(pack_values) = pack.get("values").and_then(Value::as_array) {
        match user.get("values").and_then(Value::as_array) {
            None => {
                return Ok(Some(
                    "the pack constrains it to a `values` set and the user layer lists none".into(),
                ))
            }
            Some(user_values) => {
                if let Some(extra) = user_values.iter().find(|v| !pack_values.contains(v)) {
                    return Ok(Some(format!(
                        "the user layer adds value {extra} to the pack's `values` set"
                    )));
                }
            }
        }
    }
    // Limb 4 — vocabulary dropped or swapped.
    if let Some(pack_vocab) = governing_vocab(pack) {
        let Some(user_vocab) = governing_vocab(user) else {
            return Ok(Some(format!(
                "the pack governs it with vocabulary '{pack_vocab}', the user layer names none"
            )));
        };
        // Identity, not spelling. `maturity` and `voc:maturity` designate one
        // row (`get_vocabulary` matches id OR name), so comparing the strings
        // would reject a legitimate restatement of the pack's own vocabulary
        // as a swap — a floor that fires on the honest case.
        if canonical_vocab(conn, user_vocab).await? != canonical_vocab(conn, pack_vocab).await? {
            return Ok(Some(format!(
                "the user layer re-points it from vocabulary '{pack_vocab}' to '{user_vocab}'"
            )));
        }
    }
    // A lifecycle axis says which domain question the governed vocabulary
    // answers. Facet shapes replace wholesale, so a pack axis is an identity
    // floor just like the governing vocabulary: omission or alteration would
    // make identical stored tokens mean something different to readers.
    if let Some(pack_axis) = pack.get("axis") {
        if user.get("axis") != Some(pack_axis) {
            return Ok(Some(
                "the user layer drops or changes the pack's lifecycle axis; it must restate the exact axis object"
                    .into(),
            ));
        }
    }
    Ok(None)
}

/// The type/kind views whose spine floors an incoming user row can affect.
/// Every type gets its base view (`None`), plus every `T:k` key appearing in
/// either the pack floor or incoming data.
fn shape_targets(pack: &Value, data: &Value) -> BTreeMap<String, BTreeSet<Option<String>>> {
    let mut targets: BTreeMap<String, BTreeSet<Option<String>>> = BTreeMap::new();
    for view in [pack, data] {
        for shape_key in view
            .get("shapes")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|shapes| shapes.keys())
        {
            let (record_type, kind) = match shape_key.split_once(':') {
                Some((record_type, kind)) => (record_type, Some(kind.to_string())),
                None => (shape_key.as_str(), None),
            };
            let kinds = targets.entry(record_type.to_string()).or_default();
            kinds.insert(None);
            if let Some(kind) = kind {
                kinds.insert(Some(kind));
            }
        }
    }
    targets
}

/// The declared-facet-type vocabulary covers scalar numbers and atomic JSON
/// objects. Reject unknown declarations rather than
/// storing a promise no supported writer understands.
fn assert_known_facet_types(data: &Value) -> Result<()> {
    assert_no_spine_declared_types(data)?;
    let shapes = data.get("shapes").and_then(Value::as_object);
    for (shape_key, shape) in shapes.into_iter().flatten() {
        let Some(facets) = shape.get("facets").and_then(Value::as_object) else {
            continue;
        };
        for (facet_key, facet) in facets {
            let Some(declared_type) = facet.get("type") else {
                continue;
            };
            if !matches!(declared_type.as_str(), Some("number" | "object")) {
                return Err(Error::engine(format!(
                    "cannot configure type {declared_type} on facet '{facet_key}' (shape '{shape_key}'): supported declared types are `number` and `object`; omit `type` for the string/default lane"
                )));
            }
        }
    }
    Ok(())
}

/// A pack-declared type is a nominal interop floor on every eligible open
/// facet key (decision 37de348 as amended). Omission of a user facet override
/// inherits the pack and is allowed; once the user overrides that facet shape,
/// it must restate the exact pack type. Spine facets are skipped because v1
/// rejects their type declarations rather than promising numeric validation
/// over string carriers.
fn assert_no_type_loosening(pack: &Value, data: &Value) -> Result<()> {
    for (record_type, kinds) in shape_targets(pack, data) {
        for kind in kinds {
            let pack_floor = cascade::facets_for_type(pack, &record_type, kind.as_deref());
            let user_view = cascade::facets_for_type(data, &record_type, kind.as_deref());
            let shape_key = kind
                .as_deref()
                .map(|kind| format!("{record_type}:{kind}"))
                .unwrap_or_else(|| record_type.clone());
            for (facet_key, pack_shape) in pack_floor {
                if SPINE_FACET_KEYS.contains(&facet_key.as_str()) {
                    continue;
                }
                let Some(pack_type) = pack_shape.get("type").and_then(Value::as_str) else {
                    continue;
                };
                let Some(user_shape) = user_view.get(&facet_key) else {
                    continue;
                };
                let user_type = user_shape.get("type").and_then(Value::as_str);
                if user_type != Some(pack_type) {
                    return Err(Error::engine(format!(
                        "cannot loosen declared type for facet '{facet_key}' on shape '{shape_key}': the pack declares `type: \"{pack_type}\"`, so a user override must restate that exact nominal type; omitting the whole facet override inherits the pack"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn assert_object_contract_restatement(
    shape_key: &str,
    facet_key: &str,
    pack_shape: &Value,
    user_shape: &Value,
) -> Result<()> {
    if pack_shape.get("type").and_then(Value::as_str) != Some("object") {
        return Ok(());
    }
    if pack_shape.get("required") == Some(&Value::Bool(true))
        && user_shape.get("required") != Some(&Value::Bool(true))
    {
        return Err(Error::engine(format!(
            "cannot loosen object facet '{facet_key}' on shape '{shape_key}': a user override must preserve the pack's required:true contract; omit the whole facet override to inherit it"
        )));
    }
    for key in ["json_schema", "temporal_order"] {
        if pack_shape.get(key).is_some() && pack_shape.get(key) != user_shape.get(key) {
            return Err(Error::engine(format!(
                "cannot loosen object facet '{facet_key}' on shape '{shape_key}': a user override must exactly restate the pack's '{key}' contract; omit the whole facet override to inherit it"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod object_contract_tests {
    use super::*;

    #[test]
    fn absent_pack_object_constraints_may_be_tightened() {
        let pack = json!({ "type": "object" });
        let tightened = json!({
            "type": "object",
            "required": true,
            "json_schema": { "type": "object" },
            "temporal_order": [{ "earlier": "start", "later": "end" }]
        });
        assert_object_contract_restatement("Document:example", "data", &pack, &tightened).unwrap();
    }

    #[test]
    fn present_pack_object_constraints_cannot_be_dropped() {
        let pack = json!({
            "type": "object",
            "required": true,
            "json_schema": { "type": "object" },
            "temporal_order": [{ "earlier": "start", "later": "end" }]
        });
        for loosened in [
            json!({ "type": "object", "json_schema": pack["json_schema"], "temporal_order": pack["temporal_order"] }),
            json!({ "type": "object", "required": true, "temporal_order": pack["temporal_order"] }),
            json!({ "type": "object", "required": true, "json_schema": pack["json_schema"] }),
        ] {
            assert!(assert_object_contract_restatement(
                "Outcome:impact",
                "impact",
                &pack,
                &loosened
            )
            .is_err());
        }
    }
}

fn assert_no_object_contract_loosening(pack: &Value, data: &Value) -> Result<()> {
    for (record_type, kinds) in shape_targets(pack, data) {
        for kind in kinds {
            let pack_floor = cascade::facets_for_type(pack, &record_type, kind.as_deref());
            let user_view = cascade::facets_for_type(data, &record_type, kind.as_deref());
            let shape_key = kind
                .as_deref()
                .map(|kind| format!("{record_type}:{kind}"))
                .unwrap_or_else(|| record_type.clone());
            for (facet_key, pack_shape) in pack_floor {
                let Some(user_shape) = user_view.get(&facet_key) else {
                    continue;
                };
                assert_object_contract_restatement(
                    &shape_key,
                    &facet_key,
                    &pack_shape,
                    user_shape,
                )?;
            }
        }
    }
    Ok(())
}

/// Report historical values that do not conform to the prospective declared
/// types without turning a forward-only guard into retroactive validation.
///
/// `value_num` is the read-side definition of number (234721a), so using the
/// generated projection here keeps this report aligned with filtering and
/// avoids inventing a second parser. Shape resolution is per resulting
/// `(type, kind)`, exactly as it is at write time. Spine declarations are
/// rejected, and spine values never live in this table, so the report cannot
/// accidentally imply numeric validation for their string carriers.
async fn count_nonconforming_declared_values(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    prospective: &[cascade::SchemaConfigRow],
) -> Result<i64> {
    let rows = sqlx::query_as::<_, (String, Option<String>, String, Option<String>, Option<f64>)>(
        "SELECT r.type, r.kind, fv.key, fv.value, fv.value_num
         FROM facet_values fv
         JOIN records r ON r.id = fv.record_id",
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut count = 0;
    for (record_type, kind, key, value, value_num) in rows {
        let shape =
            cascade::facets_for_record_context(prospective, &record_type, kind.as_deref(), None);
        let declared_type = shape
            .get(&key)
            .and_then(|facet| facet.get("type"))
            .and_then(Value::as_str);
        let nonconforming = match declared_type {
            Some("number") => value_num.is_none(),
            Some("object") => value
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .is_none_or(|value| {
                    !value.is_object()
                        || shape.get(&key).is_some_and(|facet| {
                            crate::meta::schema_config::validate_object_facet_value(facet, &value)
                                .is_err()
                        })
                }),
            _ => false,
        };
        if nonconforming {
            count += 1;
        }
    }
    Ok(count)
}

fn scoped_shape_targets(
    rows: &[cascade::SchemaConfigRow],
    data: &Value,
    bearer_id: &str,
) -> BTreeMap<String, BTreeSet<Option<String>>> {
    let mut targets = shape_targets(&json!({"shapes": {}}), data);
    for row in rows.iter().filter(|row| {
        row.layer == "pack"
            && (row.applies_to_collection_id.is_none()
                || row.applies_to_collection_id.as_deref() == Some(bearer_id))
    }) {
        for shape_key in row
            .data
            .get("shapes")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|shapes| shapes.keys())
        {
            let (record_type, kind) = match shape_key.split_once(':') {
                Some((record_type, kind)) => (record_type, Some(kind.to_string())),
                None => (shape_key.as_str(), None),
            };
            let kinds = targets.entry(record_type.to_string()).or_default();
            kinds.insert(None);
            if let Some(kind) = kind {
                kinds.insert(Some(kind));
            }
        }
    }
    targets
}

fn assert_no_type_loosening_scoped(
    rows: &[cascade::SchemaConfigRow],
    data: &Value,
    bearer_id: &str,
) -> Result<()> {
    for (record_type, kinds) in scoped_shape_targets(rows, data, bearer_id) {
        for kind in kinds {
            let pack_floor = cascade::pack_facets_for_record_context(
                rows,
                &record_type,
                kind.as_deref(),
                Some(bearer_id),
            );
            let user_view = cascade::facets_for_type(data, &record_type, kind.as_deref());
            let shape_key = kind
                .as_deref()
                .map(|kind| format!("{record_type}:{kind}"))
                .unwrap_or_else(|| record_type.clone());
            for (facet_key, pack_shape) in pack_floor {
                if SPINE_FACET_KEYS.contains(&facet_key.as_str()) {
                    continue;
                }
                let Some(pack_type) = pack_shape.get("type").and_then(Value::as_str) else {
                    continue;
                };
                let Some(user_shape) = user_view.get(&facet_key) else {
                    continue;
                };
                if user_shape.get("type").and_then(Value::as_str) != Some(pack_type) {
                    return Err(Error::engine(format!(
                        "cannot loosen declared type for facet '{facet_key}' on anchored shape '{shape_key}' (bearer {bearer_id}): the resolved pack floor declares `type: \"{pack_type}\"`, so a user override must restate that exact nominal type"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn assert_no_object_contract_loosening_scoped(
    rows: &[cascade::SchemaConfigRow],
    data: &Value,
    bearer_id: &str,
) -> Result<()> {
    for (record_type, kinds) in scoped_shape_targets(rows, data, bearer_id) {
        for kind in kinds {
            let pack_floor = cascade::pack_facets_for_record_context(
                rows,
                &record_type,
                kind.as_deref(),
                Some(bearer_id),
            );
            let user_view = cascade::facets_for_type(data, &record_type, kind.as_deref());
            let shape_key = kind
                .as_deref()
                .map(|kind| format!("{record_type}:{kind}"))
                .unwrap_or_else(|| record_type.clone());
            for (facet_key, pack_shape) in pack_floor {
                let Some(user_shape) = user_view.get(&facet_key) else {
                    continue;
                };
                assert_object_contract_restatement(
                    &format!("{shape_key} (bearer {bearer_id})"),
                    &facet_key,
                    &pack_shape,
                    user_shape,
                )?;
            }
        }
    }
    Ok(())
}

async fn assert_no_spine_loosening_scoped(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    rows: &[cascade::SchemaConfigRow],
    data: &Value,
    bearer_id: &str,
) -> Result<()> {
    for (record_type, kinds) in scoped_shape_targets(rows, data, bearer_id) {
        for kind in kinds {
            let pack_floor = cascade::pack_facets_for_record_context(
                rows,
                &record_type,
                kind.as_deref(),
                Some(bearer_id),
            );
            let user_view = cascade::facets_for_type(data, &record_type, kind.as_deref());
            let shape_key = kind
                .as_deref()
                .map(|kind| format!("{record_type}:{kind}"))
                .unwrap_or_else(|| record_type.clone());
            for key in SPINE_FACET_KEYS {
                let (Some(user_shape), Some(pack_shape)) =
                    (user_view.get(key), pack_floor.get(key))
                else {
                    continue;
                };
                if let Some(why) = loosens(tx, pack_shape, user_shape).await? {
                    return Err(Error::engine(format!(
                        "cannot loosen spine facet '{key}' on anchored shape '{shape_key}' (bearer {bearer_id}): {why}. The resolved pack shape for that bearer is the interop floor"
                    )));
                }
            }
        }
    }
    Ok(())
}

async fn assert_kind_shapes_enumerated_scoped(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    rows: &[cascade::SchemaConfigRow],
    bearer_id: &str,
) -> Result<()> {
    for row in rows.iter().filter(|row| {
        row.applies_to_collection_id.is_none()
            || row.applies_to_collection_id.as_deref() == Some(bearer_id)
    }) {
        for shape_key in row
            .data
            .get("shapes")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|shapes| shapes.keys())
        {
            let Some((record_type, kind)) = shape_key.split_once(':') else {
                continue;
            };
            let resolution = crate::meta::kind::resolve_on(&mut *tx, record_type, kind).await?;
            if resolution.classification != crate::meta::kind::KindClassification::ActiveCanonical {
                return Err(Error::engine(format!(
                    "kind-specific schema shape '{shape_key}' is not governed by an active canonical value in 'kind:{record_type}' for bearer {bearer_id}; propose and promote it with manage_vocabularies first"
                )));
            }
        }
    }
    Ok(())
}

/// Rejection (a) — the interop floor (3057bba §4), generalised across kind
/// specificity. `pack` is the pack view and `data` is the incoming user row.
/// Each comparison uses base ⊕ kind on both sides.
pub(crate) async fn assert_no_spine_loosening(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    pack: &Value,
    data: &Value,
) -> Result<()> {
    for (record_type, kinds) in shape_targets(pack, data) {
        for kind in kinds {
            let pack_floor = cascade::facets_for_type(pack, &record_type, kind.as_deref());
            let user_view = cascade::facets_for_type(data, &record_type, kind.as_deref());
            let shape_key = kind
                .as_deref()
                .map(|kind| format!("{record_type}:{kind}"))
                .unwrap_or_else(|| record_type.clone());
            for key in SPINE_FACET_KEYS {
                let (Some(user_shape), Some(pack_shape)) =
                    (user_view.get(key), pack_floor.get(key))
                else {
                    continue;
                };
                if let Some(why) = loosens(tx, pack_shape, user_shape).await? {
                    return Err(Error::engine(format!(
                        "cannot loosen spine facet '{key}' on shape '{shape_key}': {why}. The four spine facets ({}) are the interop floor (3057bba): the user layer may not loosen a pack/recommended shape, because loosening a spine facet is forking core — tighten it or restate the pack's shape",
                    SPINE_FACET_KEYS.join(", ")
                )));
                }
            }
        }
    }
    Ok(())
}

/// Reject any resolved `T:k` shape unless `k` is in T's resolved `kinds` list
/// after applying the incoming write. Checking the prospective whole prevents
/// a base `kinds` replacement from orphaning an existing pack kind-shape.
async fn assert_kind_shapes_enumerated(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    prospective: &Value,
) -> Result<()> {
    for shape_key in prospective
        .get("shapes")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|shapes| shapes.keys())
    {
        let Some((record_type, kind)) = shape_key.split_once(':') else {
            continue;
        };
        let resolution = crate::meta::kind::resolve_on(&mut *tx, record_type, kind).await?;
        if resolution.classification != crate::meta::kind::KindClassification::ActiveCanonical {
            return Err(Error::engine(format!(
                "kind-specific shape '{shape_key}' names an ungoverned kind '{kind}' or a non-canonical lifecycle value; only an active canonical value in 'kind:{record_type}' may define a shape — propose and promote it with manage_vocabularies first"
            )));
        }
    }
    Ok(())
}

/// Rejection (c) — an inert cardinality claim on any facet. Deliberately
/// NOT a limb of [`loosens`]: a limb asserts a floor under a constraint the
/// engine enforces, and there is no cardinality enforcement here to floor. The
/// four spine facets project to scalar COLUMNS on `records`
/// ([`crate::schema::spine_facet_column`]); open facets live in `facet_values`,
/// whose `UNIQUE (record_id, key)` constraint also permits only one value per
/// key. `multi` is therefore meaningless in either direction — `true` promises
/// a cardinality nothing will honour, while `false` restates what storage
/// already guarantees. Either way the resolved view advertises a constraint no
/// part of the engine reads, which is the actual harm: the config can lie. So
/// this refuses the key's PRESENCE, like rejection (b), rather than judging its
/// value.
///
/// Two consequences of not being a limb: it needs no pack view (an inert claim
/// is inert whether or not the pack shapes the key), and kind-discriminated
/// (`T:k`) shapes need no special handling because every shape key is scanned.
fn assert_no_facet_cardinality(data: &Value) -> Result<()> {
    let shapes = data.get("shapes").and_then(Value::as_object);
    for (shape_type, shape) in shapes.into_iter().flatten() {
        let Some(facets) = shape.get("facets").and_then(Value::as_object) else {
            continue;
        };
        for (key, facet) in facets {
            if facet.get("multi").is_none() {
                continue;
            }
            return Err(Error::engine(format!(
                "cannot configure `multi` on facet '{key}' (shape '{shape_type}'): every facet key is single-valued, either as a scalar column on `records` or by `facet_values`' UNIQUE (record_id, key), so cardinality is inert in either direction — `multi: true` promises many values the engine cannot store, and `multi: false` restates what storage already guarantees. Cardinality decides facet versus link: use a facet for one value (such as one owner), and model many related records (such as contributors) as `links`, which are naturally multi-valued. Drop the `multi` key rather than have the resolved view advertise a constraint nothing reads"
            )));
        }
    }
    Ok(())
}

/// Rewrite every spine facet's governing-vocabulary reference in an accepted
/// user payload into canonical `rec:<row id>` form, so what is STORED is the
/// identity limb 4 judged rather than a name that can be re-pointed later.
///
/// The user's choice of key (`vocab` vs `vocab_ref`) is preserved — only the
/// value is canonicalised. A designator naming no row is left exactly as
/// written: there is no identity to pin it to, and rewriting it would invent
/// one.
///
/// Spine keys only. Non-spine facets carry no floor, so normalising them would
/// be rewriting a user's file for no safety gain.
async fn canonicalise_spine_vocab_refs(
    conn: &mut sqlx::SqliteConnection,
    data: &mut Value,
) -> Result<()> {
    let Some(shapes) = data
        .get_mut("shapes")
        .and_then(Value::as_object_mut)
        .map(|shapes| shapes.values_mut())
    else {
        return Ok(());
    };
    for shape in shapes {
        let Some(facets) = shape.get_mut("facets").and_then(Value::as_object_mut) else {
            continue;
        };
        for (_, facet) in facets
            .iter_mut()
            .filter(|(key, _)| SPINE_FACET_KEYS.contains(&key.as_str()))
        {
            let Some(facet) = facet.as_object_mut() else {
                continue;
            };
            for key in ["vocab", "vocab_ref"] {
                let Some(designator) = facet.get(key).and_then(Value::as_str) else {
                    continue;
                };
                if let Some(row) = get_vocabulary_on(conn, resolve_vocab_ref(designator)).await? {
                    facet.insert(key.into(), Value::String(vocab_ref(&row.id)));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone)]
struct SchemaWriteLockHook {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[cfg(test)]
tokio::task_local! {
    static SCHEMA_WRITE_LOCK_HOOK: SchemaWriteLockHook;
}

/// Deterministic unit-test seam immediately after the schema write owns
/// SQLite's reserved write lock and before it reads the cascade or values.
#[cfg(test)]
async fn schema_write_lock_checkpoint() {
    let hook = SCHEMA_WRITE_LOCK_HOOK.try_with(Clone::clone).ok();
    if let Some(hook) = hook {
        hook.entered.notify_one();
        hook.release.notified().await;
    }
}

async fn manage_schema_config(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ManageSchemaConfigArgs = parse_args("manage_schema_config", arguments)?;
    match args {
        ManageSchemaConfigArgs::Read { layer } => {
            // ONE fetch for all three views. `schema_config` is direct-write by
            // design (the meta tier sits outside the append-event invariant) and
            // the edition is single-principal but many-agent, so two independent
            // reads could pair `rows` from one state with `pack`/`resolved` from
            // another. The fold is pure, so fetching every row once and filtering
            // by layer in memory is both cheaper and more coherent than a read
            // transaction around two reads.
            let all_rows = cascade::schema_config_rows(&db, None).await?;
            let mut visible_rows = Vec::with_capacity(all_rows.len());
            for row in all_rows {
                let visible = match row.applies_to_collection_id.as_deref() {
                    Some(collection) => {
                        super::can_record(&db, &caller, collection, Capability::View).await?
                    }
                    None => true,
                };
                if visible {
                    visible_rows.push(row);
                }
            }
            let all_rows = visible_rows;
            let mut cascade = cascade::resolve_from_rows(&all_rows);
            let mut conn = db.write_pool().acquire().await?;
            cascade::inject_kind_projection_on(&mut conn, &mut cascade.resolved).await?;
            let rows: Vec<&cascade::SchemaConfigRow> = match layer.map(ConfigLayer::as_str) {
                // Row order is the query's application order; filtering preserves it.
                Some(layer) => all_rows.iter().filter(|r| r.layer == layer).collect(),
                None => all_rows.iter().collect(),
            };
            Ok(json!({
                "pack": cascade.pack,
                "resolved": cascade.resolved,
                "rows": rows,
                // The two constant sets the write path judges against, so a
                // caller can see the floor without reading the source.
                "spine_facets": SPINE_FACET_KEYS,
                "reserved_facets": ENGINE_RESERVED_FACET_KEYS,
                "declared_facet_types": ["number", "object"],
                "declared_type_scope": "eligible open facets only; v1 rejects declared type on string-carried spine facets",
            }))
        }
        ManageSchemaConfigArgs::Write {
            data,
            id,
            version_lineage,
            applies_to_collection_id,
            if_schema_state_revision,
        } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let result = apply_schema_config_write_in(
                &mut tx,
                &caller,
                data,
                id,
                version_lineage,
                applies_to_collection_id,
                if_schema_state_revision.as_deref(),
            )
            .await?;
            tx.commit().await?;
            Ok(result)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_schema_config_write_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    data: Value,
    id: Option<String>,
    version_lineage: Option<String>,
    applies_to_collection_id: Option<String>,
    expected_revision: Option<&str>,
) -> Result<Value> {
    if !data.is_object() {
        return Err(Error::engine(
            "manage_schema_config: data must be a JSON object ({ shapes: ... })",
        ));
    }
    // Preserve the production error ordering: payload-wide structural guards
    // run before the scope authorization and state fence.
    assert_no_reserved_facet_keys(&data)?;
    assert_no_authored_kind_arrays(&data)?;
    assert_no_facet_cardinality(&data)?;
    assert_known_facet_types(&data)?;
    assert_valid_lifecycle_axes(&data)?;
    assert_valid_object_facet_schemas(&data)?;
    if let Some(collection) = applies_to_collection_id.as_deref() {
        super::require_record_in(
            tx,
            caller,
            "manage_schema_config",
            collection,
            Capability::Manage,
        )
        .await?;
        let record_type: String =
            sqlx::query_scalar("SELECT type FROM records WHERE id = ? AND deleted_at IS NULL")
                .bind(collection)
                .fetch_one(&mut **tx)
                .await?;
        if record_type != "Collection" {
            return Err(Error::engine(
                "manage_schema_config: applies_to_collection_id must name a Collection",
            ));
        }
    } else if !caller.is_host_owner() {
        return Err(Error::auth(
            "manage_schema_config: database owner host role required for global rows",
        ));
    }
    assert_schema_state_revision_in(tx, expected_revision).await?;
    #[cfg(test)]
    schema_write_lock_checkpoint().await;
    let mut data = data;
    canonicalise_spine_vocab_refs(tx, &mut data).await?;
    let prepared = prepare_user_schema_config_write(
        data.clone(),
        SchemaConfigOptions {
            id,
            version_lineage,
            applies_to_collection_id: applies_to_collection_id.clone(),
        },
    )?;
    let rows = cascade::schema_config_rows_in(tx).await?;
    let current = cascade::resolve_from_rows(&rows);
    let prospective_rows = cascade::rows_after_user_write(
        &rows,
        Some(prepared.id()),
        &data,
        applies_to_collection_id.as_deref(),
    );
    if let Some(bearer_id) = applies_to_collection_id.as_deref() {
        assert_kind_shapes_enumerated_scoped(tx, &prospective_rows, bearer_id).await?;
        assert_no_spine_loosening_scoped(tx, &rows, &data, bearer_id).await?;
        assert_no_type_loosening_scoped(&rows, &data, bearer_id)?;
        assert_no_object_contract_loosening_scoped(&rows, &data, bearer_id)?;
    } else {
        let prospective = cascade::resolve_from_rows(&prospective_rows).resolved;
        assert_kind_shapes_enumerated(tx, &prospective).await?;
        assert_no_spine_loosening(tx, &current.pack, &data).await?;
        assert_no_type_loosening(&current.pack, &data)?;
        assert_no_object_contract_loosening(&current.pack, &data)?;
    }
    let nonconforming_stored_values =
        count_nonconforming_declared_values(tx, &prospective_rows).await?;
    let id = append_prepared_user_schema_config_in(tx, prepared, Some(caller.actor())).await?;
    Ok(json!({
        "id": id,
        "layer": "user",
        "applies_to_collection_id": applies_to_collection_id,
        "nonconforming_stored_values": nonconforming_stored_values,
        "type_enforcement": "forward-only on supported record-writing tools for eligible open facets; historical open-facet rows are reported, not rejected or rewritten; spine declarations are rejected"
    }))
}

#[cfg(feature = "mcp-executor-prototype")]
fn schema_config_source_arguments(
    operation_arguments: Value,
    generate_id: bool,
) -> Result<(Value, Value)> {
    let mut revalidation = operation_arguments
        .as_object()
        .cloned()
        .ok_or_else(|| Error::engine("manage_schema_config.write arguments must be an object"))?;
    if revalidation.contains_key("if_schema_state_revision") {
        return Err(Error::engine(
            "schema state revision is source-owned and cannot be supplied by the caller",
        ));
    }
    if generate_id && !revalidation.contains_key("id") {
        revalidation.insert("id".into(), json!(uuid::Uuid::new_v4().to_string()));
    }
    let revalidation = Value::Object(revalidation);
    let mut canonical = revalidation
        .as_object()
        .cloned()
        .expect("revalidation arguments are an object");
    canonical.insert("action".into(), json!("write"));
    Ok((revalidation, Value::Object(canonical)))
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn validate_schema_config_mutation(operation_arguments: Value) -> Result<()> {
    let (_, source) = schema_config_source_arguments(operation_arguments, false)?;
    match parse_args::<ManageSchemaConfigArgs>("manage_schema_config", source)? {
        ManageSchemaConfigArgs::Write { .. } => Ok(()),
        ManageSchemaConfigArgs::Read { .. } => Err(Error::engine(
            "manage_schema_config.write has no exact mutation route",
        )),
    }
}

#[cfg(feature = "mcp-executor-prototype")]
async fn schema_config_snapshot_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
) -> Result<Value> {
    let rows = cascade::schema_config_rows_in(tx).await?;
    let row = rows
        .iter()
        .find(|row| row.id == id)
        .map(serde_json::to_value)
        .transpose()?
        .map(|mut row| {
            row.as_object_mut()
                .expect("schema config row serializes as an object")
                .remove("created_at");
            row
        });
    let resolved = cascade::resolve_from_rows(&rows).resolved;
    Ok(json!({"row":row,"resolved":resolved}))
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_schema_config_mutation(
    db: &Db,
    caller: &Caller,
    operation_arguments: Value,
) -> Result<SchemaMutationPreparation> {
    let (revalidation_arguments, canonical_without_revision) =
        schema_config_source_arguments(operation_arguments, true)?;
    let parsed: ManageSchemaConfigArgs =
        parse_args("manage_schema_config", canonical_without_revision.clone())?;
    let ManageSchemaConfigArgs::Write {
        data,
        id,
        version_lineage,
        applies_to_collection_id,
        if_schema_state_revision: _,
    } = parsed
    else {
        return Err(Error::engine(
            "manage_schema_config.write has no exact mutation route",
        ));
    };
    let id = id.expect("schema preparation injects an id");
    let target = match applies_to_collection_id.as_deref() {
        Some(collection) => format!("schema config row '{id}' for collection {collection}"),
        None => format!("global schema config row '{id}'"),
    };

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let state_revision = schema_state_revision_in(&mut tx).await?;
    let before = schema_config_snapshot_in(&mut tx, &id).await?;
    let (meta_before, _) = schema_state_high_waters_in(&mut tx).await?;
    let result = apply_schema_config_write_in(
        &mut tx,
        caller,
        data,
        Some(id.clone()),
        version_lineage,
        applies_to_collection_id,
        None,
    )
    .await?;
    let (meta_after, _) = schema_state_high_waters_in(&mut tx).await?;
    let after = schema_config_snapshot_in(&mut tx, &id).await?;
    tx.rollback().await?;

    let changed = meta_after != meta_before;
    let mut canonical_source_arguments = canonical_without_revision;
    canonical_source_arguments["if_schema_state_revision"] = json!(state_revision);
    let nonconforming = result["nonconforming_stored_values"]
        .as_i64()
        .unwrap_or_default();
    let effect_summary = if changed {
        format!("write {target}; report {nonconforming} nonconforming stored value(s)")
    } else {
        format!("leave {target} unchanged")
    };
    Ok(SchemaMutationPreparation {
        revalidation_arguments,
        canonical_source_arguments,
        target_id: id,
        target,
        state_revision: state_revision.clone(),
        target_state_digest: schema_value_digest(&before)?,
        effect_summary,
        effect: json!({
            "action":"write",
            "changed":changed,
            "projection_changed":before != after,
            "source_event_appended":changed,
            "before":before,
            "after":after,
            "result":result,
        }),
        operation_evidence: json!({
            "kind":"schema_config_write",
            "schema_state_revision":state_revision,
        }),
    })
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register tools 20–21.
pub fn register_meta_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageVocabularies,
        "Governed vocabularies and their values. The lifecycle is propose → \
         promote → deprecate → alias, not CRUD: a value leaves service by being \
         deprecated (existing assignments keep resolving), and renames/merges go \
         through alias_value. Values carry a per-vocabulary fractional ordinal \
         and open/terminal-positive/terminal-negative progression meaning; \
         reorder_value changes ordering metadata without touching lifecycle, \
         and set_gloss amends an existing value's prose gloss in place without \
         touching lifecycle either. \
         Hard delete exists only for values and \
         vocabularies that are neither seeded nor referenced. Use list_values \
         and the schema/facet surfaces to inspect them.",
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "list_values", "create_vocabulary", "propose_value",
                        "reorder_value", "set_gloss", "set_metadata",
                        "promote_value", "deprecate_value", "alias_value",
                        "delete_value", "delete_vocabulary"
                    ]
                },
                "vocabulary": {
                    "type": "string",
                    "description": "Vocabulary id or name (list_values, propose_value, delete_vocabulary)."
                },
                "name": { "type": "string", "description": "New vocabulary's name (create_vocabulary), e.g. \"lifecycle\" or \"kind:Document\"." },
                "id": { "type": "string", "description": "Explicit vocabulary id (create_vocabulary); defaults to voc:<name>." },
                "value": { "type": "string", "description": "The value to propose (propose_value)." },
                "gloss": { "type": "string", "description": "Short prose definition of what the value means (propose_value, and set_gloss to amend an existing value; null clears it)." },
                "ordinal": {
                    "type": "number",
                    "description": "Per-vocabulary fractional order (propose_value and reorder_value; default 0 on proposal). Sparse values such as 100, 200, 300 leave insertion room."
                },
                "terminality": {
                    "type": "string",
                    "enum": ["open", "terminal_positive", "terminal_negative"],
                    "description": "Progression meaning for a proposed value, distinct from lifecycle status (default open)."
                },
                "metadata": {
                    "type": "object",
                    "description": "Required KindMetadataV1 for values proposed in kind:<Type>; set_metadata replaces it through an authoritative metadata event.",
                    "properties": {
                        "schema_version": { "type": "integer", "const": 1 },
                        "provenance_ref": { "type": "string", "description": "Non-empty rec:<id> citation." },
                        "definition": { "type": "string" },
                        "identity": {
                            "type": "object",
                            "properties": {
                                "criterion": { "type": "string" },
                                "dedup": {
                                    "type": "object",
                                    "properties": {
                                        "mode": { "type": "string", "enum": ["external_binding", "facet_tuple", "record_id", "manual"] },
                                        "keys": { "type": "array", "items": { "type": "string" } }
                                    },
                                    "required": ["mode", "keys"],
                                    "additionalProperties": false
                                }
                            },
                            "required": ["criterion", "dedup"],
                            "additionalProperties": false
                        },
                        "declared_capabilities": { "type": "array", "items": { "type": "string" } },
                        "legacy_unattested": { "type": "boolean" }
                    },
                    "required": ["schema_version", "provenance_ref", "definition", "identity", "declared_capabilities"],
                    "additionalProperties": false
                },
                "value_id": { "type": "string", "description": "Vocabulary-value id (reorder/set_gloss/promote/deprecate/alias/delete_value)." },
                "canonical_id": { "type": "string", "description": "The value this one redirects to (alias_value). Chains are rejected." },
                "status": {
                    "type": "string",
                    "enum": ["proposed", "active", "deprecated"],
                    "description": "Filter a listing by status (list_values)."
                },
                "resolve_aliases": {
                    "type": "boolean",
                    "description": "Resolve alias_of into its canonical value on each listed value (list_values, default true)."
                }
            },
            "required": ["action"],
            "additionalProperties": false
        }),
        manage_vocabularies,
    )?;
    registry.register(
        ToolKind::ManageSchemaConfig,
        "Read the resolved pack → user schema_config cascade (both views, \
         closest-wins) and write the user layer — the only editable one; pack \
         rows are seed-only. A full user row may optionally be anchored to one \
         record's direct members. Three rejections on write: engine-reserved facet \
         keys (archived) are not user-configurable in either direction; `multi` \
         on any facet is refused in either direction, since every facet key is \
         single-valued and many related records belong in links; and the user \
         layer may not loosen \
         a spine facet below the pack shape — the interop floor.",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["read", "write"] },
                "layer": {
                    "type": "string",
                    "enum": ["pack", "user"],
                    "description": "Restrict the returned rows to one layer (read). The pack and resolved views are always both returned."
                },
                "data": {
                    "type": "object",
                    "description": "The user-layer config: { shapes: { <Type or Type:kind>: { facets } } } (write). Kind arrays are rejected; use manage_vocabularies."
                },
                "id": {
                    "type": "string",
                    "description": "Row id to upsert (write). Omit for a new row; a pack row id is rejected."
                },
                "version_lineage": {
                    "type": "string",
                    "description": "Compat-lineage marker for this row (write) — distinct from the event log."
                },
                "applies_to_collection_id": {
                    "type": ["string", "null"],
                    "description": "Optional record id anchoring this full row to that record's direct members. Omit or null for a global row."
                }
            },
            "required": ["action"],
            "additionalProperties": false
        }),
        manage_schema_config,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_string_facet(registry: &ToolRegistry, db: &Db, id: &str) -> Result<Value> {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": id,
                    "type": "Outcome",
                    "kind": "target",
                    "reason": "Exercise schema-write serialization.",
                    "facets": { "target": "not-a-number" }
                }),
            )
            .await
    }

    fn numeric_target_schema() -> Value {
        json!({
            "action": "write",
            "id": "user:numeric-target",
            "data": { "shapes": { "Outcome": { "facets": {
                "target": { "type": "number" }
            } } } }
        })
    }

    #[tokio::test]
    async fn schema_count_and_declaration_share_the_write_lock_boundary() {
        // A supported content write that commits first is part of the exact
        // snapshot the schema declaration reports.
        let before_db = crate::create_database(":memory:").await.unwrap();
        let mut before_registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut before_registry).unwrap();
        create_string_facet(
            &before_registry,
            &before_db,
            "0e7a0000-0000-4000-8000-000000000001",
        )
        .await
        .unwrap();
        let before = manage_schema_config(before_db, Caller::local(), numeric_target_schema())
            .await
            .unwrap();
        assert_eq!(before["nonconforming_stored_values"], 1);

        // Once the schema write owns BEGIN IMMEDIATE, a supported content
        // writer is queued behind both the count and declaration. It then sees
        // the committed numeric shape and cannot add a historical string that
        // the successful response failed to count.
        let after_db = crate::create_database(":memory:").await.unwrap();
        let mut after_registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut after_registry).unwrap();
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let schema_hook = SchemaWriteLockHook {
            entered: entered.clone(),
            release: release.clone(),
        };
        let schema_db = after_db.clone();
        let schema = tokio::spawn(SCHEMA_WRITE_LOCK_HOOK.scope(
            schema_hook,
            manage_schema_config(schema_db, Caller::local(), numeric_target_schema()),
        ));
        entered.notified().await;

        let before_begin = std::sync::Arc::new(tokio::sync::Notify::new());
        let writer_db = after_db.clone();
        let writer = tokio::spawn(crate::db::with_before_begin_write_notification(
            before_begin.clone(),
            async move {
                create_string_facet(
                    &after_registry,
                    &writer_db,
                    "0e7a0000-0000-4000-8000-000000000002",
                )
                .await
            },
        ));
        before_begin.notified().await;
        assert!(
            !writer.is_finished(),
            "content writer must be queued behind the schema write lock"
        );

        release.notify_one();
        let response = schema.await.unwrap().unwrap();
        assert_eq!(response["nonconforming_stored_values"], 0);
        let error = writer.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("requires a JSON number"), "{error}");

        let stored: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_values WHERE record_id = 'after' AND key = 'target'",
        )
        .fetch_one(after_db.write_pool())
        .await
        .unwrap();
        assert_eq!(stored, 0);
    }
}
