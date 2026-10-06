//! Member-scope axis for every `ToolKind` (contract c323277 rev 7 §3.1
//! last sentence, §2.3 per-surface table, §2.6 omitted fields, §6.2, §2.5).
//!
//! This is data, not behaviour: it records, per tool, the member-offline
//! answer decided by §2.3 so that a new `ToolKind` without a member
//! classification fails the build (the exhaustive match in
//! [`ToolKind::member_scope`](super::interactions::ToolKind::member_scope)
//! has no wildcard arm, like `holding_classification`).
//!
//! Variants (§2.3 groups):
//! - `Served`: answered over the slice at parity, omitting the listed §2.6
//!   fields, refusing the listed arguments, and refusing the listed write
//!   actions with typed `STANDBY_READ_ONLY` (§6.2);
//! - `ServedPartial`: served, but the listed sections become
//!   `unavailable_offline` markers rather than silent omissions;
//! - `SchemaGated`: served, except it refuses entirely with
//!   `unavailable_offline` where the §3.3 rule-6 exact-id gate withheld a
//!   row that applies (global → everywhere, collection-scoped → that
//!   collection). A refusal, never a marker;
//! - `UnavailableOffline`: refused with typed `UnavailableOffline` before
//!   any storage access (§2.3(b));
//! - `WriteRefused`: every action is a write and gets the typed
//!   `STANDBY_READ_ONLY` refusal (§6.2). This covers every `Mutation` tool
//!   except `Quickstart`, which §2.3(a) serves locally.
//!
//! Mixed tools carry their write actions in the served variants'
//! `refused_write_actions`, so read actions stay served while
//! `manage_attachments.detach` and `manage_links.add|remove` refuse with
//! `STANDBY_READ_ONLY` — a consumer keyed only off `member_scope()` cannot
//! mistake them for served.
//!
//! Where §2.3 is silent or ambiguous for a tool, it is
//! `UnavailableOffline` (fail closed). Every arm below cites its
//! §2.3 row; the fail-closed-by-default set is empty today and the
//! exhaustive test pins that.

use super::interactions::ToolKind;

/// An argument whose presence on a member copy is refused (§2.3 "→ refuse").
/// Typed rather than a bare string so the map names an argument once, and so
/// `refused_arg_names_are_distinct_live_argument_keys` can assert the names
/// are distinct and spelled exactly. That test does not read the live tool
/// schemas; a typo in `name()` that stays distinct would not be caught here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusedArg {
    AsOf,
    Activity,
    IncludeCoordination,
}

impl RefusedArg {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AsOf => "as_of",
            Self::Activity => "activity",
            Self::IncludeCoordination => "include_coordination",
        }
    }
}

/// How one tool answers on a member copy.
///
/// Read and write answers live in one value so a consumer keyed only off
/// [`ToolKind::member_scope`](super::interactions::ToolKind::member_scope)
/// cannot mistake a mixed tool's write action for a served read. The
/// `refused_write_actions` list names the actions that get the typed
/// `STANDBY_READ_ONLY` refusal (§6.2) while the read actions stay served
/// (`manage_attachments.detach`, `manage_links.add|remove`).
///
/// `omitted_fields` are the §2.6 field spellings verbatim (the contract
/// quotes them, so the strings stay literal); `refused_args` are typed
/// [`RefusedArg`] names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberScope {
    /// Served over the slice at parity (§2.3(a) full rows).
    Served {
        /// §2.6 fields this surface omits (tokens as §2.6 spells them).
        omitted_fields: &'static [&'static str],
        /// Argument-level refusals (§2.3 "→ refuse" notes).
        refused_args: &'static [RefusedArg],
        /// Write actions of a mixed tool, refused with the typed
        /// `STANDBY_READ_ONLY` (§2.3(c)/§6.2); empty for a pure read.
        refused_write_actions: &'static [&'static str],
    },
    /// Served, with the listed sections as `unavailable_offline` markers.
    ServedPartial {
        /// Sections replaced by markers, never omitted silently.
        unavailable_sections: &'static [&'static str],
        /// §2.6 fields this surface omits.
        omitted_fields: &'static [&'static str],
        /// Argument-level refusals.
        refused_args: &'static [RefusedArg],
        /// Write actions of a mixed tool (§2.3(c)/§6.2).
        refused_write_actions: &'static [&'static str],
    },
    /// Served at parity, but refuses entirely with `unavailable_offline`
    /// where the §3.3 rule-6 exact-id gate withheld a row that applies:
    /// `global` → everywhere, collection-scoped → that collection only.
    /// This is a refusal, never a marker that could stand in for an answer.
    SchemaGated {
        /// §2.6 fields this surface omits.
        omitted_fields: &'static [&'static str],
        /// Argument-level refusals.
        refused_args: &'static [RefusedArg],
        /// Write actions of a mixed tool (§2.3(c)/§6.2).
        refused_write_actions: &'static [&'static str],
    },
    /// Refused before storage access (§2.3(b)).
    UnavailableOffline,
    /// Write refused with typed `STANDBY_READ_ONLY` (§2.3(c), §6.2).
    WriteRefused,
}

impl MemberScope {
    /// The write actions that refuse with `STANDBY_READ_ONLY`, or `None`
    /// when the tool has no served read to pair them with (wholesale
    /// refusals). `Some(&[])` means served with no write actions.
    pub const fn refused_write_actions(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Served {
                refused_write_actions,
                ..
            }
            | Self::ServedPartial {
                refused_write_actions,
                ..
            }
            | Self::SchemaGated {
                refused_write_actions,
                ..
            } => Some(refused_write_actions),
            Self::UnavailableOffline | Self::WriteRefused => None,
        }
    }
}

/// Served `query_sql` relations (§2.3(a) `query_sql` row, rev 7 §2.3, 1e5d802
/// §2a). The same governed views with the same column sets, over the slice,
/// plus the two catalog relations served locally from the compiled contract
/// (never shipped in the artifact; identical for every caller).
///
/// Row-level rules live with the data, not here: `bindings` own-only,
/// `schema_config` only if the exact-id gate passed, external-tier blob
/// bytes as `not_held`. Every other relation — including the two
/// log-position views (`content_events`, `facet_observations`), `actors`,
/// `agent_activity*`, `messages_awaiting_reply` and
/// `effective_relationships` — raises typed `UnavailableOffline` at prepare
/// time. The envelope omits `as_of_seq` (§2.6).
///
/// Classification only in this increment (no runtime wiring yet), so nothing
/// outside tests reads this until the query_sql port is wired to it.
#[allow(dead_code)]
pub const QUERY_SQL_SERVED_RELATIONS: &[&str] = &[
    "records",
    "links",
    "facet_values",
    "facet_times",
    "bindings",
    "blobs",
    "vocabularies",
    "vocabulary_values",
    "schema_config",
    "catalog_relations",
    "catalog_columns",
];

/// Member-scope classification for every `ToolKind`. Called only from
/// [`ToolKind::member_scope`](super::interactions::ToolKind::member_scope);
/// kept as a free function so the match stays beside this module's docs.
pub(crate) const fn classify(kind: ToolKind) -> MemberScope {
    use MemberScope::{SchemaGated, Served, ServedPartial, UnavailableOffline, WriteRefused};
    use RefusedArg::{Activity, AsOf, IncludeCoordination};
    use ToolKind as K;
    match kind {
        // §2.3(a), served locally, no slice access: report the scope holding.
        K::Ping | K::EngineInfo | K::StandbyStatus => Served {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `read_guide, quickstart`: build-owned compile-time
        // content. Note: Quickstart is `Mutation` authoritatively but §2.3
        // serves it; §2.3(c) does not list it among refused writes.
        K::ReadGuide | K::Quickstart => Served {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `bootstrap`: reduced footing, caller-bound instructions,
        // record-derived scan, scope holding; run/claim/intent are markers.
        K::Bootstrap => ServedPartial {
            unavailable_sections: &["run", "claim", "intent"],
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `get_record`: parity minus §2.6 version tokens; excluded
        // sections become markers (incl. `kind_governance` when the schema
        // gate withheld a row, §2.4 item 12); the saved governed-SQL path
        // omits `as_of_seq` (§2.6 row 4); `as_of` refuses.
        K::GetRecord => ServedPartial {
            unavailable_sections: &[
                "history_summary",
                "contribution",
                "citation_resolution",
                "message_audience",
                "message_mentions",
                "kind_governance (schema-gated)",
            ],
            omitted_fields: &[
                "version (rec:<seq>)",
                "facet version (obs:<seq>)",
                "saved governed SQL as_of_seq (§2.6 row 4)",
            ],
            refused_args: &[AsOf],
            refused_write_actions: &[],
        },
        // §2.3(a) `resolve_many, batch reads`: per-item parity; version
        // tokens omitted as batch reads; the saved governed-SQL path omits
        // `as_of_seq` too (§2.6 row 4).
        K::ResolveMany => Served {
            omitted_fields: &[
                "version (rec:<seq>)",
                "facet version (obs:<seq>)",
                "saved governed SQL as_of_seq (§2.6 row 4)",
            ],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `render_record`: minimum-journey rendering; version
        // omitted (§2.6 get_record/batch/render row).
        K::RenderRecord => Served {
            omitted_fields: &["version (rec:<seq>)", "facet version (obs:<seq>)"],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `search, scan`: corpus-independent ranking over the
        // slice; scan samples carry display_reference (shipped, §2.4).
        K::Search | K::Scan => Served {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `query_record`: slice parity; page snapshot omits its
        // content coordinates (§2.6) for an opaque page basis.
        K::QueryRecord => Served {
            omitted_fields: &["as_of.content_seq", "content_head_seq"],
            refused_args: &[AsOf, Activity, IncludeCoordination],
            refused_write_actions: &[],
        },
        // §2.3(a) `open_collection` (§2.5, in v1): members from
        // query_record over the slice; counter fields omitted as for
        // query_record, plus its governed-SQL path's `as_of_seq`
        // (§2.6 row 4). A saved definition using as_of/activity or
        // coordination refuses.
        K::OpenCollection => Served {
            omitted_fields: &[
                "as_of.content_seq",
                "content_head_seq",
                "saved governed SQL as_of_seq (§2.6 row 4)",
            ],
            refused_args: &[AsOf, Activity, IncludeCoordination],
            refused_write_actions: &[],
        },
        // §2.3(a) `query_sql`: row parity under the relation rule
        // (QUERY_SQL_SERVED_RELATIONS); envelope omits as_of_seq (§2.6).
        K::QuerySql => Served {
            omitted_fields: &["as_of_seq"],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) `get_structure`: post-visibility child counts; hidden
        // parents surface as NULL home_id; `as_of` refuses.
        K::GetStructure => Served {
            omitted_fields: &[],
            refused_args: &[AsOf],
            refused_write_actions: &[],
        },
        // §2.3(a) `get_dashboard`: record-derived parts; claims and run
        // sections are markers.
        K::GetDashboard => ServedPartial {
            unavailable_sections: &["claims", "run_sections"],
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) schema three: caller-independent vocabularies plus scoped
        // schema. Where the exact-id gate withheld a row that applies
        // (global → everywhere, collection-scoped → that collection) the
        // surface refuses with `unavailable_offline` (§3.3 rule 6) — a
        // refusal, never a marker standing in for an answer.
        K::DescribeSchema | K::PreviewRecordShape | K::SuggestFacetValues => SchemaGated {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // As above, plus the facet version token omitted (§2.6).
        K::ResolveFacets => SchemaGated {
            omitted_fields: &["facet version (obs:<seq>)"],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // §2.3(a) attachments: inline tier at parity; external-tier bytes
        // are per-item not_held (R2), not a refused section.
        K::ReadAttachment => Served {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &[],
        },
        // `detach` is a write action: refused with the typed
        // STANDBY_READ_ONLY (§2.3(c)/§6.2) while list/inspect stay served.
        K::ManageAttachments => Served {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &["detach"],
        },
        // §2.3(a) `manage_links (list)`: both endpoints visible. `add` and
        // `remove` are write actions and refuse with STANDBY_READ_ONLY.
        K::ManageLinks => Served {
            omitted_fields: &[],
            refused_args: &[],
            refused_write_actions: &["add", "remove"],
        },
        // §2.3(b) history (Richard's decision 1): refused, never partial.
        K::GetHistory
        | K::WhatsChanged
        | K::GetEventContext
        | K::GetRunActivity
        | K::RenderRecordVersionDiff
        | K::ReadAttributions
        | K::QueryChangeSummaries
        | K::ManageFacetObservations
        | K::GetWorkspaceSnapshot
        | K::GetReuseContext => UnavailableOffline,
        // §2.3(b) server-side reductions that could depend on hidden
        // inputs (Q5): need a server result or fixture first.
        K::ResolveRollup | K::ManageRelationships => UnavailableOffline,
        // §2.3(b) needs-excluded-tables group.
        K::ResolveCitation
        | K::RenderSuggestionReview
        | K::ManageMessages
        | K::ReadCanvas
        | K::RenderArtifact
        | K::VerifyArtifact
        | K::ManageRecordPolicy
        | K::ManageBindings
        | K::ManageVocabularies
        | K::ManageSchemaConfig
        | K::ManageInstructions
        | K::ManageOnboarding
        | K::ManageChangeSummaries
        | K::ManageInterventions
        | K::ManageRendererBinding
        | K::ManageMdxModules
        | K::ManageArtifactInputs
        | K::ManageArtifactModuleGrants
        | K::ManageSurfaceBindings
        | K::ManageAlphaTabs
        | K::StartWork => UnavailableOffline,
        // §2.3(b) catalog or hosting state (HostOwner-only or roster).
        K::ManageMemberships
        | K::WorkspaceRead
        | K::ReachRead
        | K::AuthorityActHead
        | K::AuthorityActDelta => UnavailableOffline,
        // §2.3(c) writes: typed STANDBY_READ_ONLY (§6.2). ExportSnapshot is
        // Mutation: it refuses as a write before its §2.3(b) history reason
        // could apply.
        K::SetIntent
        | K::CloseRun
        | K::CreateRecord
        | K::CreateMany
        | K::CreateExploration
        | K::BatchWrite
        | K::SaveAccount
        | K::UpdateRecord
        | K::ClaimUnownedRecord
        | K::CorrectRecordType
        | K::DeleteRecord
        | K::ArchiveRecord
        | K::ResolveExternal
        | K::ObserveExternal
        | K::InstantiateArtifact
        | K::AdvanceArtifactPortPin
        | K::InvokeArtifactInteraction
        | K::AttachText
        | K::AttachFromUrl
        | K::ResolveSuggestions
        | K::ExportSnapshot
        | K::ManageCitations
        | K::CreateAttribution
        | K::ManageCanvas
        | K::ManageAttributions
        | K::ReachConnect => WriteRefused,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{MemberScope, QUERY_SQL_SERVED_RELATIONS};
    use crate::mcp::interactions::{AuthoritativeDisposition, ToolKind};
    use crate::mcp::{ExposureProfile, ToolRegistry};

    fn scope(kind: ToolKind) -> MemberScope {
        kind.member_scope()
    }

    #[test]
    fn every_tool_has_exactly_one_member_classification() {
        let names = ToolKind::ALL
            .iter()
            .map(|kind| kind.name())
            .collect::<Vec<_>>();
        assert_eq!(
            names.iter().collect::<BTreeSet<_>>().len(),
            names.len(),
            "ToolKind::ALL must not repeat a tool"
        );
        // The match has no wildcard arm, so a new ToolKind fails the build;
        // this pins the current 87 and that no name repeats.
        assert_eq!(ToolKind::ALL.len(), 87);
    }

    #[test]
    fn every_write_is_write_refused() {
        // §2.3(c) + §6.2 typed STANDBY_READ_ONLY. Quickstart is the single
        // exemption: Mutation authoritatively, served locally by §2.3(a),
        // and absent from the §2.3(c) refusal list.
        for kind in ToolKind::ALL {
            if matches!(
                kind.authoritative_disposition(),
                AuthoritativeDisposition::Mutation
            ) && kind != ToolKind::Quickstart
            {
                assert_eq!(
                    scope(kind),
                    MemberScope::WriteRefused,
                    "{:?} is a write and must refuse with STANDBY_READ_ONLY",
                    kind
                );
            }
        }
        assert!(
            matches!(scope(ToolKind::Quickstart), MemberScope::Served { .. }),
            "Quickstart is served locally despite its Mutation disposition"
        );
    }

    #[test]
    fn every_section_2_3b_surface_is_unavailable_offline() {
        // The §2.3(b) groups, verbatim. ExportSnapshot is the principled
        // exemption: it is Mutation, so it refuses as a write (§2.3(c))
        // before its history reason could apply.
        let unavailable = [
            ToolKind::GetHistory,
            ToolKind::WhatsChanged,
            ToolKind::GetEventContext,
            ToolKind::GetRunActivity,
            ToolKind::RenderRecordVersionDiff,
            ToolKind::ReadAttributions,
            ToolKind::QueryChangeSummaries,
            ToolKind::ManageFacetObservations,
            ToolKind::GetWorkspaceSnapshot,
            ToolKind::GetReuseContext,
            ToolKind::ResolveRollup,
            ToolKind::ManageRelationships,
            ToolKind::ResolveCitation,
            ToolKind::RenderSuggestionReview,
            ToolKind::ManageMessages,
            ToolKind::ReadCanvas,
            ToolKind::RenderArtifact,
            ToolKind::VerifyArtifact,
            ToolKind::ManageRecordPolicy,
            ToolKind::ManageBindings,
            ToolKind::ManageVocabularies,
            ToolKind::ManageSchemaConfig,
            ToolKind::ManageInstructions,
            ToolKind::ManageOnboarding,
            ToolKind::ManageChangeSummaries,
            ToolKind::ManageInterventions,
            ToolKind::ManageRendererBinding,
            ToolKind::ManageMdxModules,
            ToolKind::ManageArtifactInputs,
            ToolKind::ManageArtifactModuleGrants,
            ToolKind::ManageSurfaceBindings,
            ToolKind::ManageAlphaTabs,
            ToolKind::StartWork,
            ToolKind::ManageMemberships,
            ToolKind::WorkspaceRead,
            ToolKind::ReachRead,
            ToolKind::AuthorityActHead,
            ToolKind::AuthorityActDelta,
        ];
        assert_eq!(unavailable.len(), 38);
        for kind in unavailable {
            assert_eq!(
                scope(kind),
                MemberScope::UnavailableOffline,
                "{:?} is §2.3(b) and must refuse before storage access",
                kind
            );
        }
        // Converse (N5): no tool outside the §2.3(b) list may be
        // UnavailableOffline without a contract row. ExportSnapshot is the
        // one documented exception: Mutation, so it refuses as a write.
        let expected = unavailable
            .into_iter()
            .map(|kind| kind.name())
            .collect::<BTreeSet<_>>();
        let actual = ToolKind::ALL
            .iter()
            .filter(|kind| scope(**kind) == MemberScope::UnavailableOffline)
            .map(|kind| kind.name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "the UnavailableOffline set must equal the §2.3(b) list exactly"
        );
        assert_eq!(
            scope(ToolKind::ExportSnapshot),
            MemberScope::WriteRefused,
            "ExportSnapshot refuses as a write first"
        );
    }

    #[test]
    fn every_write_action_of_every_mixed_tool_is_refused() {
        // N2: a mixed (`Actions`) tool keeps its read actions served but
        // every write action refuses with STANDBY_READ_ONLY (§2.3(c)/§6.2).
        // A mixed tool that is served must enumerate its write actions; one
        // that refuses wholesale is covered by UnavailableOffline.
        let tools = registered_tools();
        for kind in ToolKind::ALL {
            let Some(read_actions) = kind.authoritative_disposition().actions() else {
                continue;
            };
            match scope(kind) {
                MemberScope::UnavailableOffline | MemberScope::WriteRefused => {}
                MemberScope::Served { .. }
                | MemberScope::ServedPartial { .. }
                | MemberScope::SchemaGated { .. } => {
                    // NC3: expected write actions come from the live JSON
                    // input schema (every declared action minus the admitted
                    // reads), not from the map the assertion checks.
                    let declared = live_actions(&tools, kind);
                    let expected: BTreeSet<String> = declared
                        .iter()
                        .filter(|action| !read_actions.contains(&action.as_str()))
                        .cloned()
                        .collect();
                    let actual: BTreeSet<String> = write_actions(kind)
                        .iter()
                        .map(|action| (*action).to_owned())
                        .collect();
                    assert!(
                        !expected.is_empty(),
                        "{kind:?} is a served mixed tool but its live schema declares no writes"
                    );
                    assert_eq!(
                        actual, expected,
                        "{kind:?}: refused_write_actions must equal the live actions minus read actions"
                    );
                    for action in &actual {
                        assert!(
                            !read_actions.contains(&action.as_str()),
                            "{kind:?}: {action} is listed as a read action, not a write"
                        );
                        assert!(
                            !kind.authoritative_disposition().admits(&serde_json::json!({
                                "action": action
                            })),
                            "{kind:?}: {action} must not be admitted as a read"
                        );
                    }
                }
            }
        }
        // The two mixed served tools, pinned.
        assert_eq!(write_actions(ToolKind::ManageAttachments), ["detach"]);
        assert_eq!(write_actions(ToolKind::ManageLinks), ["add", "remove"]);
    }

    #[test]
    fn refused_arg_names_are_distinct_live_argument_keys() {
        use super::RefusedArg::{Activity, AsOf, IncludeCoordination};
        assert_eq!(AsOf.name(), "as_of");
        assert_eq!(Activity.name(), "activity");
        assert_eq!(IncludeCoordination.name(), "include_coordination");
        let names = [AsOf.name(), Activity.name(), IncludeCoordination.name()];
        assert_eq!(
            names.iter().collect::<BTreeSet<_>>().len(),
            names.len(),
            "refused argument names must be distinct"
        );
    }

    fn omitted(kind: ToolKind) -> Vec<&'static str> {
        match scope(kind) {
            MemberScope::Served { omitted_fields, .. }
            | MemberScope::ServedPartial { omitted_fields, .. }
            | MemberScope::SchemaGated { omitted_fields, .. } => omitted_fields.to_vec(),
            other => panic!("{kind:?} is not served: {other:?}"),
        }
    }

    fn refused_args(kind: ToolKind) -> Vec<&'static str> {
        match scope(kind) {
            MemberScope::Served { refused_args, .. }
            | MemberScope::ServedPartial { refused_args, .. }
            | MemberScope::SchemaGated { refused_args, .. } => {
                refused_args.iter().map(|arg| arg.name()).collect()
            }
            other => panic!("{kind:?} is not served: {other:?}"),
        }
    }

    fn write_actions(kind: ToolKind) -> Vec<&'static str> {
        scope(kind)
            .refused_write_actions()
            .unwrap_or_else(|| panic!("{kind:?} is not a served surface"))
            .to_vec()
    }

    /// The live registry projection: the tool's declared `action` values, read
    /// from its JSON input schema (NC3). Derived from the same descriptors MCP
    /// discovery advertises, not from the map under test.
    fn registered_tools() -> Vec<crate::mcp::AdvertisedTool> {
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).expect("builtins register");
        crate::mcp::register_surface_tools(&mut registry).expect("surface tools register");
        registry.descriptor_projection(ExposureProfile::Complete)
    }

    fn collect_action_values(schema: &serde_json::Value, out: &mut BTreeSet<String>) {
        if let Some(action) = schema
            .get("properties")
            .and_then(|properties| properties.get("action"))
        {
            if let Some(single) = action.get("const").and_then(|value| value.as_str()) {
                out.insert(single.to_owned());
            }
            if let Some(values) = action.get("enum").and_then(|value| value.as_array()) {
                for value in values {
                    if let Some(action) = value.as_str() {
                        out.insert(action.to_owned());
                    }
                }
            }
        }
        for keyword in ["oneOf", "anyOf", "allOf"] {
            if let Some(branches) = schema.get(keyword).and_then(|value| value.as_array()) {
                for branch in branches {
                    collect_action_values(branch, out);
                }
            }
        }
    }

    fn live_actions(tools: &[crate::mcp::AdvertisedTool], kind: ToolKind) -> BTreeSet<String> {
        let tool = tools
            .iter()
            .find(|tool| tool.name == kind.name())
            .unwrap_or_else(|| panic!("{kind:?} is not registered"));
        let mut actions = BTreeSet::new();
        collect_action_values(&tool.descriptor["inputSchema"], &mut actions);
        assert!(
            !actions.is_empty(),
            "{kind:?} declares no action values in its live schema"
        );
        actions
    }

    fn sections(kind: ToolKind) -> Vec<&'static str> {
        match scope(kind) {
            MemberScope::ServedPartial {
                unavailable_sections,
                ..
            } => unavailable_sections.to_vec(),
            MemberScope::Served { .. } | MemberScope::SchemaGated { .. } => Vec::new(),
            other => panic!("{kind:?} is not served: {other:?}"),
        }
    }

    #[test]
    fn every_section_2_6_row_is_represented_where_it_names_tools() {
        // query_sql envelope omits as_of_seq.
        assert!(omitted(ToolKind::QuerySql).contains(&"as_of_seq"));
        // query_record page (and open_collection members) omit the content
        // coordinates for an opaque page basis.
        for kind in [ToolKind::QueryRecord, ToolKind::OpenCollection] {
            assert!(omitted(kind).contains(&"as_of.content_seq"), "{kind:?}");
            assert!(omitted(kind).contains(&"content_head_seq"), "{kind:?}");
            assert!(refused_args(kind).contains(&"as_of"), "{kind:?}");
            assert!(refused_args(kind).contains(&"activity"), "{kind:?}");
            assert!(
                refused_args(kind).contains(&"include_coordination"),
                "{kind:?}"
            );
        }
        // Record version tokens omitted on the surfaces §2.6 names
        // (`get_record`, batch reads, `render_record`).
        for kind in [
            ToolKind::GetRecord,
            ToolKind::ResolveMany,
            ToolKind::RenderRecord,
        ] {
            assert!(omitted(kind).contains(&"version (rec:<seq>)"), "{kind:?}");
        }
        // Facet version tokens omitted on those plus `resolve_facets` (§2.6
        // "the same, plus resolve_facets": it omits only the facet token,
        // never the record token).
        for kind in [
            ToolKind::GetRecord,
            ToolKind::ResolveMany,
            ToolKind::RenderRecord,
            ToolKind::ResolveFacets,
        ] {
            assert!(
                omitted(kind).contains(&"facet version (obs:<seq>)"),
                "{kind:?}"
            );
        }
        assert!(
            !omitted(ToolKind::ResolveFacets).contains(&"version (rec:<seq>)"),
            "resolve_facets omits only the facet token (§2.6)"
        );
        // §2.6 row 4 (`execute_saved_sql`, including open_collection's
        // governed-SQL path) omits `as_of_seq`; reached through get_record,
        // batch resolution and open_collection (N1).
        for kind in [
            ToolKind::GetRecord,
            ToolKind::ResolveMany,
            ToolKind::OpenCollection,
        ] {
            assert!(
                omitted(kind)
                    .iter()
                    .any(|field| field.contains("saved governed SQL")),
                "{kind:?} reaches the saved-SQL path and must omit as_of_seq (§2.6 row 4)"
            );
        }
        // N3: the exact-id schema gate is a refusal, not a marker.
        for kind in [
            ToolKind::DescribeSchema,
            ToolKind::PreviewRecordShape,
            ToolKind::SuggestFacetValues,
            ToolKind::ResolveFacets,
        ] {
            assert!(
                matches!(scope(kind), MemberScope::SchemaGated { .. }),
                "{kind:?} must model the §3.3 rule-6 gate as a conditional refusal"
            );
        }
        // N4: get_record's kind_governance is a schema-gate marker (§2.4
        // item 12).
        assert!(
            sections(ToolKind::GetRecord)
                .iter()
                .any(|section| section.contains("kind_governance")),
            "get_record must mark kind_governance when the schema gate withholds a row"
        );
        // get_record argument refusal and marker sections.
        assert!(refused_args(ToolKind::GetRecord).contains(&"as_of"));
        for section in [
            "history_summary",
            "contribution",
            "citation_resolution",
            "message_audience",
            "message_mentions",
        ] {
            assert!(sections(ToolKind::GetRecord).contains(&section));
        }
        // get_structure / get_dashboard argument and marker rules.
        assert!(refused_args(ToolKind::GetStructure).contains(&"as_of"));
        for section in ["claims", "run_sections"] {
            assert!(sections(ToolKind::GetDashboard).contains(&section));
        }
        // bootstrap markers.
        for section in ["run", "claim", "intent"] {
            assert!(sections(ToolKind::Bootstrap).contains(&section));
        }
        // Version/history reads and rollups cannot emit their §2.6 fields
        // because the surfaces refuse outright.
        for kind in [
            ToolKind::GetHistory,
            ToolKind::WhatsChanged,
            ToolKind::ResolveRollup,
            ToolKind::ReadAttributions,
        ] {
            assert_eq!(scope(kind), MemberScope::UnavailableOffline, "{kind:?}");
        }
    }

    #[test]
    fn query_sql_serves_exactly_the_contract_relations() {
        assert_eq!(
            QUERY_SQL_SERVED_RELATIONS,
            &[
                "records",
                "links",
                "facet_values",
                "facet_times",
                "bindings",
                "blobs",
                "vocabularies",
                "vocabulary_values",
                "schema_config",
                "catalog_relations",
                "catalog_columns",
            ],
            "served relations are the §2.3(a) views plus the two catalog relations"
        );
        // The refused log-position views and operational relations (§2.3).
        for refused in [
            "content_events",
            "facet_observations",
            "actors",
            "agent_activity",
            "agent_activity_claims",
            "messages_awaiting_reply",
            "effective_relationships",
            "effective_relationship_endpoints",
        ] {
            assert!(
                !QUERY_SQL_SERVED_RELATIONS.contains(&refused),
                "{refused} must raise UnavailableOffline at prepare time"
            );
        }
    }

    #[test]
    fn parity_set_matches_section_2_3a_exactly() {
        // Pins both directions: no served tool lacks a §2.3(a) row, and no
        // §2.3(a) row is missing. §2.3 is silent for no ToolKind, so the
        // fail-closed-by-default set is empty — this assertion is what
        // keeps it empty.
        let served = ToolKind::ALL
            .iter()
            .filter(|kind| {
                matches!(
                    scope(**kind),
                    MemberScope::Served { .. }
                        | MemberScope::ServedPartial { .. }
                        | MemberScope::SchemaGated { .. }
                )
            })
            .map(|kind| kind.name())
            .collect::<BTreeSet<_>>();
        let expected = [
            "ping",
            "engine_info",
            "standby_status",
            "bootstrap",
            "quickstart",
            "read_guide",
            "get_structure",
            "get_dashboard",
            "describe_schema",
            "get_record",
            "resolve_many",
            "render_record",
            "manage_links",
            "resolve_facets",
            "suggest_facet_values",
            "query_record",
            "query_sql",
            "search",
            "scan",
            "open_collection",
            "read_attachment",
            "manage_attachments",
            "preview_record_shape",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(served, expected);
    }
}
