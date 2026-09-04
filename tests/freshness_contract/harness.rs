use native_ce::freshness::*;
use native_ce::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticInventory {
    pub units: i64,
    pub occurrences: i64,
    pub receipts: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvidence {
    pub outcome: DependencyAuditOutcome,
    pub has_declared_dependency: bool,
    pub has_observed_dependency: bool,
}

/// Test-only semantic contract implemented by a physical backend adapter.
///
/// Shared scenarios receive an opaque database and exact domain values. The
/// adapter owns persistence, authorization setup, replay, and failure probes.
pub trait FreshnessHarness: Sync {
    type Database: Clone + Send + Sync;

    async fn fresh_database(&self) -> Result<Self::Database>;
    async fn close(&self, database: &Self::Database);

    async fn create_artefact(
        &self,
        database: &Self::Database,
        id: &str,
        name: &str,
        body: &str,
    ) -> Result<RevisionRef>;

    async fn artefact_body(&self, database: &Self::Database, id: &str) -> Result<String>;

    async fn artefact_name(&self, database: &Self::Database, id: &str) -> Result<String>;

    async fn rename_artefact(&self, database: &Self::Database, id: &str, name: &str) -> Result<()>;

    async fn update_artefact(
        &self,
        database: &Self::Database,
        id: &str,
        expected: &RevisionRef,
        body: &str,
    ) -> Result<RevisionRef>;

    async fn promote_idea(
        &self,
        database: &Self::Database,
        input: PromoteIdeaInput,
    ) -> Result<PromoteIdeaResult>;

    async fn bind_occurrence(
        &self,
        database: &Self::Database,
        input: BindOccurrenceInput,
    ) -> Result<BindOccurrenceResult>;

    async fn revise_unit(
        &self,
        database: &Self::Database,
        input: ReviseUnitInput,
    ) -> Result<ReviseUnitResult>;

    async fn read_unit(&self, database: &Self::Database, unit_id: &UnitId) -> Result<UnitView>;

    async fn read_unit_revision(
        &self,
        database: &Self::Database,
        reference: &RevisionRef,
    ) -> Result<UnitRevisionView>;

    async fn list_occurrences(
        &self,
        database: &Self::Database,
        unit_id: &UnitId,
    ) -> Result<Vec<OccurrenceView>>;

    async fn resolve_occurrence(
        &self,
        database: &Self::Database,
        occurrence_id: &OccurrenceId,
    ) -> Result<OccurrenceResolution>;

    async fn is_subordinate_in_ordinary_listing(
        &self,
        database: &Self::Database,
        unit_id: &UnitId,
    ) -> Result<bool>;

    async fn assemble_context(
        &self,
        database: &Self::Database,
        request: ContextRequest,
        consumer_record_id: Option<&str>,
        source_record_ids: Vec<String>,
    ) -> Result<ContextAssembly>;

    async fn commit_output(
        &self,
        database: &Self::Database,
        input: CommitDurableOutputInput,
    ) -> Result<CommitDurableOutputResult>;

    async fn impact_candidates(
        &self,
        database: &Self::Database,
        consumer_record_id: &str,
    ) -> Result<ImpactCandidateSet>;

    async fn explain(
        &self,
        database: &Self::Database,
        receipt_id: ReceiptId,
    ) -> Result<FreshnessExplanation>;

    async fn reconcile(
        &self,
        database: &Self::Database,
        input: ReconcileDependencyInput,
    ) -> Result<()>;

    async fn audit(
        &self,
        database: &Self::Database,
        input: AuditDependencyInput,
    ) -> Result<AuditEvidence>;

    async fn semantic_inventory(&self, database: &Self::Database) -> Result<SemanticInventory>;

    async fn receipt_dependency_budget(
        &self,
        database: &Self::Database,
        receipt_id: &ReceiptId,
    ) -> Result<(u32, u32)>;

    async fn assert_replay_equivalent(&self, database: &Self::Database) -> Result<()>;
}
