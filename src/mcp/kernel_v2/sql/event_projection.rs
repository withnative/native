//! Cached unbounded staging. Every authority decision is made in this read
//! snapshot; only caller-independent event facts survive between queries.
use super::*;
use kernel::sql_event_projection as cache;

pub(super) async fn install(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    root: bool,
    expected_generation: Option<i64>,
) -> Result<bool> {
    #[cfg(test)]
    if event_equivalence::baseline_enabled() || event_equivalence::slice_a_enabled() {
        return Ok(false);
    }
    let Some(frontier) = cache::frontier_on(conn, expected_generation).await? else {
        return Ok(false);
    };
    // A malformed/non-string subject array must retain the old path's
    // visibility-dependent decoding and errors. Hidden/unanchored rows never
    // disable otherwise valid cached staging.
    let invalid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_sql_event_projection p JOIN temp._v2_visible v ON v.id=p.record_id JOIN temp._v2_visible anchor ON anchor.id=p.outer_anchor WHERE p.seq<=?1 AND p.origin='legacy' AND p.selector='invalid-subjects' AND p.source_stream='content_events' AND NOT p.hidden AND ((SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?2)=p.owner OR NOT p.restricted OR ?3))")
        .bind(frontier).bind(actor).bind(kernel::kernel_effective_capability_on(conn,actor,crate::events::KERNEL_ROOT_ID).await?.allows(Capability::Manage)).fetch_one(&mut *conn).await?;
    if invalid {
        tracing::warn!(
            diagnostic = "event_cache_subject_fallback",
            "using original staging for admitted non-string subjects"
        );
        return Ok(false);
    }
    #[cfg(test)]
    let subjects_phase = event_profile::Phase::new("projection_subject_admission");
    let binding: String =
        sqlx::query_scalar("SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_one(&mut *conn)
            .await?;
    let admin = kernel::kernel_effective_capability_on(conn, actor, crate::events::KERNEL_ROOT_ID)
        .await?
        .allows(Capability::Manage);
    sqlx::query("CREATE TEMP TABLE _v2_projection_sets(set_id INTEGER PRIMARY KEY,admitted INTEGER NOT NULL DEFAULT 0); CREATE TEMP TABLE _v2_projection_visible_subjects(id TEXT PRIMARY KEY)").execute(&mut *conn).await?;
    sqlx::query("WITH headers AS MATERIALIZED (SELECT DISTINCT p.subject_set,p.record_id,p.outer_anchor,p.restricted,p.owner FROM main.kernel_sql_event_projection p INDEXED BY idx_kernel_sql_event_admission WHERE p.seq<=?1 AND p.origin='legacy' AND p.source_stream='content_events' AND p.hidden=0) INSERT INTO temp._v2_projection_sets(set_id) SELECT DISTINCT h.subject_set FROM headers h CROSS JOIN temp._v2_visible v ON v.id=h.record_id CROSS JOIN temp._v2_visible anchor ON anchor.id=h.outer_anchor WHERE (?2 OR NOT h.restricted OR h.owner=?3)")
        .bind(frontier).bind(admin).bind(&binding).execute(&mut *conn).await?;
    let subjects: Vec<String> = sqlx::query_scalar("SELECT DISTINCT s.subject_id FROM temp._v2_projection_sets a CROSS JOIN main.kernel_sql_event_subject_sets s ON s.set_id=a.set_id").fetch_all(&mut *conn).await?;
    // Preserve Slice A's preseed for ordinary visible records; comments and
    // mapped homes still pass through the W5 helper in this exact snapshot.
    let mut visibility = std::collections::BTreeMap::new();
    let ordinary = format!(
        "SELECT v.id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id WHERE NOT {}",
        kernel::comments_v2::sql_is_comment("r")
    );
    for id in sqlx::query_scalar::<_, String>(&ordinary)
        .fetch_all(&mut *conn)
        .await?
    {
        visibility.insert(id, true);
    }
    let mut visible = Vec::new();
    for subject in subjects {
        if kernel::legacy_history_visible(conn, actor, &subject, &mut visibility).await? {
            visible.push(subject);
        }
    }
    for chunk in visible.chunks(500) {
        let mut q = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO temp._v2_projection_visible_subjects(id) ",
        );
        q.push_values(chunk, |mut q, id| {
            q.push_bind(id);
        });
        q.build().execute(&mut *conn).await?;
    }
    sqlx::query("UPDATE temp._v2_projection_sets SET admitted=NOT EXISTS(SELECT 1 FROM main.kernel_sql_event_subject_sets s WHERE s.set_id=_v2_projection_sets.set_id AND NOT EXISTS(SELECT 1 FROM temp._v2_projection_visible_subjects v WHERE v.id=s.subject_id))").execute(&mut *conn).await?;
    #[cfg(test)]
    drop(subjects_phase);
    #[cfg(test)]
    let disclosure_phase = event_profile::Phase::new("projection_actor_disclosure");
    // Resolve native actors once, preserving root/self/visible Person rules.
    sqlx::query("CREATE TEMP TABLE _v2_projection_actors(actor TEXT PRIMARY KEY,disclosed INTEGER NOT NULL) WITHOUT ROWID; WITH actors AS MATERIALIZED (SELECT DISTINCT actor FROM main.kernel_sql_event_projection INDEXED BY idx_kernel_sql_event_actors WHERE origin='native' AND actor IS NOT NULL AND seq<=?3) INSERT INTO temp._v2_projection_actors(actor,disclosed) SELECT actor,?1 OR actor=?2 OR EXISTS(SELECT 1 FROM main.kernel_message_people mp JOIN temp._v2_visible v ON v.id=mp.person_id WHERE mp.principal_id=actors.actor) FROM actors")
        .bind(root).bind(actor).bind(frontier).execute(&mut *conn).await?;
    for principal in kernel::v1_state::disclosed_accounts_on(conn, actor).await? {
        sqlx::query("INSERT OR IGNORE INTO temp._v2_disclosed_legacy_actors(actor) SELECT 'v1:'||auth_binding FROM main.kernel_principals WHERE principal_id=?").bind(principal).execute(&mut *conn).await?;
    }
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _v2_disclosed_legacy_principals(actor TEXT PRIMARY KEY,principal_id TEXT) WITHOUT ROWID; DELETE FROM temp._v2_disclosed_legacy_principals; INSERT INTO temp._v2_disclosed_legacy_principals(actor,principal_id) SELECT d.actor,p.principal_id FROM temp._v2_disclosed_legacy_actors d LEFT JOIN main.kernel_principals p ON p.auth_binding=substr(d.actor,4) AND d.actor LIKE 'v1:%' AND p.kind='account'").execute(&mut *conn).await?;
    #[cfg(test)]
    drop(disclosure_phase);
    #[cfg(test)]
    let copy_phase = event_profile::Phase::new("projection_copy");
    // Scan once in source sequence order. Prefixing high native positions
    // before low imported positions makes the TEMP integer PK copy dominate.
    sqlx::query(r#"INSERT INTO temp._v2_event_rows(local_seq,id,record_id,type,actor,run_key,parent_key,channel_kind,created_at,created_at_ms)
      SELECT p.seq,p.id,p.record_id,p.type,
       CASE WHEN p.origin='legacy' THEN CASE WHEN d.actor IS NOT NULL THEN coalesce(d.principal_id,p.actor) END ELSE CASE WHEN a.disclosed THEN p.actor END END,
       CASE WHEN p.origin='legacy' THEN CASE WHEN d.actor IS NOT NULL AND (NOT p.claim_sensitive OR p.actor='v1:'||?4) THEN p.run_key END ELSE CASE WHEN ?1 THEN p.run_key END END,
       CASE WHEN p.origin='legacy' THEN CASE WHEN d.actor IS NOT NULL AND (NOT p.claim_sensitive OR p.actor='v1:'||?4) THEN p.parent_key END ELSE CASE WHEN ?1 THEN p.parent_key END END,
       CASE WHEN p.origin='legacy' THEN CASE WHEN d.actor IS NOT NULL THEN 'unknown' END ELSE CASE WHEN ?1 OR p.actor=?2 THEN 'unknown' END END,
       p.created_at,p.created_at_ms
      FROM main.kernel_sql_event_projection p NOT INDEXED
       LEFT JOIN temp._v2_visible v ON v.id=p.record_id
       LEFT JOIN temp._v2_projection_actors a ON p.origin='native' AND a.actor=p.actor
       LEFT JOIN temp._v2_disclosed_legacy_principals d ON p.origin='legacy' AND d.actor=p.actor
       LEFT JOIN temp._v2_projection_sets admitted ON p.origin='legacy' AND admitted.set_id=p.subject_set
      WHERE p.seq<=?3 AND (
       (p.origin='legacy' AND v.id IS NOT NULL AND EXISTS(SELECT 1 FROM temp._v2_visible anchor WHERE anchor.id=p.outer_anchor) AND p.source_stream='content_events' AND NOT p.hidden AND (?5 OR NOT p.restricted OR p.owner=?4) AND admitted.admitted)
       OR (p.origin='native' AND (
        (p.selector='record' AND v.id IS NOT NULL)
        OR (p.selector='reaction' AND v.id IS NOT NULL AND EXISTS(SELECT 1 FROM main.kernel_messages m WHERE m.message_id=p.record_id))
        OR (p.selector IN ('link4','link1','generic') AND EXISTS(SELECT 1 FROM temp._v2_visible s WHERE s.id=p.source_id) AND EXISTS(SELECT 1 FROM temp._v2_visible t WHERE t.id=p.target_id))
        OR (p.selector='provider' AND v.id IS NOT NULL
            AND EXISTS(SELECT 1 FROM main.kernel_sql_event_subject_sets s WHERE s.set_id=p.subject_set)
            AND NOT EXISTS(SELECT 1 FROM main.kernel_sql_event_subject_sets s WHERE s.set_id=p.subject_set AND NOT EXISTS(SELECT 1 FROM temp._v2_visible t WHERE t.id=s.subject_id))))))
      ORDER BY p.seq"#)
        .bind(root).bind(actor).bind(frontier).bind(&binding).bind(admin).execute(&mut *conn).await?;
    #[cfg(test)]
    drop(copy_phase);
    let oracle_only: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_sql_event_projection WHERE origin='oracle' AND selector='oracle-only' AND seq<=?)").bind(frontier).fetch_one(&mut *conn).await?;
    if oracle_only {
        sqlx::query("CREATE TEMP TABLE _v2_oracle_events(seq INTEGER PRIMARY KEY); INSERT INTO temp._v2_oracle_events(seq) SELECT seq FROM main.kernel_sql_event_projection WHERE origin='oracle' AND selector='oracle-only' AND seq<=?").bind(frontier).execute(&mut *conn).await?;
    }
    let tail: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq>?)")
            .bind(frontier)
            .fetch_one(&mut *conn)
            .await?;
    if oracle_only {
        #[cfg(test)]
        let _phase = event_profile::Phase::new("projection_oracle");
        select_event_ids_after(conn, false, frontier, true).await?;
        install_events_after(conn, actor, root, false, frontier, true).await?;
    }
    if tail {
        #[cfg(test)]
        let _phase = event_profile::Phase::new("projection_tail");
        // Each installation consumes only its own candidates. The tail keeps
        // a pure seq range and never carries an OR against sparse old rows.
        sqlx::query("DELETE FROM temp._v2_event_ids")
            .execute(&mut *conn)
            .await?;
        select_event_ids_after(conn, false, frontier, false).await?;
        install_events_after(conn, actor, root, false, frontier, false).await?;
    }
    Ok(true)
}
