use super::*;

pub(super) async fn project_persona_registered(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let p: crate::events::PersonaRegisteredPayload = parse_payload(event)?;
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND type='Entity' AND kind='persona' AND owner_id=?)")
        .bind(&event.record_id).bind(&p.owner_person_id).fetch_one(&mut *conn).await?;
    if !valid {
        return Err(Error::engine(
            "persona registration requires an owned Entity/persona profile",
        ));
    }
    assert_portable_person(conn, &p.owner_person_id, &event.event_type).await?;
    declared_principal(&p.owner_principal, &event.event_type)?;
    sqlx::query("INSERT INTO personas(persona_id,owner_person_id,owner_principal,state,registered_event_seq,updated_at) VALUES (?,?,?,'active',?,?)")
        .bind(&event.record_id).bind(&p.owner_person_id).bind(&p.owner_principal).bind(event.local_seq).bind(&event.created_at).execute(&mut *conn).await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_persona_retired(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let p: crate::events::PersonaRetiredPayload = parse_payload(event)?;
    if p.reason.trim().is_empty() {
        return Err(Error::engine("persona retirement requires a reason"));
    }
    let result=sqlx::query("UPDATE personas SET state='retired',retired_event_seq=?,updated_at=? WHERE persona_id=? AND state='active'")
        .bind(event.local_seq).bind(&event.created_at).bind(&event.record_id).execute(&mut *conn).await?;
    if result.rows_affected() != 1 {
        return Err(Error::engine("persona is not active"));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_message_speaker(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: crate::events::MessageSpeakerDeclaredPayload = parse_payload(event)?;
    // The fold validates the frozen identity without consulting account bindings,
    // which are outside content replay. Current claims cannot rewrite old sends.
    let valid: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records m
        JOIN message_audience_state a ON a.message_id=m.id AND a.status='pending_local'
        JOIN personas p ON p.persona_id=? AND p.state='active'
        WHERE m.id=? AND m.type='Message' AND m.deleted_at IS NULL AND m.owner_id=p.owner_person_id AND p.owner_principal=?)")
        .bind(&p.persona_id).bind(&event.record_id).bind(&p.owner_principal).fetch_one(&mut *conn).await?;
    if !valid || p.kind != "persona" || p.assurance != "client_asserted" {
        return Err(Error::engine(
            "message speaker event is not a coherent creation-time persona claim",
        ));
    }
    sqlx::query("INSERT INTO message_speakers(message_id,speaker_kind,persona_id,owner_principal,assurance,event_seq) VALUES (?,'persona',?,?,?,?)")
        .bind(&event.record_id).bind(&p.persona_id).bind(&p.owner_principal).bind(&p.assurance).bind(event.local_seq).execute(&mut *conn).await?;
    touch(conn, &event.record_id, &event.created_at).await
}
