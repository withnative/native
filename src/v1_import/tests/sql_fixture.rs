//! Shared invented visibility boundaries for SQL staging equivalence.
use super::*;

pub(super) async fn prepare_visibility_fixture(f: &Fixture) {
    catalogue_fixture(f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute(r#"
      INSERT INTO schema_config VALUES('scoped','user',NULL,'{"shapes":{"WorkItem:task":{"facets":{"lifecycle":{"axis":{"key":"scoped_status","label":"Scoped status"},"vocab_ref":"custom","required":true}}}}}','folder',NULL,'2026-01-02T00:00:00Z');
      UPDATE records SET lifecycle='preserved' WHERE id='task';
      UPDATE records SET type='WorkItem',kind='task',home_id='folder',lifecycle='preserved' WHERE id='private';
      INSERT INTO bindings VALUES('person-a','native-principal','principal-a',1),('person-b','native-principal','principal-b',1);
      INSERT INTO records(id,type,kind,name,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id)
      VALUES('person-b','Entity','person','Synthetic member','folder','person-b','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root');
      CREATE TABLE message_audience_state(message_id TEXT,status TEXT);
      CREATE TABLE message_audiences(message_id TEXT,principal_id TEXT,source TEXT,event_seq INTEGER);
      CREATE TABLE message_origin_state(message_id TEXT,status TEXT,origin_type TEXT,collection_id TEXT,direct_set_digest TEXT,participant_count INTEGER,declaration_event_seq INTEGER,updated_at TEXT);
      CREATE TABLE message_origin_principals(message_id TEXT,principal_id TEXT);
    "#).await.unwrap();
    for (id, home, policy) in [
        ("direct-public", "folder", "native:root"),
        ("direct-private", "private", "private"),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES(?,'Message','text','Synthetic direct','Synthetic body',?,'person-a','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,?)")
            .bind(id).bind(home).bind(policy).execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO message_audience_state VALUES(?,'declared'); INSERT INTO message_audiences VALUES(?,'principal-a','sender',1); INSERT INTO message_audiences VALUES(?,'principal-b','addressed_to',1); INSERT INTO message_origin_state VALUES(?,'declared','direct',NULL,NULL,2,1,'2026-01-01T00:00:00Z'); INSERT INTO message_origin_principals VALUES(?,'principal-a'),(?,'principal-b')")
            .bind(id).bind(id).bind(id).bind(id).bind(id).bind(id).execute(&mut source).await.unwrap();
    }
    for (id, bearer) in [
        ("comment-public", "direct-public"),
        ("comment-private", "direct-private"),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES(?,'Annotation','comment','Synthetic comment','Synthetic body','folder','person-a','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root')")
            .bind(id).execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO links VALUES(?,?,?,'part_of',NULL,'2026-01-01T00:00:00Z')")
            .bind(format!("bearer:{id}"))
            .bind(id)
            .bind(bearer)
            .execute(&mut source)
            .await
            .unwrap();
    }
    source.close().await.unwrap();
    add_derived_attachment(f, "attachment-public", "direct-public", "person-a").await;
    add_derived_attachment(f, "attachment-private", "direct-private", "person-a").await;
}
