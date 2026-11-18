//! Native publications share the hosted registry's authority, scope key and
//! lease duration. Private source fences stay in this server-only store.
use super::*;
use crate::member_copy_kernel_v2::profile::ProducedMemberFile;

impl MemberCopyRegistry {
    /// Reserve durably before production. Failed/cancelled production may
    /// consume an ordinal; it must never allow a later publication to regress.
    pub async fn allocate_native_ordinal(&self, scope: &str) -> Result<i64> {
        let mut connection = self.pool.acquire().await?;
        let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
        let ordinal = sqlx::query_scalar(
            "INSERT INTO native_member_ordinals VALUES (?, 1) ON CONFLICT(scope_ref) \
             DO UPDATE SET ordinal = ordinal + 1 RETURNING ordinal",
        )
        .bind(scope)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ordinal)
    }

    // Registration retains the producer's exclusive artifact borrow through
    // its async lease writes. The owned SQLite connection is Send, not Sync;
    // publication must not require sharing that connection across threads.
    pub async fn register_native_download(
        &self,
        account: &str,
        scope: &str,
        route: &str,
        fence: &str,
        artifact: &mut ProducedMemberFile,
    ) -> Result<String> {
        let handle = uuid::Uuid::new_v4().to_string();
        let path = self.store_dir.join(format!("native-{handle}.db"));
        artifact
            .persist(&path)
            .map_err(|_| Error::engine("native member publication refused"))?;
        let expires = chrono::Utc::now().timestamp_millis() + self.lease_ttl.as_millis() as i64;
        let result =
            sqlx::query("INSERT INTO native_member_downloads VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&handle)
                .bind(account)
                .bind(scope)
                .bind(route)
                .bind(fence)
                .bind(serde_json::to_string(artifact.manifest())?)
                .bind(path.to_string_lossy().as_ref())
                .bind(expires)
                .execute(&self.pool)
                .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&path);
        }
        result?;
        // Expired artifacts and rotated member scopes cannot be used again.
        let stale = sqlx::query("SELECT handle, file_path FROM native_member_downloads WHERE expires_at_ms < ? OR (account = ? AND route = ? AND scope_ref <> ?)")
            .bind(chrono::Utc::now().timestamp_millis()).bind(account).bind(route).bind(scope)
            .fetch_all(&self.pool).await?;
        for row in stale {
            remove_file_if_present(&row.get::<String, _>("file_path"))?;
            sqlx::query("DELETE FROM native_member_downloads WHERE handle = ?")
                .bind(row.get::<String, _>("handle"))
                .execute(&self.pool)
                .await?;
        }
        Ok(handle)
    }

    /// Exact requester/route/scope lookup precedes all artifact access. An
    /// unknown or foreign handle reveals neither identity nor file metadata.
    pub async fn native_download(
        &self,
        handle: &str,
        account: &str,
        scope: &str,
        route: &str,
    ) -> Result<Option<(ReplicaGenerationManifest, String, PathBuf)>> {
        let row = sqlx::query("SELECT manifest, fence, file_path FROM native_member_downloads WHERE handle = ? AND account = ? AND scope_ref = ? AND route = ? AND expires_at_ms >= ?")
            .bind(handle).bind(account).bind(scope).bind(route)
            .bind(chrono::Utc::now().timestamp_millis()).fetch_optional(&self.pool).await?;
        row.map(|r| {
            Ok((
                serde_json::from_str(&r.get::<String, _>("manifest"))?,
                r.get("fence"),
                PathBuf::from(r.get::<String, _>("file_path")),
            ))
        })
        .transpose()
    }
}
