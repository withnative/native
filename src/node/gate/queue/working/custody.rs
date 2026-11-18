use super::*;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyPage {
    schema: String,
    install_id: String,
    account_id: String,
    database_id: String,
    origin_database_id: String,
    high_water: u64,
    observed: Vec<Observation>,
    next_after: Option<u64>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    sequence: u64,
    original_binding_sha256: String,
}

impl CustodyPage {
    fn verify(
        &self,
        scope: &crate::node::journal::CustodyBinding,
        after: u64,
        high_water: Option<u64>,
        local_high_water: u64,
        held: &BTreeMap<u64, String>,
    ) -> Result<()> {
        let refused = || Error::engine("enrolled journal continuity is unverified");
        if self.schema != "native.node-custody.page.v1"
            || Some(self.install_id.as_str()) != scope.install_id.as_deref()
            || self.account_id != scope.account_id
            || self.database_id != scope.database_id
            || self.origin_database_id != scope.origin_database_id
            || high_water.is_some_and(|high_water| self.high_water != high_water)
            || self.high_water > local_high_water
        {
            return Err(refused());
        }
        let mut last = after;
        for entry in &self.observed {
            if entry.sequence <= last
                || entry.sequence > self.high_water
                || held.get(&entry.sequence) != Some(&entry.original_binding_sha256)
            {
                return Err(refused());
            }
            last = entry.sequence;
        }
        match self.next_after {
            None if last == self.high_water => Ok(()),
            Some(next) if next == last && next > after && next < self.high_water => Ok(()),
            _ => Err(refused()),
        }
    }
}

impl WriteGate {
    /// Qualify the retained sequence domain before any new ACK or send in
    /// this process. Failed or incomplete checks leave the gate closed.
    pub(in crate::node) async fn verify_enrolled_custody(
        &self,
        upstream: &Upstream,
        expected_credential: [u8; 32],
    ) -> Result<()> {
        let Some(key) = &upstream.install_key else {
            return Ok(());
        };
        let install = key.id();
        if self
            .custody_scope
            .as_ref()
            .and_then(|scope| scope.install_id.as_deref())
            != Some(install.as_str())
        {
            return Err(Error::engine("enrolled journal installation changed"));
        }
        self.journal
            .enrolled_qualification()
            .ok_or_else(|| Error::engine("enrolled journal scope is unavailable"))?
            .get_or_try_init(|| async {
                tokio::time::timeout(
                    self.config.attempt_timeout,
                    self.check_custody_pages(upstream, &install, expected_credential),
                )
                .await
                .map_err(|_| Error::engine("enrolled journal continuity check expired"))?
            })
            .await?;
        Ok(())
    }

    async fn check_custody_pages(
        &self,
        upstream: &Upstream,
        install: &str,
        expected_credential: [u8; 32],
    ) -> Result<()> {
        use sha2::Digest;
        let token = read_guarded_credential(&upstream.config.credential_file, "node")?;
        let digest: [u8; 32] = sha2::Sha256::digest(&*token).into();
        if digest != expected_credential {
            return Err(Error::auth("enrolled journal credential changed"));
        }
        let scope = self
            .custody_scope
            .as_ref()
            .ok_or_else(|| Error::engine("enrolled journal scope is unavailable"))?;
        let (local_high_water, held, mut confirmed) =
            self.journal.enrolled_original_sequences(install)?;
        let mut after = 0;
        let mut high_water = None;
        loop {
            let response = enrolled_request(
                upstream,
                std::str::from_utf8(&token).expect("guarded UTF-8"),
                "custody",
                &json!({"after_sequence": after}),
                self.config.attempt_timeout,
            )
            .await?;
            if !response.status().is_success() {
                return Err(Error::engine("enrolled journal high-water is unavailable"));
            }
            let page: CustodyPage = serde_json::from_value(read_enrolled_answer(response).await?)?;
            page.verify(scope, after, high_water, local_high_water, &held)?;
            for observed in &page.observed {
                confirmed.remove(&observed.sequence);
            }
            high_water = Some(page.high_water);
            match page.next_after {
                Some(next) => after = next,
                None => break,
            }
        }
        if !confirmed.is_empty() {
            return Err(Error::engine(
                "hosted custody ledger lost a confirmed sequence",
            ));
        }
        if read_guarded_credential(&upstream.config.credential_file, "node")?.as_slice()
            != token.as_slice()
        {
            return Err(Error::auth("enrolled journal credential changed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(high_water: u64, observed: &[(u64, &str)], next: Option<u64>) -> CustodyPage {
        CustodyPage {
            schema: "native.node-custody.page.v1".into(),
            install_id: "install-a".into(),
            account_id: "account".into(),
            database_id: "database".into(),
            origin_database_id: "origin".into(),
            high_water,
            observed: observed
                .iter()
                .map(|(sequence, binding)| Observation {
                    sequence: *sequence,
                    original_binding_sha256: (*binding).into(),
                })
                .collect(),
            next_after: next,
        }
    }

    #[test]
    fn original_settlement_hosted_high_water_detects_rollback_and_missing_custody() {
        let scope = crate::node::journal::CustodyBinding {
            account_id: "account".into(),
            database_id: "database".into(),
            origin_database_id: "origin".into(),
            resource_origin: "https://host.example".into(),
            history_lineage: "lineage".into(),
            install_id: Some("install-a".into()),
        };
        let held = BTreeMap::from([
            (2, "first".into()),
            (4, "second".into()),
            (9, "third".into()),
        ]);
        assert!(page(9, &[(2, "first"), (4, "second")], Some(4))
            .verify(&scope, 0, None, 9, &held)
            .is_ok());
        assert!(page(9, &[(9, "third")], None)
            .verify(&scope, 4, Some(9), 9, &held)
            .is_ok());
        for invalid in [
            page(10, &[(10, "later")], None),
            page(9, &[(3, "missing"), (9, "third")], None),
            page(9, &[(4, "changed"), (9, "third")], None),
            page(9, &[(2, "first")], Some(3)),
        ] {
            assert!(invalid.verify(&scope, 0, None, 9, &held).is_err());
        }
        assert!(page(4, &[(4, "second")], None)
            .verify(&scope, 2, Some(9), 9, &held)
            .is_err());
        let mut wrong_origin = page(9, &[(9, "third")], None);
        wrong_origin.origin_database_id = "a different origin".into();
        assert!(wrong_origin.verify(&scope, 0, None, 9, &held).is_err());
        let mut wrong_install = page(9, &[(9, "third")], None);
        wrong_install.install_id = "install-b".into();
        assert!(wrong_install.verify(&scope, 0, None, 9, &held).is_err());
    }
}
