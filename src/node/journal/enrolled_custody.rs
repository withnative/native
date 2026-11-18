//! The enrolled sequence counter lives alongside the journal and survives
//! failed writes and restarts. A number is reserved before its entry is
//! written. An allocated number without an entry can never be sent.

use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    schema: String,
    binding: CustodyBinding,
    high_water: u64,
}

pub(super) struct Sequence {
    path: PathBuf,
    saved: StdMutex<Saved>,
    pub(super) qualification: tokio::sync::OnceCell<()>,
}

impl Sequence {
    pub(super) fn open(socket_directory: &Path, binding: &CustodyBinding) -> Result<Self> {
        const SCHEMA: &str = "native.installed-journal-sequence.v1";
        let path = socket_directory.join("installed-journal-sequence.json");
        let saved = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                check_owned(&metadata, 0o600)?;
                let bytes = read_guarded_credential(&path, "installed journal sequence")?;
                let saved: Saved = serde_json::from_slice(&bytes)?;
                if saved.schema != SCHEMA || &saved.binding != binding {
                    return Err(Error::engine("installed journal sequence binding changed"));
                }
                saved
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Saved {
                schema: SCHEMA.into(),
                binding: binding.clone(),
                high_water: 0,
            },
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            saved: StdMutex::new(saved),
            qualification: tokio::sync::OnceCell::new(),
        })
    }

    pub(super) fn high_water(&self) -> u64 {
        self.saved.lock().expect("installed sequence").high_water
    }

    pub(super) fn reserve(&self, sequence: u64) -> Result<()> {
        if sequence == 0 {
            return Err(Error::engine("installed journal sequence is invalid"));
        }
        let mut saved = self.saved.lock().expect("installed sequence");
        if sequence <= saved.high_water {
            return Ok(());
        }
        let next = Saved {
            schema: saved.schema.clone(),
            binding: saved.binding.clone(),
            high_water: sequence,
        };
        super::super::oauth::atomic_private_write(&self.path, &serde_json::to_vec(&next)?)?;
        *saved = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_settlement_custody_sequence_survives_a_failed_entry_and_restart() {
        let temp = tempfile::tempdir().unwrap();
        let binding = CustodyBinding {
            account_id: "acct_example".into(),
            database_id: "database".into(),
            origin_database_id: "origin".into(),
            history_lineage: "history".into(),
            resource_origin: "https://local.test".into(),
            install_id: Some("b".repeat(64)),
        };
        let sequence = Sequence::open(temp.path(), &binding).unwrap();
        assert_eq!(sequence.high_water(), 0);
        sequence.reserve(7).unwrap();
        drop(sequence);

        let reopened = Sequence::open(temp.path(), &binding).unwrap();
        assert_eq!(reopened.high_water(), 7);
        reopened.reserve(3).unwrap();
        assert_eq!(reopened.high_water(), 7);

        let foreign = CustodyBinding {
            install_id: Some("c".repeat(64)),
            ..binding
        };
        assert!(Sequence::open(temp.path(), &foreign).is_err());
    }
}
