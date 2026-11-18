//! Account flag for the `merge_body` home operation (design
//! `docs/design/body-merge-home.md` §2.8).
//!
//! `merge_body` ships dark. Two settings, the same shape as the hosted
//! outbox's `…_OUTBOX` + `…_OUTBOX_ACCOUNTS` pair
//! (`held/hosting/src/hosting/maintenance_outbox/mod.rs`):
//!
//! * `NATIVE_CE_BODY_MERGE=true` is the master switch. Absent, blank or
//!   `false`: off for everyone. Anything else that is not a boolean refuses
//!   startup.
//! * `NATIVE_CE_BODY_MERGE_ACCOUNTS` optionally limits it to a JSON array of
//!   portable account ids, e.g. `["acct_abc"]`. **Absent or JSON `null` = all
//!   accounts** (once the master is on); `[]` = none; a malformed value, or an
//!   id that does not start `acct_`, refuses startup. This is the outbox's
//!   parse rule verbatim.
//!
//! The configuration is read once at process start ([`install`]) and consulted
//! by the handler against the authenticated caller's credential, the portable
//! account id every hosted caller carries (`Caller::credential`).

use std::sync::RwLock;

use crate::{Error, Result};

/// Master switch.
pub const ENABLED_ENV: &str = "NATIVE_CE_BODY_MERGE";
/// Optional JSON allowlist of portable account ids.
pub const ACCOUNTS_ENV: &str = "NATIVE_CE_BODY_MERGE_ACCOUNTS";

/// Parsed flag state. The default is off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BodyMergeConfig {
    pub enabled: bool,
    /// `None` (absent or JSON `null`) permits every account once `enabled`;
    /// `Some([])` permits none.
    pub accounts: Option<Vec<String>>,
}

impl BodyMergeConfig {
    /// Parse from an injected environment, strictly: a bad value refuses
    /// startup rather than silently turning the feature off or on.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let enabled = env(ENABLED_ENV)
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value
                    .trim()
                    .parse::<bool>()
                    .map_err(|_| Error::engine(format!("{ENABLED_ENV} must be true or false")))
            })
            .transpose()?
            .unwrap_or(false);
        let accounts = env(ACCOUNTS_ENV)
            .map(|value| {
                if value.trim() == "null" {
                    return Ok(None);
                }
                let accounts: Vec<String> = serde_json::from_str(&value).map_err(|_| {
                    Error::engine(format!(
                        "{ACCOUNTS_ENV} must be a JSON array of account ids"
                    ))
                })?;
                if accounts
                    .iter()
                    .any(|id| !id.starts_with("acct_") || id.trim() != id || id.len() <= 5)
                {
                    return Err(Error::engine(format!(
                        "{ACCOUNTS_ENV} contains an invalid account id"
                    )));
                }
                Ok(Some(accounts))
            })
            .transpose()?
            .flatten();
        Ok(Self { enabled, accounts })
    }

    /// Whether `account` may use `merge_body` under this configuration.
    pub fn allows(&self, account: &str) -> bool {
        self.enabled
            && self
                .accounts
                .as_ref()
                .is_none_or(|accounts| accounts.iter().any(|allowed| allowed == account))
    }
}

static PROCESS: RwLock<BodyMergeConfig> = RwLock::new(BodyMergeConfig {
    enabled: false,
    accounts: None,
});

#[cfg(test)]
thread_local! {
    static SCOPED: std::cell::RefCell<Option<BodyMergeConfig>> =
        const { std::cell::RefCell::new(None) };
}

/// Install the process-wide configuration. Called once at startup by the
/// hosting service after [`BodyMergeConfig::from_env`] succeeded.
pub fn install(config: BodyMergeConfig) {
    *PROCESS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = config;
}

/// Whether the operation is on for `account` right now.
pub fn account_enabled(account: &str) -> bool {
    #[cfg(test)]
    if let Some(scoped) = SCOPED.with(|scoped| scoped.borrow().as_ref().map(|c| c.allows(account)))
    {
        return scoped;
    }
    PROCESS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .allows(account)
}

/// Overrides the configuration for the **current thread** until dropped, so
/// parallel unit tests can each hold their own flag without touching the
/// process state. Compiled for unit tests only; production code uses
/// [`install`]. The guard is `!Send`: it must be dropped on the thread that
/// created it.
#[cfg(test)]
pub(crate) struct ScopedConfig(Option<BodyMergeConfig>, std::marker::PhantomData<*const ()>);

#[cfg(test)]
pub(crate) fn scoped(config: BodyMergeConfig) -> ScopedConfig {
    ScopedConfig(
        SCOPED.with(|scoped| scoped.replace(Some(config))),
        std::marker::PhantomData,
    )
}

#[cfg(test)]
impl Drop for ScopedConfig {
    fn drop(&mut self) {
        SCOPED.with(|scoped| *scoped.borrow_mut() = self.0.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn absent_settings_leave_it_off_for_everyone() {
        let config = BodyMergeConfig::from_env(&env(&[])).unwrap();
        assert!(!config.enabled);
        assert!(!config.allows("acct_alice"));
        // The allowlist alone does not turn it on.
        let config =
            BodyMergeConfig::from_env(&env(&[(ACCOUNTS_ENV, r#"["acct_alice"]"#)])).unwrap();
        assert!(!config.allows("acct_alice"));
    }

    #[test]
    fn master_on_with_no_allowlist_covers_every_account() {
        for accounts in [None, Some("null")] {
            let config = match accounts {
                None => BodyMergeConfig::from_env(&env(&[(ENABLED_ENV, "true")])),
                Some(_) => BodyMergeConfig::from_env(&env(&[
                    (ENABLED_ENV, "true"),
                    (ACCOUNTS_ENV, "null"),
                ])),
            }
            .unwrap();
            assert!(config.allows("acct_alice") && config.allows("acct_bea"));
        }
    }

    #[test]
    fn an_allowlist_limits_it_and_an_empty_one_refuses_everyone() {
        let config = BodyMergeConfig::from_env(&env(&[
            (ENABLED_ENV, "true"),
            (ACCOUNTS_ENV, r#"["acct_alice"]"#),
        ]))
        .unwrap();
        assert!(config.allows("acct_alice"));
        assert!(!config.allows("acct_bea"));
        let none = BodyMergeConfig::from_env(&env(&[(ENABLED_ENV, "true"), (ACCOUNTS_ENV, "[]")]))
            .unwrap();
        assert!(!none.allows("acct_alice"));
    }

    #[test]
    fn malformed_values_refuse_startup() {
        for pairs in [
            &[(ENABLED_ENV, "yes")][..],
            &[(ENABLED_ENV, "true"), (ACCOUNTS_ENV, "acct_alice")][..],
            &[(ENABLED_ENV, "true"), (ACCOUNTS_ENV, r#"["alice"]"#)][..],
            &[(ENABLED_ENV, "true"), (ACCOUNTS_ENV, r#"["acct_"]"#)][..],
            &[(ENABLED_ENV, "true"), (ACCOUNTS_ENV, r#"[" acct_a"]"#)][..],
            &[(ENABLED_ENV, "true"), (ACCOUNTS_ENV, r#"{"a":1}"#)][..],
        ] {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            let lookup = |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
            };
            assert!(
                BodyMergeConfig::from_env(&lookup).is_err(),
                "{pairs:?} should refuse startup"
            );
        }
    }

    #[test]
    fn a_scoped_override_wins_and_restores() {
        assert!(!account_enabled("acct_alice"));
        {
            let _on = scoped(BodyMergeConfig {
                enabled: true,
                accounts: Some(vec!["acct_alice".into()]),
            });
            assert!(account_enabled("acct_alice"));
            assert!(!account_enabled("acct_bea"));
        }
        assert!(!account_enabled("acct_alice"));
    }
}
