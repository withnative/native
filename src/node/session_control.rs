//! Daemon Save authority and status labels. Ported from Desktop's shipped
//! saved-sessions.ts contract, not from the S1 presence-only subscription
//! filter. Parsing never authorizes a write: account/database must match the
//! node binding, then the writer independently checks the daemon server id.

use crate::error::{Error, Result};

use super::session_persist::Binding;

pub(super) fn agent_archived(snapshot: &serde_json::Value) -> bool {
    snapshot
        .get("archivedAt")
        .is_some_and(serde_json::Value::is_string)
        || snapshot.get("status").and_then(serde_json::Value::as_str) == Some("closed")
}

const STATUS_INTERVAL_MS: u64 = 30_000;
const MAX_STATUS_NUMBER: u64 = 9_999_999_999;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveRequest {
    Save {
        account: String,
        database: String,
        request: String,
    },
    Stop {
        request: String,
    },
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b':' | b'_' | b'-'))
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

impl SaveRequest {
    /// Exact field order/version/arity, ASCII tokens and lowercase canonical
    /// UUIDs match Desktop. Duplicate, unknown and reordered fields refuse.
    pub fn parse(raw: &str) -> Option<Self> {
        let fields: Vec<_> = raw.split(';').collect();
        match fields.as_slice() {
            ["off", req] => {
                let req = req.strip_prefix("req=")?;
                canonical_uuid(req).then(|| Self::Stop {
                    request: req.to_owned(),
                })
            }
            ["v1", acct, db, req] => {
                let account = acct.strip_prefix("acct=")?;
                let database = db.strip_prefix("db=")?;
                let request = req.strip_prefix("req=")?;
                (token(account) && token(database) && canonical_uuid(request)).then(|| Self::Save {
                    account: account.to_owned(),
                    database: database.to_owned(),
                    request: request.to_owned(),
                })
            }
            _ => None,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::Save { request, .. } | Self::Stop { request } => request,
        }
    }

    /// Stop is deliberately not a positive Save authorization. A Stop can
    /// only update a previously owned tracked session through its own lease.
    pub fn authorizes_save(&self, binding: &Binding) -> bool {
        matches!(self, Self::Save {account, database, ..}
            if account == &binding.account_id && database == &binding.db_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Accepted,
    Ok,
    Paused,
    Refused,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveStatus {
    Accepted {
        request: String,
    },
    Persisted {
        confirmed_pos: u64,
        folder: String,
        pending: u64,
    },
    Paused {
        reason: String,
    },
    RefusedBinding,
    Error {
        code: String,
    },
}

impl SaveStatus {
    pub fn kind(&self) -> StatusKind {
        match self {
            Self::Accepted { .. } => StatusKind::Accepted,
            Self::Persisted { .. } => StatusKind::Ok,
            Self::Paused { .. } => StatusKind::Paused,
            Self::RefusedBinding => StatusKind::Refused,
            Self::Error { .. } => StatusKind::Error,
        }
    }

    pub fn label(&self) -> Result<String> {
        match self {
            Self::Accepted { request } if canonical_uuid(request) => {
                Ok(format!("accepted:{request}"))
            }
            Self::Persisted {
                confirmed_pos,
                folder,
                pending,
            } if token(folder)
                && *confirmed_pos <= MAX_STATUS_NUMBER
                && *pending <= MAX_STATUS_NUMBER =>
            {
                Ok(format!(
                    "ok:{confirmed_pos};folder={folder};pending={pending}"
                ))
            }
            Self::Paused { reason } if token(reason) => Ok(format!("paused:{reason}")),
            Self::RefusedBinding => Ok("refused:binding".into()),
            Self::Error { code } if token(code) => Ok(format!("error:{code}")),
            _ => Err(Error::engine(
                "saved-session status exceeds daemon label contract",
            )),
        }
    }
}

/// Connection-scoped status publisher. A new request must publish its own
/// accepted correlation before any `ok` derived from an older request can be
/// shown. Failed sends do not advance the gate. Reconnect starts a fresh gate.
#[derive(Default)]
pub struct StatusPublisher {
    request: Option<String>,
    accepted_sent: bool,
    last_sent: Option<(StatusKind, u64)>,
}

impl StatusPublisher {
    /// Revoke acknowledgement without resetting the connection's send rate.
    /// A restored identical request still needs a fresh successful acceptance.
    pub fn revoke(&mut self) {
        self.request = None;
        self.accepted_sent = false;
    }

    pub fn request(&mut self, request: &SaveRequest, binding: &Binding) -> Result<()> {
        if !request.authorizes_save(binding) {
            self.request = None;
            self.accepted_sent = false;
            return Err(Error::engine(
                "cannot accept an unbound Save or Stop request",
            ));
        }
        if self.request.as_deref() != Some(request.request_id()) {
            self.request = Some(request.request_id().to_owned());
            self.accepted_sent = false;
        }
        Ok(())
    }

    /// Only a Save already admitted against the node binding may call
    /// `request`. Binding refusal and terminal errors do not imply accepted.
    pub fn next(&self, desired: &SaveStatus, tick_ms: u64) -> Result<Option<SaveStatus>> {
        let status = if !self.accepted_sent && matches!(desired, SaveStatus::Persisted { .. }) {
            match &self.request {
                Some(request) => SaveStatus::Accepted {
                    request: request.clone(),
                },
                None => return Err(Error::engine("no admitted Save request for status")),
            }
        } else {
            desired.clone()
        };
        if let SaveStatus::Accepted { request } = &status {
            if self.request.as_deref() != Some(request.as_str()) {
                return Err(Error::engine(
                    "status acknowledgement names another Save request",
                ));
            }
        }
        status.label()?;
        let due = self.last_sent.is_none_or(|(kind, last)| {
            kind != status.kind() || tick_ms.saturating_sub(last) >= STATUS_INTERVAL_MS
        });
        Ok(due.then_some(status))
    }

    /// Call only after the daemon client's typed status send succeeds.
    pub fn sent(&mut self, status: &SaveStatus, tick_ms: u64) -> Result<()> {
        status.label()?;
        if matches!(status, SaveStatus::Persisted { .. })
            && (!self.accepted_sent || self.request.is_none())
        {
            return Err(Error::engine(
                "cannot settle ok before current Save acceptance",
            ));
        }
        if let SaveStatus::Accepted { request } = status {
            if self.request.as_deref() != Some(request.as_str()) {
                return Err(Error::engine(
                    "status acknowledgement names another Save request",
                ));
            }
            self.accepted_sent = true;
        }
        self.last_sent = Some((status.kind(), tick_ms));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const REQUEST: &str = "123e4567-e89b-12d3-a456-426614174000";
    const SECOND: &str = "223e4567-e89b-12d3-a456-426614174000";

    fn save(request: &str) -> SaveRequest {
        SaveRequest::parse(&format!("v1;acct=acct_1;db=db_1;req={request}")).unwrap()
    }
    fn persisted(pos: u64) -> SaveStatus {
        SaveStatus::Persisted {
            confirmed_pos: pos,
            folder: "folder_1".into(),
            pending: 0,
        }
    }

    fn binding() -> Binding {
        Binding::new("server", "acct_1", "db_1", None).unwrap()
    }

    #[test]
    fn exact_desktop_labels_match_only_their_account_and_database() {
        let binding = Binding::new("server", "acct_1", "db_1", None).unwrap();
        assert!(save(REQUEST).authorizes_save(&binding));
        assert!(!save(REQUEST)
            .authorizes_save(&Binding::new("server", "acct_2", "db_1", None).unwrap()));
        assert!(!save(REQUEST)
            .authorizes_save(&Binding::new("server", "acct_1", "db_2", None).unwrap()));
        let stop = SaveRequest::parse(&format!("off;req={REQUEST}")).unwrap();
        assert!(!stop.authorizes_save(&binding));
        assert_eq!(stop.request_id(), REQUEST);
    }

    #[test]
    fn malformed_duplicate_reordered_and_unknown_labels_never_authorize() {
        for raw in [
            "v1",
            "off",
            "v2;acct=a;db=b;req=x",
            "v1;db=b;acct=a;req=x",
            "v1;acct=a;db=b;req=x;extra=yes",
            "v1;acct=a;acct=b;db=c;req=x",
        ] {
            assert!(SaveRequest::parse(raw).is_none(), "{raw}");
        }
        for bad in ["a=b", "a;b", "a/b", "a b", "", "é", "a\nb"] {
            assert!(SaveRequest::parse(&format!("v1;acct={bad};db=b;req={REQUEST}")).is_none());
        }
        assert!(
            SaveRequest::parse(&format!("v1;acct={};db=b;req={REQUEST}", "a".repeat(129)))
                .is_none()
        );
        assert!(
            SaveRequest::parse(&format!("v1;acct=a;db=b;req={}", REQUEST.to_uppercase())).is_none()
        );
    }

    #[test]
    fn namespaced_account_tokens_are_not_mistaken_for_position_key_parts() {
        let request =
            SaveRequest::parse(&format!("v1;acct=account:one;db=db:one;req={REQUEST}")).unwrap();
        let binding = Binding::new("server", "account:one", "db:one", None).unwrap();
        assert!(request.authorizes_save(&binding));
        assert!(Binding::new("server:bad", "a", "b", None).is_err());
        assert!(Binding::new("server/bad", "a", "b", None).is_err());
    }

    #[test]
    fn status_wire_values_match_desktop_without_clamping_progress() {
        assert_eq!(
            persisted(40).label().unwrap(),
            "ok:40;folder=folder_1;pending=0"
        );
        assert_eq!(
            SaveStatus::Accepted {
                request: REQUEST.into()
            }
            .label()
            .unwrap(),
            format!("accepted:{REQUEST}")
        );
        assert_eq!(
            SaveStatus::Paused {
                reason: "hosted_unreachable".into()
            }
            .label()
            .unwrap(),
            "paused:hosted_unreachable"
        );
        assert_eq!(
            SaveStatus::RefusedBinding.label().unwrap(),
            "refused:binding"
        );
        assert!(persisted(MAX_STATUS_NUMBER + 1).label().is_err());
        assert!(SaveStatus::Error {
            code: "auth;ok=1".into()
        }
        .label()
        .is_err());
    }

    #[test]
    fn old_ok_cannot_bypass_new_request_correlation() {
        let mut publisher = StatusPublisher::default();
        publisher.request(&save(REQUEST), &binding()).unwrap();
        assert!(publisher.sent(&persisted(40), 0).is_err());
        let accepted = publisher.next(&persisted(40), 0).unwrap().unwrap();
        assert_eq!(
            accepted,
            SaveStatus::Accepted {
                request: REQUEST.into()
            }
        );
        publisher.sent(&accepted, 0).unwrap();
        let ok = publisher.next(&persisted(40), 1).unwrap().unwrap();
        publisher.sent(&ok, 1).unwrap();
        publisher.request(&save(SECOND), &binding()).unwrap();
        assert!(publisher.sent(&persisted(40), 2).is_err());
        assert_eq!(
            publisher.next(&persisted(40), 2).unwrap(),
            Some(SaveStatus::Accepted {
                request: SECOND.into()
            })
        );
        assert!(publisher.sent(&accepted, 2).is_err());
        let accepted_second = publisher.next(&persisted(40), 3).unwrap().unwrap();
        publisher.sent(&accepted_second, 3).unwrap();
        publisher.revoke();
        publisher.request(&save(SECOND), &binding()).unwrap();
        assert!(publisher.sent(&persisted(40), 4).is_err());
        assert!(publisher.next(&persisted(40), 4).unwrap().is_none());
        assert!(matches!(
            publisher.next(&persisted(40), 30_003).unwrap(),
            Some(SaveStatus::Accepted { .. })
        ));
    }

    #[test]
    fn failed_sends_and_kind_throttling_keep_acceptance_pending() {
        let mut publisher = StatusPublisher::default();
        publisher.request(&save(REQUEST), &binding()).unwrap();
        let first = publisher.next(&persisted(1), 0).unwrap().unwrap();
        assert_eq!(
            publisher.next(&persisted(2), 1).unwrap(),
            Some(first.clone())
        );
        publisher.sent(&first, 0).unwrap();
        publisher.request(&save(SECOND), &binding()).unwrap();
        assert_eq!(publisher.next(&persisted(2), 29_999).unwrap(), None);
        let next = publisher.next(&persisted(2), 30_000).unwrap().unwrap();
        publisher.sent(&next, 30_000).unwrap();
        let ok = publisher.next(&persisted(2), 30_001).unwrap().unwrap();
        publisher.sent(&ok, 30_001).unwrap();
        assert_eq!(publisher.next(&persisted(3), 30_002).unwrap(), None);
        assert_eq!(
            publisher
                .next(
                    &SaveStatus::Paused {
                        reason: "backlog".into()
                    },
                    30_002
                )
                .unwrap(),
            Some(SaveStatus::Paused {
                reason: "backlog".into()
            })
        );
    }
}
