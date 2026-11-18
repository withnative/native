//! Explicit storage selection for the reusable session body boundary.
//! Selection belongs to the engine-aware opener; never probe/fall back by schema.
use super::live::{LoadedBody, SessionMode};
#[cfg(feature = "v2-kernel-probe")]
use super::RefusalCode;
use super::Refused;
use crate::{db::Db, mcp::Caller};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionBackend {
    V1,
    #[cfg(feature = "v2-kernel-probe")]
    KernelV2,
}

impl SessionBackend {
    pub(crate) async fn load_committed(
        self,
        db: &Db,
        caller: &Caller,
        record: &str,
        mode: SessionMode,
    ) -> Result<LoadedBody, Refused> {
        match self {
            Self::V1 => super::live::load_committed(db, caller, record, mode).await,
            #[cfg(feature = "v2-kernel-probe")]
            Self::KernelV2 => super::kernel_v2::load_committed(db, caller, record, mode)
                .await
                .map_err(kernel_refusal),
        }
    }
}

#[cfg(feature = "v2-kernel-probe")]
pub(super) fn kernel_refusal(error: crate::Error) -> Refused {
    match error {
        crate::Error::Engine(message) if message == crate::kernel::HIDDEN_OR_MISSING => {
            Refused::new(
                RefusalCode::Forbidden,
                "caller cannot access this record in the requested mode",
            )
        }
        crate::Error::Engine(message)
            if message == "kernel record body is not live-editable Markdown" =>
        {
            Refused::new(
                RefusalCode::RecordUnsupported,
                "record body is not live-editable Markdown",
            )
        }
        crate::Error::Engine(message) if message == "kernel live body exceeds session budget" => {
            Refused::new(RefusalCode::TooLarge, "body exceeds session budget")
        }
        _ => Refused::new(
            RefusalCode::Unavailable,
            "kernel session foundation unavailable",
        ),
    }
}

impl SessionBackend {
    pub(crate) async fn revalidate(
        self,
        db: &Db,
        caller: &Caller,
        record: &str,
        mode: SessionMode,
    ) -> Result<(), Refused> {
        match self {
            Self::V1 => super::live::load_committed(db, caller, record, mode)
                .await
                .map(|_| ()),
            #[cfg(feature = "v2-kernel-probe")]
            Self::KernelV2 => super::kernel_v2::revalidate(db, caller, record, mode)
                .await
                .map_err(kernel_refusal),
        }
    }
}

impl SessionBackend {
    pub(crate) async fn author(
        self,
        db: &Db,
        caller: &Caller,
    ) -> Result<super::live::Author, Refused> {
        let _ = db;
        match self {
            Self::V1 => Ok(super::live::author_for(caller)),
            #[cfg(feature = "v2-kernel-probe")]
            Self::KernelV2 => {
                let mut tx = db.pool().begin().await.map_err(super::live::unavailable)?;
                let contributor = super::kernel_v2::contributor_on(&mut tx, caller).await;
                tx.rollback().await.map_err(super::live::unavailable)?;
                Ok(super::live::Author {
                    contributor: contributor.map_err(super::live::unavailable)?,
                    kind: super::live::author_for(caller).kind,
                })
            }
        }
    }
}
