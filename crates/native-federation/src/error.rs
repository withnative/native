/// Errors owned by the storage-independent federation protocol and runtime.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Engine(String),
    #[error("{0}")]
    Auth(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn engine(message: impl Into<String>) -> Self {
        Self::Engine(message.into())
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth(message.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
