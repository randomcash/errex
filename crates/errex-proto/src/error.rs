use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("malformed event payload: {0}")]
    InvalidEvent(String),

    #[error("malformed metric point: {0}")]
    InvalidMetric(String),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
