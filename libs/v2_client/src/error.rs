use thiserror::Error;
use v2_identity::IdentityError;
use v2_transport::TransportError;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("http error (status {status}): {body}")]
    HttpStatus { status: u16, body: String },
    #[error("http protocol error: {0}")]
    Http(String),
    #[error("json codec error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("noise access control error: {0}")]
    Noise(String),
    #[error("edge control rejected request (status={status:#06x}): {context}")]
    EdgeStatus { status: u16, context: String },
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}
