#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid CWE file {file}: {error}")]
    InvalidCweFile {
        file: String,
        error: String,
    },
}
