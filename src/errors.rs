#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid cwe file {file}: {error}")]
    InvalidCweFile {
        file: String,
        error: String,
    },
}
