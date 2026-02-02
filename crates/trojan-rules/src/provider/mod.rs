//! Rule-set providers for loading rules from various sources.

pub mod file;
#[cfg(feature = "http")]
pub mod http;

pub use file::FileProvider;
#[cfg(feature = "http")]
pub use http::HttpProvider;
