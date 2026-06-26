#[no_std]
#![deny(unsafe_code)]

pub mod hot;
pub mod warm;
pub mod cold;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    IOError,
    FormatError,
    MemoryLimitExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotFound => write!(f, "Memory page not found"),
            Error::AlreadyExists => write!(f, "Memory page already exists"),
            Error::PermissionDenied => write!(f, "Permission denied accessing memory"),
            Error::IOError => write!(f, "IO error accessing memory store"),
            Error::FormatError => write!(f, "Memory format error"),
            Error::MemoryLimitExceeded => write!(f, "Memory limit exceeded"),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}