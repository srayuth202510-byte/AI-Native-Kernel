#![no_std]
#![deny(unsafe_code)]

pub mod token;
pub mod policy;
pub mod audit;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    TokenValidationFailed,
    PolicyDecisionDenied,
    AuditWriteFailed,
    ScopeExpansionFailed,
    ExpirationError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TokenValidationFailed => write!(f, "Capability token validation failed"),
            Error::PolicyDecisionDenied => write!(f, "Policy decision denied"),
            Error::AuditWriteFailed => write!(f, "Audit log write failed"),
            Error::ScopeExpansionFailed => write!(f, "Scope expansion failed"),
            Error::ExpirationError => write!(f, "Token expiration error"),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}