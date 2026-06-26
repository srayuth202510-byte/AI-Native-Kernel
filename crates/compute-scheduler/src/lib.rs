#![no_std]
#![deny(unsafe_code)]

pub mod cost;
pub mod weights;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidWeights,
    ComputationError,
    ResourceUnavailable,
    HardwareNotSupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidWeights => write!(f, "Invalid compute weights"),
            Error::ComputationError => write!(f, "Computation error"),
            Error::ResourceUnavailable => write!(f, "Resource unavailable"),
            Error::HardwareNotSupported => write!(f, "Hardware not supported"),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}