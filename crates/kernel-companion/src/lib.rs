#![no_std]
#![allow(dead_code)]

pub mod lsm;
pub mod ebpf;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    // LSM hook errors
    PolicyDecisionDenied,
    CapabilityTokenInvalid,
    AuditLogWriteFailed,
    
    // eBPF program errors  
    MemoryAccessViolation,
    PageFaultHandlingFailed,
    CapabilityNotFound,
    
    // Compute scheduler errors
    ComputeAllocationFailed,
    ResourceExhausted,
    HardwareUnavailable,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::PolicyDecisionDenied => write!(f, "Policy denied"),
            Error::CapabilityTokenInvalid => write!(f, "Invalid capability token"),
            Error::AuditLogWriteFailed => write!(f, "Failed to write audit log"),
            Error::MemoryAccessViolation => write!(f, "Memory access violation"),
            Error::PageFaultHandlingFailed => write!(f, "Page fault handling failed"),
            Error::CapabilityNotFound => write!(f, "Capability token not found"),
            Error::ComputeAllocationFailed => write!(f, "Compute allocation failed"),
            Error::ResourceExhausted => write!(f, "Resource exhausted"),
            Error::HardwareUnavailable => write!(f, "Hardware unavailable"),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}