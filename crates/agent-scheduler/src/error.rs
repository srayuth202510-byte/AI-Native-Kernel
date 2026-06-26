use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    #[error("agent already exists")]
    AgentAlreadyExists,
    #[error("agent not found")]
    AgentNotFound,
    #[error("agent is not running")]
    AgentNotRunning,
    #[error("agent is not paused")]
    AgentNotPaused,
    #[error("intent dispatch failed")]
    IntentDispatchFailed,
    #[error("context update failed")]
    ContextUpdateFailed,
    #[error("capability denied")]
    CapabilityDenied,
    #[error("capability security failure")]
    CapabilitySecurityFailed,
}
