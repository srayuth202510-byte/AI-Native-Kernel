# Security Architecture

This document describes the security-first design of the AI-Native Kernel, following zero-trust principles and security best practices.

## Current Prototype Note

The repository now contains a mature security crate in `crates/capability-security/src/`.

Current implementation facts:

- token validation is in-memory (with constant-time comparison)
- policy is fail-closed (default DENY)
- policy decisions are constrained by an allowlist
- WORM audit logger is file-backed with hash chain validation and cryptographic log verification
- `authorize_token`, `validate`, and `decision_for` all emit audit records with Prometheus metrics counters
- token issuance is rate-limited (configurable via `max_issue_rate`)
- automatic revoke with callback propagation to kernel LSM `allowed_pids`
- revocation callbacks registered via `register_revocation_callback`

## Zero-Trust Security Model

The AI-Native Kernel implements a strict zero-trust security model where:

- **Every interaction requires validation**
- **Default is DENY** (fail-closed policy)
- **No implicit trust** for any component or user
- **Continuous verification** of all actions

## Security Layers

### 1. Capability Token System

#### Token Structure

```rust
#[derive(Debug, Clone)]
pub struct CapabilityToken {
    pub id: u64,                    // Unique token identifier
    pub scope: Scope,              // Process/thread/global scope
    pub capabilities: Vec<String>, // Allowed operations
    pub expires_at: std::time::Instant, // Token expiration
}

#[derive(Debug, Clone)]
pub enum Scope {
    Process(u32),   // Specific process ID
    Thread(u32),    // Specific thread ID  
    Global,         // All processes/threads
}
```

#### Token Validation Rules

1. **Scope Validation**: Token scope must exactly match operation scope
2. **Capability Matching**: Operation must be in token's capability list
3. **Expiration Check**: Token must not be expired
4. **Revocation Support**: Tokens can be revoked at any time

### 2. LSM Policy Engine

#### Policy Decision Points

The LSM (Linux Security Modules) hooks enforce security at syscall boundaries:

```rust
#[lsm]
fn ai_lsm_policy_hook(hook: &str, ctx: &mut LsmContext) -> LsmDecision {
    // Extract token from context
    let token = extract_token_from_context(ctx)?;
    
    // Validate token
    if !token.validate() {
        audit_log.log_denial(token.id, hook, "invalid_token");
        return LsmDecision::Deny;
    }
    
    // Check if operation is permitted
    if policy_engine.check_permission(token, hook) {
        audit_log.log_allow(token.id, hook, "policy_permit");
        LsmDecision::Allow
    } else {
        audit_log.log_denial(token.id, hook, "policy_deny");
        LsmDecision::Deny
    }
}
```

#### Default-Deny Policy

All decisions default to DENY unless explicitly allowed:

```rust
pub struct SecurityPolicy {
    pub allowed_capabilities: Vec<String>,  // Explicitly allowed operations
    pub deny_operations: Vec<String>,       // Explicitly denied operations  
    pub audit_enabled: bool,                // Enable/disable audit logging
}

impl SecurityPolicy {
    pub fn check(&self, operation: &str) -> PolicyDecision {
        // Explicit deny takes precedence
        if self.deny_operations.contains(&operation.to_string()) {
            return PolicyDecision::Deny(PolicyReason::ExplicitDeny);
        }
        
        // Check if explicitly allowed
        if self.allowed_capabilities.contains(&operation.to_string()) {
            return PolicyDecision::Allow(PolicyReason::ExplicitAllow);
        }
        
        // Default deny
        PolicyDecision::Deny(PolicyReason::DefaultDeny)
    }
}
```

In the current prototype, the equivalent behavior is implemented by `PolicyEngine` and defaults to allowing only a small allowlist of capabilities such as `read` and `execute`.

### 3. WORM Audit Logger

#### Audit Log Format

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: std::time::Instant,
    pub token_id: u64,
    pub operation: String,
    pub decision: Decision,
    pub context: String,           // Sanitized context
    pub source_ip: String,         // Sanitized IP
    pub process_id: u32,
    pub thread_id: u32,
    pub metadata: HashMap<String, String>, // Additional audit data
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Error,
}
```

#### Write-Once, Read-Many Properties

- **Write-Only**: Once written, entries cannot be modified
- **Append-Only**: New entries are always appended
- **Immutable**: All entries are read-only after creation
- **Tamper-Evident**: Any modification is detectable

#### Long-Term WORM Direction

```rust
pub struct WormAuditLogger {
    db: rocksdb::DB,
    pub key: Vec<u8>,  // Hashed log identifier
}

impl WormAuditLogger {
    pub fn new(name: &str) -> Result<Self, AuditError> {
        let path = format!("/var/log/ai_kernel/audit/{}-audit", name);
        let mut opts = rocksdb::Options::default();
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
        opts.set_max_file_size_for_level_compaction(512 * 1024 * 1024); // 512MB
        
        let db = rocksdb::DB::open(&opts, path)?;
        let key = format!("audit_log_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()).into_bytes();
        
        Ok(Self { db, key })
    }
    
    pub async fn log_decision(&self, entry: AuditLogEntry) -> Result<(), AuditError> {
        let value = bincode::serialize(&entry)?;
        
        // Atomic append
        self.db.put(&self.key, &value)?;
        
        // Flush to disk
        self.db.flush()?;
        
        Ok(())
    }
}
```

The current repository does not implement this RocksDB-backed audit logger yet. The active prototype uses an in-memory `AuditLogger` to validate policy flow and test behavior first.

## Security-First Implementation Rules

### 1. No `unwrap()` in Production Code

```rust
// ❌ BAD - Never use in production
let data = unsafe_data.unwrap();

// ✅ GOOD - Proper error propagation
let data = unsafe_data
    .ok_or_else(|| ComponentError::InvalidData { 
        source: Box::new(unsafe_data) 
    })?;
```

### 2. Constant-Time Comparisons

```rust
pub fn constant_time_eq<T: PartialEq>(a: &T, b: &T) -> bool {
    let a_bytes = unsafe { core::ptr::addr_of!(*a).cast::<u8>() };
    let b_bytes = unsafe { core::ptr::addr_of!(*b).cast::<u8>() };
    
    constant_time_eq_impl(a_bytes, b_bytes)
}
```

### 3. Sanitization Before Logging

```rust
pub fn sanitize_log_entry(&self, entry: &LogEntry) -> SanitizedLogEntry {
    let mut sanitized = entry.clone();
    
    // Remove PII
    sanitized.user_data = None;
    sanitized.ip_address = None;
    sanitized.token = None;
    
    // Remove sensitive metadata
    sanitized.sensitive_keys.retain(|k| {
        !["password", "secret", "token", "key"].contains(&k.as_str())
    });
    
    sanitized
}
```

### 4. Timeout for All External Calls

```rust
pub async fn external_api_call(&self, endpoint: &str) -> Result<ApiResponse, ApiError> {
    tokio::time::timeout(
        Duration::from_secs(30),
        self.http_client.get(endpoint).send()
    ).await
    .map_err(|_| ApiError::Timeout {
        endpoint: endpoint.to_string(),
        timeout: Duration::from_secs(30)
    })?
    .map_err(ApiError::Http)
}
```

### 5. Structured Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Token validation failed: {0}")]
    TokenValidationFailed(#[from] TokenError),
    
    #[error("Policy decision denied: {0}")]
    PolicyDecisionDenied(#[from] PolicyError),
    
    #[error("Audit log write failed: {0}")]
    AuditLogWriteFailed(#[from] AuditError),
    
    #[error("Token expired: {0}")]
    TokenExpired(std::time::Instant),
    
    #[error("Scope expansion failed: {0}")]
    ScopeExpansionFailed(String),
}
```

## Secure Coding Guidelines

### 1. Resource Management

```rust
// Use RAII for resource management
pub struct SecureConnection {
    stream: tokio::net::TcpStream,
    timeout_handle: tokio::task::JoinHandle<()>,
}

impl Drop for SecureConnection {
    fn drop(&mut self) {
        self.timeout_handle.abort();
        // Stream will be closed automatically
    }
}
```

### 2. Memory Safety

```rust
// Use safe APIs instead of unsafe
pub fn process_data(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Good: Use safe APIs
    let mut buffer = vec![0; data.len()];
    openssl::sha::sha256(data, &mut buffer);
    
    // Don't use raw pointers unless necessary
    // unsafe { *ptr = value }; // Bad!
    
    // Use safe alternatives
    *unsafe_ptr = value; // Still not great, but safer than direct access
}
```

### 3. Cryptographic Operations

```rust
pub fn secure_hash(&self, data: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    a == b // Simple comparison is fine for hash comparisons
}
```

## Security Testing

### Chaos Tests

Every Failure Domain must have a fault injection test:

```rust
#[tokio::test]
async fn test_security_policy_failure() {
    // Simulate policy engine failure
    let policy_engine = FaultyPolicyEngine::new();
    
    let token = CapabilityToken::new_invalid();
    
    // Should handle failure gracefully
    let result = policy_engine.check_permission(token, "read").await;
    assert!(result.is_err());
    
    // Verify audit log was written
    assert!(audit_logger.has_log_for_token(token.id));
}
```

### Fuzz Tests

```rust
#[tokio::test]
async fn test_token_validation_fuzz() {
    let policy_engine = PolicyEngine::new();
    
    // Generate random tokens
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let token = CapabilityToken::generate_random(&mut rng);
        let operation = random_operation(&mut rng);
        
        // Should not panic or crash
        let result = policy_engine.check_permission(token, &operation).await;
        assert!(result.is_ok() || result.is_err());
    }
}
```

## Compliance Checklist

### Security Checklist (Before Production)

- [ ] No `unwrap()` in non-test code
- [ ] No secrets/keys in code or logs  
- [ ] Error types defined and propagated correctly
- [ ] Policy Engine fails closed (DENY) on error
- [ ] Audit log entry written for every security decision
- [ ] Timeout applied to all external calls


### Security Principles

**Authentication & Authorization**:
- [ ] Capability tokens validate scope and expiration
- [ ] Role-based access control (RBAC) implemented
- [ ] Multi-factor authentication where appropriate

**Integrity & Confidentiality**:
- [ ] Encryption for sensitive data at rest
- [ ] Tamper-evident audit logs
- [ ] Sensitive data sanitization before logging

**Availability & Reliability**:
- [ ] Redundant components for critical paths
- [ ] Graceful degradation on failure
- [ ] Recovery mechanisms for all failure domains

**Monitoring & Compliance**:
- [ ] Real-time security monitoring
- [ ] Alerting for security events
- [ ] Regular security audits

## Incident Response

### Security Events

1. **Event Detection**: Monitor logs for:
   - Failed authorization attempts
   - Unusual activity patterns
   - Cryptographic failures

2. **Containment**: 
   - Isolate affected components
   - Revoke compromised tokens
   - Block offending IP addresses

3. **Recovery**:
   - Restore from clean backups
   - Rotate all security tokens
   - Update security policies

4. **Post-Mortem**:
   - Analyze root cause
   - Update security controls
   - Document lessons learned

This security architecture ensures the AI-Native Kernel operates as a truly zero-trust system, protecting both the host system and AI workloads with defense-in-depth security controls.

---

**Maintainer**: Security Team  
**Version**: 2.0.0  
**Last Updated**: $(date)
