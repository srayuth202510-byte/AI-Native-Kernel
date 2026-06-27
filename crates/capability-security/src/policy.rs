use std::collections::BTreeSet;

use crate::token::{CapabilityToken, Scope};

/// ผลลัพธ์การตัดสินใจตามนโยบายความปลอดภัย
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// อนุญาตให้เข้าถึงสิทธิ์ความสามารถตามที่ร้องขอได้
    Allow,
    /// ปฏิเสธการเข้าถึงสิทธิ์ความสามารถตามที่ร้องขอ (สอดคล้องกับแนวคิด Fail-Closed)
    Deny,
}

/// กลไกการประเมินและตัดสินใจตามนโยบายความปลอดภัย (Policy Engine)
/// ตรวจสอบว่าโทเค็น ขอบเขต (Scope) และ Capability มีความสอดคล้องกันหรือไม่
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// รายการสิทธิ์ความสามารถที่ได้รับอนุญาตให้ทำงานในระบบ (เป็น Allowlist)
    allowed_capabilities: BTreeSet<String>,
    /// ผลการตัดสินใจเริ่มต้นหากไม่มีข้อกำหนดใดแมตช์ตรงกับข้อมูลการร้องขอ
    default_decision: PolicyDecision,
}

impl PolicyEngine {
    /// สร้างกลไกนโยบายความปลอดภัยด้วยผลการตัดสินใจเริ่มต้น พร้อมกำหนดสิทธิ์อนุญาตมาตรฐานคือ "read" และ "execute"
    #[must_use]
    pub fn new(default_decision: PolicyDecision) -> Self {
        Self::with_allowed_capabilities(default_decision, ["read", "execute"])
    }

    /// สร้างกลไกนโยบายความปลอดภัยที่อนุญาตให้กำหนดผลการตัดสินใจเริ่มต้นและปรับแต่งรายการสิทธิ์ความสามารถที่ยอมรับได้เอง
    #[must_use]
    pub fn with_allowed_capabilities<I, S>(
        default_decision: PolicyDecision,
        capabilities: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_capabilities: capabilities.into_iter().map(Into::into).collect(),
            default_decision,
        }
    }

    /// ตรวจสอบความถูกต้องและอนุมัติสิทธิ์ (Authorize) ว่าตรงตามเงื่อนไขของนโยบายความปลอดภัยหรือไม่
    #[must_use]
    pub fn authorize(&self, token: &CapabilityToken, scope: &Scope, capability: &str) -> bool {
        matches!(
            self.decision(token, scope, capability),
            PolicyDecision::Allow
        )
    }

    /// ทำการประเมินสิทธิ์ความสามารถตามกฎของนโยบายและส่งกลับผลการตัดสินใจ (Policy Decision) เป็น Allow หรือ Deny
    #[must_use]
    pub fn decision(
        &self,
        token: &CapabilityToken,
        scope: &Scope,
        capability: &str,
    ) -> PolicyDecision {
        // ปฏิเสธทันทีหากโทเค็นหมดอายุ หรือไม่มีสิทธิ์ความสามารถนั้น หรือสิทธิ์นั้นไม่อยู่ใน Allowlist ของนโยบาย
        if !token.is_valid()
            || !token.allows(capability)
            || !self.allowed_capabilities.contains(capability)
        {
            return PolicyDecision::Deny;
        }

        // หากขอบเขตของโทเค็นตรงกับขอบเขตที่ร้องขอ หรือเป็นขอบเขตระดับสากล (Global) ให้ยอมรับ
        if token.scope == *scope || matches!(token.scope, Scope::Global) {
            PolicyDecision::Allow
        } else {
            // หากขอบเขตไม่ตรงกัน ให้ใช้ผลการตัดสินใจเริ่มต้นของระบบ (โดยทั่วไปคือ Deny)
            self.default_decision
        }
    }
}

impl Default for PolicyEngine {
    /// สร้างค่าเริ่มต้นสำหรับ `PolicyEngine` ซึ่งจะใช้โหมดปฏิเสธสิทธิ์ (Deny) เป็นหลักตามหลักการความปลอดภัย Zero-Trust
    fn default() -> Self {
        Self::new(PolicyDecision::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn token(scope: Scope, capabilities: &[&str]) -> CapabilityToken {
        CapabilityToken::new(
            1,
            scope,
            capabilities.iter().map(|cap| (*cap).to_string()).collect(),
            Duration::from_secs(60),
            [0xAA; 32],
        )
    }

    #[test]
    fn decision_allows_matching_scope_and_capability() {
        let engine = PolicyEngine::default();
        let token = token(Scope::Process(7), &["read"]);

        assert_eq!(
            engine.decision(&token, &Scope::Process(7), "read"),
            PolicyDecision::Allow
        );
        assert!(engine.authorize(&token, &Scope::Process(7), "read"));
    }

    #[test]
    fn decision_denies_scope_mismatch_by_default() {
        let engine = PolicyEngine::default();
        let token = token(Scope::Process(7), &["read"]);

        assert_eq!(
            engine.decision(&token, &Scope::Thread(7), "read"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn decision_can_allow_scope_mismatch_when_default_is_allow() {
        let engine = PolicyEngine::new(PolicyDecision::Allow);
        let token = token(Scope::Process(7), &["read"]);

        assert_eq!(
            engine.decision(&token, &Scope::Thread(7), "read"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn decision_denies_capability_outside_allowlist() {
        let engine = PolicyEngine::default();
        let token = token(Scope::Global, &["write"]);

        assert_eq!(
            engine.decision(&token, &Scope::Global, "write"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn decision_denies_expired_tokens_even_when_scope_matches() {
        let engine = PolicyEngine::default();
        let expired = CapabilityToken {
            id: 2,
            scope: Scope::Global,
            capabilities: vec!["read".to_string()],
            expires_at: SystemTime::now() - Duration::from_secs(1),
            secret: [0xBB; 32],
        };

        assert_eq!(
            engine.decision(&expired, &Scope::Global, "read"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn custom_allowlist_is_honored() {
        let engine = PolicyEngine::with_allowed_capabilities(PolicyDecision::Deny, ["write"]);
        let token = token(Scope::Global, &["write"]);

        assert_eq!(
            engine.decision(&token, &Scope::Global, "write"),
            PolicyDecision::Allow
        );
        assert_eq!(
            engine.decision(&token, &Scope::Global, "read"),
            PolicyDecision::Deny
        );
    }
}
