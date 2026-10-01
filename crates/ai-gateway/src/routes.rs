//! เส้นทาง HTTP ของ gateway
//!
//! แต่ละเส้นทางทำงานเหมือนกัน: อ่าน body → สรุปคำขอ → ให้ `GatewayCore` ตัดสินใจ
//! → ถ้าผ่านจึงส่งต่อ upstream แล้วตรวจ response → บันทึก audit
//!
//! ตรรกะการตัดสินใจทั้งหมดอยู่ใน `GatewayCore` ไม่ใช่ที่นี่ เพื่อให้ทดสอบได้
//! โดยไม่ต้องเปิด socket — ไฟล์นี้มีหน้าที่แค่แปลง HTTP เป็นเรียกใช้ และแปลงผลกลับ

use async_stream::stream;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use semantic_guard::Guard;
use serde::Serialize;
use std::sync::Arc;

use crate::entry::{ApiAuditEntry, ApiDecision};
use crate::policy::AuthError;
use crate::proxy::{self, ResponseInspection, Upstream};
use crate::wire::{Endpoint, RequestSummary};
use crate::{GatewayCore, GatewayError};

/// สถานะที่แชร์กับทุก handler
#[derive(Clone)]
pub struct AppState {
    /// แกนการตัดสินใจ
    pub core: Arc<GatewayCore>,
    /// ตัวส่งต่อไป upstream
    pub upstream: Upstream,
    /// guard สำหรับตรวจ response (อ้างอิงจาก core เพื่อไม่สร้างซ้ำ)
    pub guard: Option<Arc<Guard>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("upstream", &self.upstream)
            .field("guard_enabled", &self.guard.is_some())
            .finish()
    }
}

/// รูปแบบ error ที่เข้ากันได้กับ OpenAI
///
/// ลูกค้าที่ย้ายมาจาก API ของโมเดลโดยตรงต้องยัง parse ผลลัพธ์ได้
#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: ApiErrorDetail,
}

#[derive(Debug, Serialize)]
struct ApiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    kind: &'static str,
    code: &'static str,
    param: Option<String>,
}

/// error ที่แปลงเป็นกติกา HTTP แล้ว
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    kind: &'static str,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(
        status: StatusCode,
        kind: &'static str,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            kind,
            code,
            message: message.into(),
        }
    }

    fn body(&self) -> Json<ApiErrorBody> {
        Json(ApiErrorBody {
            error: ApiErrorDetail {
                message: self.message.clone(),
                kind: self.kind,
                code: self.code,
                param: None,
            },
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.body()).into_response()
    }
}

/// แปลงข้อผิดพลาดภายในเป็นกติกา HTTP
///
/// ข้อความที่ส่งกลับไม่เผยรายละเอียดภายในของระบบ เช่น path ของไฟล์หรือ
/// ข้อความจากระบบปฏิบัติการ เพราะผู้เรียกคือคนที่ยังไม่ผ่านการยืนยันตัวตน
fn to_api_error(err: &GatewayError) -> ApiError {
    match err {
        GatewayError::Auth(AuthError::MissingCredentials) => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_request_error",
            "missing_credentials",
            "ต้องส่ง header Authorization ในรูปแบบ Bearer <key>",
        ),
        GatewayError::Auth(AuthError::MalformedHeader) => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_request_error",
            "malformed_header",
            "รูปแบบ header Authorization ไม่ถูกต้อง ต้องเป็น Bearer <key> หรือ ApiKey <key>",
        ),
        GatewayError::Auth(AuthError::UnknownTenant) => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_request_error",
            "invalid_api_key",
            "คีย์ที่ใช้ไม่ถูกต้อง",
        ),
        GatewayError::Auth(AuthError::KeyExpired) => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_request_error",
            "expired_api_key",
            "คีย์หมดอายุแล้ว",
        ),
        GatewayError::Auth(AuthError::TenantSuspended) => ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_request_error",
            "tenant_suspended",
            "บัญชีผู้ใช้ถูกระงับการใช้งาน",
        ),
        GatewayError::Auth(AuthError::EndpointNotPermitted { .. })
        | GatewayError::Auth(AuthError::ModelNotPermitted { .. }) => ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_request_error",
            "policy_violation",
            "บัญชีผู้ใช้ไม่มีสิทธิ์เรียกเส้นทางหรือโมเดลนี้",
        ),
        GatewayError::Auth(AuthError::ConcurrencyLimit) => ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            "concurrency_limit",
            "จำนวนคำขอพร้อมกันของบัญชีผู้ใช้เต็มตามที่กำหนด",
        ),
        GatewayError::Audit(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "audit_unavailable",
            "ระบบบันทึกเหตุการณ์ไม่พร้อมใช้งาน จึงปฏิเสธคำขอเพื่อความปลอดภัย",
        ),
        GatewayError::AuditChain(_) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "audit_unavailable",
            "ระบบบันทึกเหตุการณ์ไม่พร้อมใช้งาน จึงปฏิเสธคำขอเพื่อความปลอดภัย",
        ),
        // เนื้อหาถูกนโยบายปฏิเสธ — ไม่เปิดเผยเหตุผลภายในให้ผู้เรียก
        // (กัน oracle ที่ใช้เดาว่ากฎใดทำงาน) ให้รหัสทั่วไปเท่านั้น
        GatewayError::Denied(_) => ApiError::new(
            StatusCode::FORBIDDEN,
            "policy_error",
            "response_blocked",
            "เนื้อหาถูกนโยบายความปลอดภัยปฏิเสธ",
        ),
        GatewayError::Config(_) | GatewayError::Guard(_) | GatewayError::Extraction(_) => {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal_error",
                "เกิดข้อผิดพลาดภายในระบบ",
            )
        }
        GatewayError::Upstream(_) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            "server_error",
            "upstream_error",
            "เชื่อมต่อโมเดลปลายทางไม่สำเร็จ",
        ),
    }
}

/// สร้าง router ของ gateway
pub fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/completions", post(completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

/// จุดตรวจสุขภาพ — ไม่เปิดเผยข้อมูลภายใน
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    handle(state, headers, body, Endpoint::ChatCompletions).await
}

async fn completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    handle(state, headers, body, Endpoint::Completions).await
}

async fn embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    handle(state, headers, body, Endpoint::Embeddings).await
}

/// กระบวนการหลักของคำขอหนึ่งรายการ
async fn handle(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    endpoint: Endpoint,
) -> Result<Response, ApiError> {
    let text = std::str::from_utf8(&body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "invalid_encoding",
            "body ต้องเป็น UTF-8 ที่ถูกต้อง",
        )
    })?;

    let summary = RequestSummary::parse(endpoint, text).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "invalid_body",
            match e {
                crate::wire::SummaryError::MissingModel => "body ต้องมีฟิลด์ model",
                _ => "body ต้องเป็น JSON ที่ถอดได้",
            },
        )
    })?;

    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    let now_ms = now_millis();

    let inspection = state
        .core
        .inspect_request(auth, endpoint, &summary.model, text, now_ms)
        .await
        .map_err(|e| to_api_error(&e))?;

    match inspection.decision {
        ApiDecision::Deny => {
            let (status, code) = match inspection.reason.as_str() {
                "model_not_permitted" | "endpoint_not_permitted" => {
                    (StatusCode::FORBIDDEN, "policy_violation")
                }
                "prompt_injection_detected" => (StatusCode::BAD_REQUEST, "prompt_injection"),
                _ => (StatusCode::FORBIDDEN, "denied"),
            };
            return Err(ApiError::new(
                status,
                "invalid_request_error",
                code,
                client_reason(&inspection.reason),
            ));
        }
        ApiDecision::Allow | ApiDecision::Redacted => {}
    }

    // ถ้ามีการปิดบังข้อมูลส่วนบุคคล ต้องส่งต่อเป็นเนื้อหาที่ปิดบังแล้ว
    let forward_body = if inspection.decision == ApiDecision::Redacted {
        Bytes::from(inspection.payload.into_bytes())
    } else {
        body
    };

    let path = match endpoint {
        Endpoint::ChatCompletions => "/v1/chat/completions",
        Endpoint::Completions => "/v1/completions",
        Endpoint::Embeddings => "/v1/embeddings",
    };

    let upstream_response = state
        .upstream
        .forward(path, &headers, forward_body)
        .await
        .map_err(|e| to_api_error(&e))?;

    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let out_headers = proxy::sanitize_response_headers(upstream_response.headers());

    if proxy::is_event_stream(&upstream_response) {
        // กัน prefix ไว้ตรวจก่อนปล่อย แล้วปล่อยที่เหลือทันที
        let stream = proxy::guard_stream_prefix(
            upstream_response.bytes_stream(),
            state.upstream.prefix_bytes(),
            state.guard.clone(),
        );

        // สำหรับ SSE ต้องบันทึก audit หลังสตรีมจบ — wrap stream เพื่อบันทึกเมื่อจบ
        let tenant_id = inspection.audit.tenant_id.clone();
        let core = state.core.clone();
        let base_audit = inspection.audit.clone();

        let stream = async_stream::stream! {
            let mut audit_recorded = false;
            let mut final_inspection = ResponseInspection::Clean;

            for await chunk in stream {
                if let Ok(ref bytes) = chunk {
                    // ตรวจสอบว่า chunk นี้เป็น chunk สุดท้ายหรือไม่ (SSE ends with "data: [DONE]\n\n")
                    let is_done = bytes.windows(6).any(|w| w == b"[DONE]");
                    if is_done && !audit_recorded {
                        // บันทึก audit หลังสตรีมจบ
                        let response_audit = response_audit_entry(
                            base_audit.clone(),
                            &final_inspection,
                        );
                        let _ = core.record_audit(&tenant_id, response_audit).await;
                        audit_recorded = true;
                    }
                }
                yield chunk;
            }

            // Fallback: ถ้าสตรีมจบโดยไม่มี [DONE] marker
            if !audit_recorded {
                let response_audit = response_audit_entry(base_audit, &final_inspection);
                let _ = core.record_audit(&tenant_id, response_audit).await;
            }
        };

        let mut resp = Response::builder().status(status);
        for (name, value) in &out_headers {
            resp = resp.header(name, value);
        }
        return resp
            .body(axum::body::Body::from_stream(stream))
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "response_build_failed",
                    "สร้าง response ไม่สำเร็จ",
                )
            });
    }

    let raw = proxy::read_inspectable(upstream_response)
        .await
        .map_err(|e| to_api_error(&e))?;
    let (inspected, response_inspection) =
        proxy::inspect_buffered(state.guard.as_deref(), &raw).map_err(|e| to_api_error(&e))?;

    // บันทึก audit สำหรับ response inspection
    let response_audit = response_audit_entry(inspection.audit.clone(), &response_inspection);
    state
        .core
        .record_audit(&inspection.audit.tenant_id, response_audit)
        .await
        .map_err(|e| to_api_error(&e))?;

    if response_inspection != ResponseInspection::Clean {
        tracing::info!(
            ?response_inspection,
            tenant = %inspection.audit.tenant_id,
            "response flagged"
        );
    }

    let mut resp = proxy::client_response(status, out_headers, inspected);
    resp.extensions_mut().insert(inspection.audit);
    Ok(resp)
}

/// เวลาปัจจุบันเป็นมิลลิวินาทีนับจาก UNIX epoch
fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// แปลงเหตุผลภายในเป็นข้อความที่บอกผู้เรียกได้โดยไม่เผยรายละเอียดภายใน
fn client_reason(reason: &str) -> String {
    match reason {
        "model_not_permitted" => "บัญชีผู้ใช้ไม่มีสิทธิ์เรียกโมเดลนี้".to_string(),
        "endpoint_not_permitted" => "บัญชีผู้ใช้ไม่มีสิทธิ์เรียกเส้นทางนี้".to_string(),
        "prompt_injection_detected" => "คำขอถูกปฏิเสธเนื่องจากตรวจพบรูปแบบการฉ้อโฉมคำสั่ง".to_string(),
        "pii_redacted" => "ปิดบังข้อมูลส่วนบุคคลในคำขอแล้ว".to_string(),
        other => format!("คำขอถูกปฏิเสธ ({other})"),
    }
}

/// สร้าง audit สำหรับ response ที่ประมวลผลแล้ว
#[must_use]
pub fn response_audit_entry(
    mut audit: ApiAuditEntry,
    inspection: &ResponseInspection,
) -> ApiAuditEntry {
    if let ResponseInspection::Redacted { count } = inspection {
        audit.decision = ApiDecision::Redacted;
        audit.reason = "pii_redacted_in_response".to_string();
        audit.redacted_count = Some(*count as u32);
    } else if let ResponseInspection::Rules(rules) = inspection {
        audit.injection_rules = Some(rules.join(","));
    }
    audit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DataPlanePolicy, TenantCredential, TenantPolicy};
    use axum::http::header::AUTHORIZATION;
    use std::time::Duration;

    fn state_in(dir: &str) -> AppState {
        let config = crate::GatewayConfig {
            audit_dir: std::env::temp_dir().join(format!("gw-routes-{dir}")),
            policy_file: std::env::temp_dir().join("unused.json"),
            guard_enabled: false,
            extraction_enabled: false,
            ..crate::GatewayConfig::default()
        };
        let tenants = vec![TenantPolicy {
            tenant_id: "acme".to_string(),
            allowed_endpoints: ["chat_completions", "embeddings"].into_iter().collect(),
            allowed_models: ["gpt-x".to_string()].into_iter().collect(),
            max_concurrent: 10,
            suspended: false,
        }];
        let creds = vec![TenantCredential {
            tenant_id: "acme".to_string(),
            key: b"secret-key".to_vec(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        }];
        let policy = DataPlanePolicy::new(tenants, creds);
        let core = futures::executor::block_on(GatewayCore::new(config, policy, None, None))
            .expect("core");
        let upstream = Upstream::new("http://127.0.0.1:1", Duration::from_millis(200), 4096)
            .expect("upstream");
        AppState {
            core: Arc::new(core),
            upstream,
            guard: None,
        }
    }

    fn auth_header() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer secret-key".parse().unwrap());
        h
    }

    const BODY: &str = r#"{"model":"gpt-x","messages":[{"role":"user","content":"hi"}]}"#;

    #[tokio::test]
    async fn missing_auth_returns_401_with_openai_shape() {
        let state = state_in("noauth");
        let err = handle(
            state,
            HeaderMap::new(),
            Bytes::from_static(BODY.as_bytes()),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "missing_credentials");
    }

    #[tokio::test]
    async fn bad_key_returns_401_not_403() {
        // คีย์ผิดคือปัญหาการยืนยันตัวตน ไม่ใช่ปัญหาสิทธิ์ — ต้องไม่บอกว่า
        // ผู้เข้าถึงมีสิทธิ์อะไรบ้าง
        let state = state_in("badkey");
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer nope".parse().unwrap());
        let err = handle(
            state,
            h,
            Bytes::from_static(BODY.as_bytes()),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "invalid_api_key");
    }

    #[tokio::test]
    async fn forbidden_model_returns_403() {
        let state = state_in("forbidden");
        let body = r#"{"model":"other","messages":[{"role":"user","content":"hi"}]}"#;
        let err = handle(
            state,
            auth_header(),
            Bytes::from(body),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "policy_violation");
    }

    #[tokio::test]
    async fn forbidden_endpoint_returns_403() {
        let state = state_in("forbidden_ep");
        let err = handle(
            state,
            auth_header(),
            Bytes::from_static(BODY.as_bytes()),
            Endpoint::Completions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert_eq!(err.code, "policy_violation");
    }

    #[tokio::test]
    async fn non_json_body_returns_400() {
        let state = state_in("nonjson");
        let err = handle(
            state,
            auth_header(),
            Bytes::from_static(b"not json"),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "invalid_body");
    }

    #[tokio::test]
    async fn missing_model_returns_400() {
        let state = state_in("nomodel");
        let err = handle(
            state,
            auth_header(),
            Bytes::from_static(br#"{"messages":[]}"#),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_utf8_returns_400() {
        let state = state_in("badutf8");
        let err = handle(
            state,
            auth_header(),
            Bytes::from_static(&[0xff, 0xfe]),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "invalid_encoding");
    }

    #[tokio::test]
    async fn upstream_failure_maps_to_502() {
        // upstream ที่ถูกตั้งไว้ให้ชี้ไปที่พอร์ตที่ไม่มีอะไรฟัง
        let state = state_in("upstream");
        let err = handle(
            state,
            auth_header(),
            Bytes::from_static(BODY.as_bytes()),
            Endpoint::ChatCompletions,
        )
        .await
        .expect_err("should fail");
        assert_eq!(err.status, StatusCode::BAD_GATEWAY);
        assert_eq!(err.code, "upstream_error");
    }

    #[test]
    fn client_reason_hides_internal_codes() {
        assert!(!client_reason("prompt_injection_detected").contains("instr-"));
        assert!(!client_reason("model_not_permitted").is_empty());
    }

    #[test]
    fn error_body_matches_openai_shape() {
        let err = ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_request_error",
            "denied",
            "no",
        );
        let json = serde_json::to_value(err.body().0).expect("serialize");
        assert_eq!(json["error"]["code"], "denied");
        assert_eq!(json["error"]["type"], "invalid_request_error");
        assert!(json["error"]["message"].is_string());
    }

    #[test]
    fn response_audit_marks_redaction() {
        let audit = ApiAuditEntry::new("acme", "r1", "chat_completions", "gpt-x");
        let out = response_audit_entry(audit, &ResponseInspection::Redacted { count: 3 });
        assert_eq!(out.decision, ApiDecision::Redacted);
        assert_eq!(out.redacted_count, Some(3));
    }

    #[test]
    fn response_audit_keeps_clean_verdict() {
        let audit = ApiAuditEntry::new("acme", "r1", "chat_completions", "gpt-x");
        let out = response_audit_entry(audit, &ResponseInspection::Clean);
        assert_eq!(out.decision, ApiDecision::Allow);
    }
}
