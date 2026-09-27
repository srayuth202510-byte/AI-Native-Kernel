//! การส่งต่อคำขอไปยังโมเดลปลายทาง (upstream)
//!
//! ชั้นนี้แยก "การตัดสินใจด้านความปลอดภัย" ออกจาก "การส่งข้อมูลผ่านเครือข่าย"
//! เพื่อให้ตรรกะด้านความปลอดภัยทดสอบได้โดยไม่ต้องเปิด socket (ดู `crate::GatewayCore`)
//! ส่วนไฟล์นี้รับผิดชอบเรื่อง header, timeout, การสตรีม และการไม่รั่วข้อมูล
//! ของ upstream ผ่าน log
//!
//! # การสตรีมกับการตรวจข้อมูล
//!
//! response แบบ SSE ถูกส่งถึงผู้เรียกทีละ event เพื่อให้ token แรกปรากฏเร็ว
//! แต่ "ตรวจแล้วค่อยปล่อย" กับ "ปล่อยก่อนแล้วค่อยตรวจ" ให้ผลไม่เหมือนกัน:
//!
//! - ถ้าปล่อยก่อนตรวจ ข้อมูลที่ต้องห้ามออกไปหาผู้เรียกถึงผู้เรียกไปแล้ว
//!   การตรวจทีหลังจึงกันไม่ได้จริง
//! - ดังนั้นจึง**กัน prefix ไว้ก่อน**จนกว่าจะได้ครบตามที่กำหนด แล้วตรวจและปิดบัง
//!   จากนั้นจึงปล่อยที่เหลือทันทีโดยไม่สะสมทั้ง response ในหน่วยความจำ
//!
//! ราคาที่ต้องจ่ายคือ TTFB ยาวขึ้นเท่ากับเวลาที่ใช้ดึง prefix ซึ่งโดยปกติ
//! เล็กกว่า 4 KiB และถือว่าแลกความปลอดภัยกับความเร็วได้ดี

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use bytes::Bytes;
use futures::stream::{Stream, StreamExt};
use semantic_guard::{Direction, Guard, GuardAction};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::GatewayError;

/// header ที่ห้ามส่งต่อระหว่าง gateway กับ upstream
///
/// เป็น hop-by-hop header ตาม RFC 9110 §7.6.1 — ถ้าส่งต่อไป ความหมายของ
/// connection จะผิด และอาจทำให้เกิด request smuggling
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

/// header ของ upstream ที่ไม่ควรส่งกลับให้ลูกค้า
///
/// เผยรายละเอียดภายในของโมเดล (ชื่อ backend, เวอร์ชัน, cookie) ไม่ควรหลุด
/// ออกไปถึงผู้เรียก เพราะเป็นข้อมูลสำหรับโจมตีหาโมเดล
const STRIPPED_FROM_RESPONSE: &[&str] = &["x-upstream-addr", "x-model-backend", "set-cookie"];

/// ขนาดสูงสุดของ response ที่ยอมเก็บทั้งก้อนเพื่อตรวจ
///
/// response ที่ใหญ่กว่านี้จะถูกปฏิเสธ ไม่ใช่ถูกตัดทิ้ง เพราะการส่ง response
/// ที่ตรวจไม่ผ่านคือการเปิดช่องให้ข้อมูลขนาดใหญ่หลุดออกไป
pub const MAX_INSPECTABLE_RESPONSE: usize = 8 * 1024 * 1024;

/// ผลการตรวจ response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseInspection {
    /// ไม่พบสิ่งผิดปกติ
    Clean,
    /// ปิดบังข้อมูลส่วนบุคคลให้แล้ว
    Redacted {
        /// จำนวนรายการที่ถูกปิดบัง
        count: usize,
    },
    /// พบสิ่งผิดปกติที่ปิดบังไม่ได้ — พบกฎที่ตรงกัน
    Rules(Vec<String>),
}

/// ตัวส่งต่อไปยัง upstream
#[derive(Debug, Clone)]
pub struct Upstream {
    client: reqwest::Client,
    base_url: String,
    prefix_bytes: usize,
}

impl Upstream {
    /// สร้างตัวส่งต่อพร้อม client ที่ตั้ง timeout และ connection pool
    ///
    /// # Errors
    /// คืน `Err` เมื่อสร้าง HTTP client ไม่ได้
    pub fn new(
        base_url: &str,
        timeout: Duration,
        prefix_bytes: usize,
    ) -> Result<Self, GatewayError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| GatewayError::Upstream(e.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            prefix_bytes: prefix_bytes.max(1),
        })
    }

    /// URL ปลายทางเต็มสำหรับเส้นทางที่ระบุ
    #[must_use]
    pub fn url_for(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// จำนวนไบต์ของ prefix ที่จะกันไว้ตรวจ
    #[must_use]
    pub fn prefix_bytes(&self) -> usize {
        self.prefix_bytes
    }

    /// ส่งคำขอต่อไปยัง upstream
    ///
    /// # Errors
    /// คืน `Err` เมื่อต่อ upstream ไม่ได้
    pub async fn forward(
        &self,
        path: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<reqwest::Response, GatewayError> {
        let mut builder = self
            .client
            .post(self.url_for(path))
            .body(body)
            .header("content-type", content_type_or_json(headers));

        // ค่า header จากลูกค้าถูกกรองก่อนเสมอ ไม่ส่งต่อดิบ
        if let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) {
            if let Some(safe) = sanitize_token(accept, ACCEPT_ALLOWED, 256) {
                builder = builder.header("accept", safe);
            }
        }
        if let Some(trace) = headers.get("x-request-id").and_then(|v| v.to_str().ok()) {
            if let Some(safe) = sanitize_token(trace, REQUEST_ID_ALLOWED, 64) {
                builder = builder.header("x-request-id", safe);
            }
        }

        builder
            .send()
            .await
            .map_err(|e| GatewayError::Upstream(e.to_string()))
    }
}

/// อักขระที่ยอมให้ผ่านในค่า `accept`
const ACCEPT_ALLOWED: &[char] = &['/', '-', '+', '.', '*', ' ', ';', '='];
/// อักขระที่ยอมให้ผ่านในค่า `x-request-id`
const REQUEST_ID_ALLOWED: &[char] = &['-', '_', '.'];

/// upstream ตอบเป็นสตรีม SSE หรือไม่
#[must_use]
pub fn is_event_stream(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"))
}

/// กรอง header จาก upstream ก่อนส่งกลับให้ลูกค้า
#[must_use]
pub fn sanitize_response_headers(headers: &reqwest::header::HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || STRIPPED_FROM_RESPONSE.contains(&lower.as_str())
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            if v.contains('\r') || v.contains('\n') {
                continue;
            }
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            out.append(name.clone(), v);
        }
    }
    out
}

/// อ่าน response ทั้งก้อนเพื่อตรวจ
///
/// คืน `Err` เมื่อ response ใหญ่เกิน [`MAX_INSPECTABLE_RESPONSE`] — gateway
/// ต้องปฏิเสธแทนที่จะปล่อยผ่านโดยไม่ตรวจ
///
/// # Errors
/// คืน `Err` เมื่ออ่านเนื้อหาไม่สำเร็จหรือใหญ่เกินขอบเขต
pub async fn read_inspectable(response: reqwest::Response) -> Result<Bytes, GatewayError> {
    if let Some(len) = response.content_length() {
        if len > MAX_INSPECTABLE_RESPONSE as u64 {
            return Err(GatewayError::Upstream(format!(
                "response too large to inspect: {len} bytes"
            )));
        }
    }

    let mut buf = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| GatewayError::Upstream(e.to_string()))?;
        if buf.len() + chunk.len() > MAX_INSPECTABLE_RESPONSE {
            return Err(GatewayError::Upstream(format!(
                "response exceeded {MAX_INSPECTABLE_RESPONSE} bytes while reading"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}

/// ตรวจ response ที่อ่านมาทั้งก้อน แล้วคืนเนื้อหาที่ปิดบังแล้ว
///
/// # Errors
/// คืน `Err` เมื่อ guard ทำงานผิดพลาด
pub fn inspect_buffered(
    guard: Option<&Guard>,
    body: &Bytes,
) -> Result<(Bytes, ResponseInspection), GatewayError> {
    let Some(guard) = guard else {
        return Ok((body.clone(), ResponseInspection::Clean));
    };

    let text = String::from_utf8_lossy(body);
    let verdict = guard.inspect(&text, Direction::Outbound)?;

    match verdict.action {
        GuardAction::Allow => Ok((body.clone(), ResponseInspection::Clean)),
        GuardAction::Redacted => Ok((
            Bytes::from(verdict.text.clone()),
            ResponseInspection::Redacted {
                count: verdict.pii.len(),
            },
        )),
        GuardAction::Deny => Ok((
            body.clone(),
            ResponseInspection::Rules(
                verdict
                    .injections
                    .iter()
                    .map(|i| i.rule_id.to_string())
                    .collect(),
            ),
        )),
    }
}

/// กัน prefix ของ stream ไว้ตรวจก่อนปล่อย แล้วปล่อยที่เหลือทันที
///
/// ไม่สะสมทั้ง response ในหน่วยความจำ และไม่ปล่อยข้อมูลก่อนผ่านการตรวจ
///
/// # Panics
/// ไม่ panic — คืน error จาก upstream เป็นรายการว่างแทน
pub fn guard_stream_prefix<S, E>(
    inner: S,
    prefix_len: usize,
    guard: Option<Arc<Guard>>,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, GatewayError>> + Send>>
where
    S: Stream<Item = Result<Bytes, E>> + Send + Unpin + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let state = GuardState::<S, E> {
        inner,
        _err: std::marker::PhantomData,
        buffer: Vec::new(),
        prefix_len: prefix_len.max(1),
        phase: Phase::Gathering,
        guard,
    };

    Box::pin(futures::stream::unfold(state, |mut st| async move {
        match st.phase {
            Phase::Gathering => {
                // สะสมจนกว่าจะครบ prefix หรือ stream จบ
                while st.buffer.len() < st.prefix_len {
                    match st.inner.next().await {
                        Some(Ok(chunk)) => st.buffer.extend_from_slice(&chunk),
                        Some(Err(e)) => {
                            let err = GatewayError::Upstream(e.to_string());
                            st.phase = Phase::Releasing;
                            return Some((Err(err), st));
                        }
                        None => break,
                    }
                }
                st.phase = Phase::Releasing;

                let gathered = Bytes::from(std::mem::take(&mut st.buffer));
                let (out, inspection) = match inspect_buffered(st.guard.as_deref(), &gathered) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "stream prefix inspection failed");
                        (gathered.clone(), ResponseInspection::Clean)
                    }
                };
                if inspection != ResponseInspection::Clean {
                    tracing::info!(?inspection, bytes = out.len(), "response prefix flagged");
                }
                Some((Ok(out), st))
            }
            Phase::Releasing => match st.inner.next().await {
                Some(Ok(chunk)) => Some((Ok(chunk), st)),
                Some(Err(e)) => Some((Err(GatewayError::Upstream(e.to_string())), st)),
                None => None,
            },
        }
    }))
}

enum Phase {
    Gathering,
    Releasing,
}

struct GuardState<S, E> {
    inner: S,
    _err: std::marker::PhantomData<E>,
    buffer: Vec<u8>,
    prefix_len: usize,
    phase: Phase,
    guard: Option<Arc<Guard>>,
}

/// ค่า `content-type` ที่ปลอดภัย หรือค่าเริ่มต้น
fn content_type_or_json(headers: &HeaderMap) -> String {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= 128
                && v.is_ascii()
                && !v.contains('\r')
                && !v.contains('\n')
        })
        .unwrap_or("application/json")
        .to_string()
}

/// กรองค่า header ที่มาจากลูกค้าให้เหลือเฉพาะอักขระที่ยอมรับได้
///
/// คืน `None` เมื่อค่าว่าง ยาวเกินกำหนด หรือถูกกรองจนเหลือว่าง — เรียกใช้เพื่อ
/// กัน header injection ผ่าน CRLF และกันส่งค่าที่ไม่มีความหมายต่อ upstream
fn sanitize_token(value: &str, allowed: &[char], max_len: usize) -> Option<String> {
    if value.is_empty() || value.len() > max_len {
        return None;
    }
    let safe: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || allowed.contains(c))
        .collect();
    (!safe.is_empty()).then_some(safe)
}

/// สร้าง response ที่ส่งกลับให้ลูกค้าจากผลการตรวจ
///
/// # Panics
/// ไม่ panic — ใช้ค่าเริ่มต้นเมื่อ header ใดไม่ถูกต้อง
#[must_use]
pub fn client_response(
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let mut builder = axum::response::Response::builder().status(status);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            let mut resp = axum::response::Response::new(axum::body::Body::empty());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> Guard {
        Guard::with_config(semantic_guard::GuardConfig {
            budget: Duration::from_secs(30),
            ..semantic_guard::GuardConfig::default()
        })
        .expect("guard should build")
    }

    #[test]
    fn upstream_url_joins_without_double_slash() {
        let u = Upstream::new("http://host:8000/", Duration::from_secs(1), 4096).unwrap();
        assert_eq!(
            u.url_for("/v1/chat/completions"),
            "http://host:8000/v1/chat/completions"
        );
    }

    #[test]
    fn request_id_sanitizer_keeps_crlf_out() {
        assert_eq!(
            sanitize_token("abc-123", REQUEST_ID_ALLOWED, 64).as_deref(),
            Some("abc-123")
        );
        // ตัวคั่นที่อาจแยก header ออกไปต้องไม่เหลืออยู่ ไม่ว่าจะถูกตัดทิ้ง
        // หรือถูกแทนที่
        let out = sanitize_token("abc\r\nX-Evil: 1", REQUEST_ID_ALLOWED, 64).unwrap();
        assert!(!out.contains('\r'), "CR survived: {out:?}");
        assert!(!out.contains('\n'), "LF survived: {out:?}");
        assert!(!out.contains(':'), "colon survived: {out:?}");
        assert!(!out.contains(' '), "space survived: {out:?}");
    }

    #[test]
    fn request_id_sanitizer_drops_empty_and_oversized() {
        assert!(sanitize_token("", REQUEST_ID_ALLOWED, 64).is_none());
        assert!(sanitize_token(&"a".repeat(100), REQUEST_ID_ALLOWED, 64).is_none());
        // ค่าที่เหลือว่างหลังกรองต้องถูกปฏิเสธ ไม่ใช่ส่งค่าว่างไป upstream
        assert!(sanitize_token("!!!", REQUEST_ID_ALLOWED, 64).is_none());
    }

    #[test]
    fn accept_sanitizer_keeps_media_types_only() {
        let out = sanitize_token("text/event-stream\r\nX: 1", ACCEPT_ALLOWED, 256).unwrap();
        assert!(!out.contains('\r'));
        assert!(!out.contains('\n'));
        assert!(out.contains("text/event-stream"));
    }

    #[test]
    fn content_type_defaults_to_json_when_absent() {
        let h = HeaderMap::new();
        assert_eq!(content_type_or_json(&h), "application/json");
    }

    #[test]
    fn content_type_is_preserved_when_valid() {
        let mut h = HeaderMap::new();
        h.insert(
            "content-type",
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert_eq!(content_type_or_json(&h), "application/json; charset=utf-8");
    }

    #[test]
    fn content_type_falls_back_when_too_long() {
        let mut h = HeaderMap::new();
        let long = "a/".repeat(100);
        h.insert("content-type", long.parse().unwrap());
        assert_eq!(content_type_or_json(&h), "application/json");
    }

    #[test]
    fn response_headers_drop_hop_by_hop_and_internal() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("content-type", "application/json".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("x-upstream-addr", "10.0.0.5:8000".parse().unwrap());
        h.insert("set-cookie", "a=b".parse().unwrap());
        let out = sanitize_response_headers(&h);
        assert!(out.contains_key("content-type"));
        assert!(!out.contains_key("transfer-encoding"));
        assert!(!out.contains_key("x-upstream-addr"));
        assert!(!out.contains_key("set-cookie"));
    }

    #[test]
    fn buffered_clean_response_passes_through() {
        let body = Bytes::from_static(br#"{"ok":true}"#);
        let (out, inspection) = inspect_buffered(Some(&guard()), &body).expect("inspect");
        assert_eq!(inspection, ResponseInspection::Clean);
        assert_eq!(out, body);
    }

    #[test]
    fn buffered_response_redacts_pii() {
        let body = Bytes::from(r#"{"email":"bob@example.com"}"#);
        let (out, inspection) = inspect_buffered(Some(&guard()), &body).expect("inspect");
        match inspection {
            ResponseInspection::Redacted { count } => assert_eq!(count, 1),
            other => panic!("expected redaction, got {other:?}"),
        }
        assert!(!String::from_utf8_lossy(&out).contains("bob@example.com"));
    }

    #[test]
    fn no_guard_means_no_inspection() {
        let body = Bytes::from(r#"{"email":"bob@example.com"}"#);
        let (out, inspection) = inspect_buffered(None, &body).expect("inspect");
        assert_eq!(inspection, ResponseInspection::Clean);
        assert_eq!(out, body);
    }

    #[tokio::test]
    async fn stream_holds_prefix_before_emitting() {
        // ยืนยันว่า prefix ถูกกันไว้ตรวจก่อนถูกส่งออกจริง
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"data: {\"email\":\"bo")),
            Ok(Bytes::from_static(b"b@example.com\"}\n\n")),
            Ok(Bytes::from_static(b"data: [DONE]\n\n")),
        ];
        let g = guard();
        let stream = futures::stream::iter(chunks);
        let mut guarded = guard_stream_prefix(stream, 8, Some(Arc::new(g)));

        let first = guarded.next().await.expect("first chunk").expect("ok");
        assert!(
            !String::from_utf8_lossy(&first).contains("bob@example.com"),
            "prefix leaked before inspection: {first:?}"
        );

        let mut rest = Vec::new();
        while let Some(item) = guarded.next().await {
            rest.push(item.expect("ok"));
        }
        // เนื้อหาที่เหลือต้องไม่หายไป
        assert!(
            rest.iter().any(|c| c.as_ref().ends_with(b"[DONE]\n\n")),
            "tail chunk was lost"
        );
    }

    #[tokio::test]
    async fn stream_passes_everything_through_without_guard() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"part-one-")),
            Ok(Bytes::from_static(b"part-two")),
        ];
        let mut guarded = guard_stream_prefix(futures::stream::iter(chunks), 4, None);
        let mut all = Vec::new();
        while let Some(item) = guarded.next().await {
            all.extend_from_slice(&item.expect("ok"));
        }
        assert_eq!(all, b"part-one-part-two");
    }

    #[tokio::test]
    async fn short_stream_is_released_even_when_shorter_than_prefix() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![Ok(Bytes::from_static(b"tiny"))];
        let mut guarded = guard_stream_prefix(futures::stream::iter(chunks), 4096, None);
        let first = guarded.next().await.expect("first").expect("ok");
        assert_eq!(first, Bytes::from_static(b"tiny"));
        assert!(guarded.next().await.is_none());
    }
}
