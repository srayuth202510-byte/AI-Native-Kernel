//! Capability-scoped skill manifests (Hardening H8)
//!
//! ประกาศ "ความถนัด" ของ agent เป็นไฟล์ manifest แบบ skill.md — frontmatter
//! (TOML คั่นด้วย `+++`) เป็น **สัญญาที่ kernel ตรวจ** ไม่ใช่แค่คำแนะนำ:
//! manifest หนึ่งไฟล์ประกาศพร้อมกันทั้ง routing (`description`), placement
//! (`model`/`compute`) และ capability scope (`[capabilities]`) ที่ H3 บังคับ
//!
//! กติกาสำคัญ (สืบทอดจาก H3): skill **narrow ได้เท่านั้น** — `allow` list
//! บอกว่า agent ต้องการ operation class อะไร ส่วนที่ไม่อยู่ใน list จะถูก
//! ถอนออกจาก grant ของ token (ไม่มีทางเปิดเกินที่ token ให้) ทำให้ specialist
//! แต่ละตัววิ่งใต้ least-privilege ที่ตรงกับงานมันเป๊ะ ต่อให้โดน prompt
//! injection สั่งทำนอกความถนัด kernel ก็ปฏิเสธ

use intent_bus::{Intent, IntentPriority, IntentType};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// ข้อผิดพลาดจากการโหลด/แปลง skill manifest
#[derive(Debug, Error)]
pub enum SkillError {
    /// ไม่พบ frontmatter (`+++ ... +++`) ในไฟล์
    #[error("missing +++ TOML frontmatter")]
    MissingFrontmatter,
    /// parse TOML frontmatter ไม่สำเร็จ
    #[error("invalid frontmatter TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// อ่านไฟล์ไม่สำเร็จ
    #[error("cannot read skill file: {0}")]
    Io(#[from] std::io::Error),
    /// manifest ไม่มีฟิลด์บังคับ หรือค่าไม่ถูกต้อง
    #[error("invalid manifest: {0}")]
    Invalid(String),
}

/// ขอบเขตสิทธิ์ที่ skill ประกาศ (map ตรงกับ scope ที่ H3 บังคับ)
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct SkillCapabilities {
    /// จำกัด file_open ใต้ path นี้ (`None` = ไม่จำกัด path) — รูปย่อของ
    /// `scope_paths` สำหรับ skill ที่มี path เดียว ใช้ร่วมกันได้ (รวมชุด)
    #[serde(default)]
    pub scope_path: Option<String>,
    /// จำกัด file_open ใต้ path เหล่านี้ (H3 v2: เปิดได้เมื่ออยู่ใต้ตัวใด
    /// ตัวหนึ่ง) — สูงสุด [`crate::scope::MAX_PATH_PREFIXES`] ตัวรวม
    /// `scope_path`
    #[serde(default)]
    pub scope_paths: Vec<String>,
    /// operation class ที่ skill ต้องการ: `file`, `exec`, `net`
    /// (ค่าอื่นถูกละเว้น) — class ที่ไม่อยู่ในนี้จะถูกถอนออกจาก token grant
    #[serde(default)]
    pub allow: Vec<String>,
}

/// ส่วน frontmatter ของ skill manifest
#[derive(Debug, Clone, Deserialize)]
pub struct SkillManifest {
    /// ชื่อ skill (unique ใน registry)
    pub name: String,
    /// คำอธิบายความถนัด — ใช้เป็นสัญญาณ routing (จับคู่กับ intent)
    pub description: String,
    /// โมเดลที่ควรใช้ (placement hint เช่น "qwen2.5-3b-q4")
    #[serde(default)]
    pub model: Option<String>,
    /// compute target ที่แนะนำ: "cpu" | "gpu" | "npu"
    #[serde(default)]
    pub compute: Option<String>,
    /// ขอบเขตสิทธิ์ที่ kernel บังคับ
    #[serde(default)]
    pub capabilities: SkillCapabilities,
}

/// skill ที่โหลดแล้ว — frontmatter + เนื้อความ (instructions สำหรับโมเดล)
#[derive(Debug, Clone)]
pub struct Skill {
    /// ส่วน frontmatter ที่ machine อ่าน/บังคับ
    pub manifest: SkillManifest,
    /// เนื้อความหลัง frontmatter (prompt/instructions สำหรับโมเดล)
    pub instructions: String,
}

impl Skill {
    /// แปลง markdown ที่มี TOML frontmatter (`+++`) เป็น [`Skill`]
    ///
    /// # Errors
    /// คืน error หากไม่มี frontmatter, parse TOML ไม่ได้, หรือ manifest ไม่ valid
    pub fn parse(content: &str) -> Result<Self, SkillError> {
        let rest = content
            .strip_prefix("+++")
            .or_else(|| content.trim_start().strip_prefix("+++"))
            .ok_or(SkillError::MissingFrontmatter)?;
        let end = rest.find("+++").ok_or(SkillError::MissingFrontmatter)?;
        let frontmatter = &rest[..end];
        let instructions = rest[end + 3..].trim().to_string();

        let manifest: SkillManifest = toml::from_str(frontmatter)?;
        if manifest.name.trim().is_empty() {
            return Err(SkillError::Invalid("name must not be empty".to_string()));
        }
        if manifest.description.trim().is_empty() {
            return Err(SkillError::Invalid(
                "description must not be empty (routing signal)".to_string(),
            ));
        }
        Ok(Self {
            manifest,
            instructions,
        })
    }

    /// โหลด skill จากไฟล์
    ///
    /// # Errors
    /// คืน error หากอ่านไฟล์หรือ parse ไม่สำเร็จ
    pub fn load(path: &Path) -> Result<Self, SkillError> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// แปลง skill เป็น [`Intent`] ที่ป้อนเข้า `authorize_process_token_with_scope`
    /// (H3) — เนื่องจาก intent narrow ได้อย่างเดียว เราแปลง `allow` list
    /// (positive) เป็น `scope_no_*` (negative) โดยถอน class ที่ไม่ได้ประกาศ
    #[must_use]
    pub fn to_intent(&self) -> Intent {
        let allow = &self.manifest.capabilities.allow;
        let has = |names: &[&str]| names.iter().any(|n| allow.iter().any(|a| a == n));
        let wants_file = has(&["file", "file_open", "read", "write"]);
        let wants_exec = has(&["exec", "spawn"]);
        let wants_net = has(&["net", "socket"]);

        let mut intent = Intent::new(
            format!("skill:{}", self.manifest.name),
            IntentType::Structured,
            self.manifest.description.clone(),
            IntentPriority::Medium,
            "skill-manifest",
        );
        // ถอน class ที่ skill ไม่ได้ขอ (narrow token grant ลงเหลือเฉพาะที่ประกาศ)
        if !wants_file {
            intent = intent.with_metadata("scope_no_file", "1");
        }
        if !wants_exec {
            intent = intent.with_metadata("scope_no_exec", "1");
        }
        if !wants_net {
            intent = intent.with_metadata("scope_no_net", "1");
        }
        // รวม scope_path (เอกพจน์) + scope_paths (ชุด) เป็น metadata เดียว
        // คั่นด้วย newline ตาม convention ของ H3 v2 (scope.rs เป็นคน
        // validate/dedupe/จำกัดจำนวนตอน compile)
        let caps = &self.manifest.capabilities;
        let all_paths: Vec<&str> = caps
            .scope_path
            .iter()
            .map(String::as_str)
            .chain(caps.scope_paths.iter().map(String::as_str))
            .collect();
        if !all_paths.is_empty() {
            intent = intent.with_metadata("scope_path", all_paths.join("\n"));
        }
        intent
    }
}

/// ทะเบียน skill ที่โหลดจาก directory — ใช้เลือก specialist ตาม intent
#[derive(Debug, Default)]
pub struct SkillRegistry {
    skills: Vec<Skill>,
}

impl SkillRegistry {
    /// สร้าง registry เปล่า
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// โหลด skill ทุกไฟล์ `*.md` ในไดเรกทอรี — ไฟล์ที่ parse ไม่ผ่านจะถูก
    /// ข้าม (fail-open ต่อไฟล์เดียว) และนับไว้ใน error list ที่คืนกลับ
    ///
    /// # Errors
    /// คืน error หากเปิด directory ไม่ได้
    pub fn load_dir(dir: &Path) -> Result<(Self, Vec<(String, SkillError)>), SkillError> {
        let mut skills = Vec::new();
        let mut errors = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            match Skill::load(&path) {
                Ok(skill) => skills.push(skill),
                Err(e) => errors.push((path.display().to_string(), e)),
            }
        }
        Ok((Self { skills }, errors))
    }

    /// จำนวน skill ที่โหลด
    #[must_use]
    pub fn len(&self) -> usize {
        self.skills.len()
    }

    /// `true` หากไม่มี skill เลย
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    /// ค้น skill ตามชื่อ
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.iter().find(|s| s.manifest.name == name)
    }

    /// เลือก skill ที่เข้ากับ query มากที่สุดด้วยคะแนน keyword overlap อย่างง่าย
    /// (routing เฟสแรก — ต่อ NLP classifier ที่มีอยู่ได้ทีหลัง) คืน `None`
    /// หากไม่มี skill ใดมี token ตรงกับ query เลย
    #[must_use]
    pub fn route(&self, query: &str) -> Option<&Skill> {
        let q: Vec<String> = tokenize(query);
        let mut best: Option<(&Skill, usize)> = None;
        for skill in &self.skills {
            let hay = tokenize(&format!(
                "{} {}",
                skill.manifest.name, skill.manifest.description
            ));
            let score = q.iter().filter(|t| hay.contains(t)).count();
            if score > 0 && best.is_none_or(|(_, b)| score > b) {
                best = Some((skill, score));
            }
        }
        best.map(|(s, _)| s)
    }
}

/// แตกข้อความเป็น token ตัวพิมพ์เล็ก (ตัดอักขระที่ไม่ใช่ตัวอักษร/ตัวเลข)
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(|t| t.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"+++
name = "file-summarizer"
description = "สรุปเนื้อหาไฟล์ในโปรเจกต์ summarize project files"
model = "qwen2.5-3b-q4"
compute = "npu"

[capabilities]
scope_path = "/srv/project-x"
allow = ["file"]
+++
You are a file summarizer. Read files under the project and produce a concise summary.
"#;

    #[test]
    fn parses_frontmatter_and_body() {
        let skill = Skill::parse(SAMPLE).expect("parse");
        assert_eq!(skill.manifest.name, "file-summarizer");
        assert_eq!(skill.manifest.model.as_deref(), Some("qwen2.5-3b-q4"));
        assert_eq!(skill.manifest.compute.as_deref(), Some("npu"));
        assert_eq!(
            skill.manifest.capabilities.scope_path.as_deref(),
            Some("/srv/project-x")
        );
        assert!(skill.instructions.starts_with("You are a file summarizer"));
    }

    #[test]
    fn missing_frontmatter_is_rejected() {
        assert!(matches!(
            Skill::parse("no frontmatter here"),
            Err(SkillError::MissingFrontmatter)
        ));
    }

    #[test]
    fn to_intent_narrows_to_declared_classes_only() {
        // skill ขอแค่ file → intent ต้องถอน exec + net และตั้ง scope_path
        let skill = Skill::parse(SAMPLE).expect("parse");
        let intent = skill.to_intent();
        assert_eq!(
            intent.metadata.get("scope_no_exec").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            intent.metadata.get("scope_no_net").map(String::as_str),
            Some("1")
        );
        assert!(
            !intent.metadata.contains_key("scope_no_file"),
            "file was requested, must not be narrowed away"
        );
        assert_eq!(
            intent.metadata.get("scope_path").map(String::as_str),
            Some("/srv/project-x")
        );
    }

    #[test]
    fn skill_scope_compiles_through_h3() {
        // end-to-end ระดับ compile: skill → intent → IntentScope (H3)
        // token grant ครบทุก class, skill (ขอแค่ file + path) ต้อง narrow ลง
        use crate::scope::{IntentScope, SCOPE_FILE_OPEN};
        let skill = Skill::parse(SAMPLE).expect("parse");
        let intent = skill.to_intent();
        let scope = IntentScope::compile(&["read", "write", "exec", "net"], Some(&intent))
            .expect("compile");
        assert_eq!(
            scope.class_flags, SCOPE_FILE_OPEN,
            "only file_open must survive the skill's narrowing"
        );
        assert_eq!(scope.path_prefixes, vec!["/srv/project-x".to_string()]);
    }

    #[test]
    fn scope_paths_array_merges_with_scope_path() {
        // H3 v2: skill ประกาศได้ทั้ง scope_path เดี่ยวและ scope_paths ชุด —
        // ต้องรวมกันแล้ว compile เป็นชุด prefix เดียว
        use crate::scope::IntentScope;
        let manifest = r#"+++
name = "multi-path"
description = "works across data and cache dirs"
[capabilities]
scope_path = "/srv/data"
scope_paths = ["/var/cache/ank", "/srv/data"]
allow = ["file"]
+++
body"#;
        let skill = Skill::parse(manifest).expect("parse");
        let scope = IntentScope::compile(&["read"], Some(&skill.to_intent())).expect("compile");
        assert_eq!(scope.path_prefixes, vec!["/srv/data", "/var/cache/ank"]);
    }

    #[test]
    fn registry_routes_by_keyword_overlap() {
        let net_skill = r#"+++
name = "web-researcher"
description = "search the web and fetch pages over network"
[capabilities]
allow = ["net"]
+++
body"#;
        let mut reg = SkillRegistry::new();
        reg.skills.push(Skill::parse(SAMPLE).unwrap());
        reg.skills.push(Skill::parse(net_skill).unwrap());

        let routed = reg
            .route("please summarize the project files")
            .expect("route");
        assert_eq!(routed.manifest.name, "file-summarizer");
        let routed2 = reg.route("fetch a web page").expect("route");
        assert_eq!(routed2.manifest.name, "web-researcher");
        assert!(reg.route("xyzzy nothing matches zzz").is_none());
    }
}
