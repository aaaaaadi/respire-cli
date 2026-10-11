//! Convert a normalized [`Session`] into a protocol `MemoryEntry`.
//!
//! The body follows the mandatory `【前因】【行为】【后果】` three-marker
//! convention so recall renders it in full. Credentials embedded in transcripts
//! are scrubbed best-effort before storage (agent policy requires inspecting
//! content before writing; this is a safety net, not a scanner guarantee).

use chrono::{SecondsFormat, Utc};
use serde_json::Value;

use crate::memory::model::{Kind, MemoryEntry};

use super::Session;

/// Conversion knobs chosen by the CLI (`extract` flags).
#[derive(Debug, Clone)]
pub struct ConvertOptions {
    pub kind: Kind,
    /// `important` (reusable) or `trivial` (diary).
    pub importance: String,
    /// Optional causal parent for every imported memory.
    pub parent: String,
    pub user: String,
    /// Device tag (`host/os`).
    pub device: String,
    /// Explicit project override; empty → derived from the session cwd.
    pub project: String,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            kind: Kind::Context,
            importance: "important".to_owned(),
            parent: String::new(),
            user: "local".to_owned(),
            device: String::new(),
            project: String::new(),
        }
    }
}

/// Build one `MemoryEntry` from a session.
pub fn session_entry(session: &Session, opts: &ConvertOptions) -> MemoryEntry {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let created_at = session
        .created_at
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| now.clone());
    let updated_at = session
        .updated_at
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| created_at.clone());
    MemoryEntry {
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
        id: uuid::Uuid::new_v4().to_string(),
        kind: opts.kind,
        tags: vec!["session-import".to_owned(), session.platform.clone()],
        title: derive_title(session),
        content: scrub(&build_body(session)),
        user: opts.user.clone(),
        computer: opts.device.clone(),
        project: project_of(session, &opts.project),
        created_at,
        updated_at,
        emotion: -1.0,
        parent_id: opts.parent.clone(),
        importance: opts.importance.clone(),
        device: opts.device.clone(),
        modified_by: opts.device.clone(),
    }
}

/// Human-readable platform label.
fn platform_label(platform: &str) -> String {
    match platform {
        "codex" => "Codex".into(),
        "opencode" => "OpenCode".into(),
        "claude" => "Claude Code".into(),
        "senpi" => "Senpi".into(),
        "oh-my-pi" => "oh-my-pi".into(),
        "gajae-code" => "gajae-code".into(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => other.to_owned(),
            }
        }
    }
}

/// Session title: `<Platform> 会话 <first request>` (concise, event-shaped).
pub fn derive_title(session: &Session) -> String {
    let platform = platform_label(&session.platform);
    let snippet = first_line(&session.first_user_message);
    if snippet.is_empty() {
        format!("{platform} 会话 {}", short_id(&session.id))
    } else {
        format!("{platform} 会话 {snippet}")
    }
}

/// Assemble the `【前因】【行为】【后果】` body.
pub fn build_body(session: &Session) -> String {
    let cwd = session.cwd.as_deref().unwrap_or("未知");
    let model = match (session.provider.as_deref(), session.model.as_deref()) {
        (Some(provider), Some(model)) => format!("{provider}/{model}"),
        (Some(provider), None) => provider.to_owned(),
        (None, Some(model)) => model.to_owned(),
        (None, None) => "未知".to_owned(),
    };
    let created = session.created_at.as_deref().unwrap_or("未知");
    let updated = session.updated_at.as_deref().unwrap_or(created);

    let mut body = String::new();
    body.push_str(&format!(
        "【前因】{} 会话 {}。起始 {}；工作目录 {}；模型 {}。",
        platform_label(&session.platform),
        short_id(&session.id),
        created,
        cwd,
        model
    ));

    let first = truncate_chars(session.first_user_message.trim(), 600);
    body.push_str("\n【行为】");
    if first.is_empty() {
        body.push_str("（无用户消息记录）");
    } else {
        body.push_str(&first);
    }
    let last = session.last_user_message.trim();
    if !last.is_empty() && last != session.first_user_message.trim() {
        body.push_str(&format!("\n末次请求：{}", truncate_chars(last, 400)));
    }

    body.push_str(&format!("\n【后果】会话更新于 {updated}。"));
    if let Some(line) = usage_line(&session.usage) {
        body.push(' ');
        body.push_str(&line);
    }
    if let Some(agent) = session.agent.as_deref().filter(|s| !s.is_empty()) {
        body.push_str(&format!(" 由 `{agent}` 子代理执行"));
        if let Some(parent) = session.parent_id.as_deref().filter(|s| !s.is_empty()) {
            body.push_str(&format!("（父会话 {}）", short_id(parent)));
        }
        body.push('。');
    }
    body
}

fn usage_line(usage: &serde_json::Map<String, Value>) -> Option<String> {
    if usage.is_empty() {
        return None;
    }
    let number = |key: &str| -> Option<f64> { usage.get(key).and_then(Value::as_f64) };
    let mut parts = Vec::new();
    let total = number("totalTokens").or_else(|| number("total_tokens"));
    if let Some(total) = total {
        parts.push(format!("tokens {total:.0}"));
    } else {
        if let Some(input) = number("input") {
            parts.push(format!("输入 {input:.0}"));
        }
        if let Some(output) = number("output") {
            parts.push(format!("输出 {output:.0}"));
        }
    }
    if let Some(cost) = number("cost_total") {
        parts.push(format!("费用 {cost:.4}"));
    }
    if let Some(count) = number("message_count") {
        parts.push(format!("消息 {count:.0}"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("{}.", parts.join("；")))
    }
}

/// Resolve the project label: explicit override, else the cwd basename.
fn project_of(session: &Session, explicit: &str) -> String {
    if !explicit.trim().is_empty() {
        return explicit.trim().to_owned();
    }
    session
        .cwd
        .as_deref()
        .and_then(|cwd| cwd.trim_end_matches(['/', '\\']).rsplit(['/', '\\']).next())
        .filter(|name| !name.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| truncate_chars(&collapse_ws(line), 40))
        .unwrap_or_default()
}

fn collapse_ws(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        let mut out: String = text.chars().take(max).collect();
        out.push('…');
        out
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Best-effort credential scrub: PEM blocks, `key=value` secrets and known
/// token prefixes are redacted so plaintext secrets are not stored.
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_pem = false;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("begin") && lower.contains("private key") {
            in_pem = true;
            out.push_str("[已隐去私钥]");
            out.push('\n');
            continue;
        }
        if in_pem {
            if lower.contains("end") && lower.contains("private key") {
                in_pem = false;
            }
            continue;
        }
        out.push_str(&redact_line(line));
        out.push('\n');
    }
    if !text.ends_with('\n') {
        out.pop();
    }
    out
}

const SECRET_KEYS: [&str; 12] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "authorization",
    "bearer",
    "credential",
    "client_secret",
];

fn redact_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let hit = SECRET_KEYS
        .iter()
        .filter_map(|key| lower.find(key).map(|pos| (pos, key.len())))
        .min_by_key(|(pos, _)| *pos);
    if let Some((pos, len)) = hit {
        if let Some(separator) = line.find(['=', ':']) {
            let (head, _) = line.split_at(separator + 1);
            return format!("{head} ***");
        }
        let (head, _) = line.split_at(pos + len);
        return format!("{head} ***");
    }
    redact_prefixed_tokens(line)
}

const TOKEN_PREFIXES: [&str; 9] = ["sk-", "ghp_", "gho_", "ghs_", "xoxb-", "xoxp-", "AKIA", "AIza", "eyJ"];

fn redact_prefixed_tokens(line: &str) -> String {
    let mut result = String::new();
    let mut rest = line;
    loop {
        let mut earliest: Option<(usize, &str)> = None;
        for prefix in TOKEN_PREFIXES {
            if let Some(idx) = rest.find(prefix) {
                if earliest.map_or(true, |(best, _)| idx < best) {
                    earliest = Some((idx, prefix));
                }
            }
        }
        let Some((idx, prefix)) = earliest else {
            result.push_str(rest);
            break;
        };
        result.push_str(&rest[..idx]);
        let after = &rest[idx..];
        let run: String = after[prefix.len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if run.len() >= 8 {
            result.push_str(prefix);
            result.push_str("***");
        } else {
            result.push_str(prefix);
            result.push_str(&run);
        }
        rest = &after[prefix.len() + run.len()..];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Session {
        Session {
            platform: "codex".into(),
            id: "0199abcd-1234".into(),
            path: "path".into(),
            cwd: Some("/home/u/respire".into()),
            created_at: Some("2026-10-01T00:00:00Z".into()),
            updated_at: Some("2026-10-01T02:00:00Z".into()),
            provider: Some("openai".into()),
            model: Some("gpt-5".into()),
            first_user_message: "add an extract command".into(),
            last_user_message: "ship it".into(),
            usage: serde_json::json!({"total_tokens": 1234}).as_object().unwrap().clone(),
            parent_id: None,
            agent: None,
        }
    }

    #[test]
    fn builds_entry_with_three_markers_and_metadata() {
        let entry = session_entry(&sample(), &ConvertOptions::default());
        assert!(entry.content.contains("【前因】"));
        assert!(entry.content.contains("【行为】"));
        assert!(entry.content.contains("【后果】"));
        assert_eq!(entry.project, "respire");
        assert_eq!(entry.importance, "important");
        assert!(entry.title.starts_with("Codex 会话"));
        assert_eq!(entry.tags, vec!["session-import".to_owned(), "codex".to_owned()]);
    }

    #[test]
    fn scrub_redacts_secrets_and_pem() {
        let raw = "password=hunter2\nAuthorization: Bearer abcdef\ntoken=ghp_ABCDEFGHIJKLMNOP\nAKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        let clean = scrub(raw);
        assert!(!clean.contains("hunter2"));
        assert!(!clean.contains("ghp_ABCDEFGHIJKLMNOP"));
        assert!(!clean.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!clean.contains("MIIabc"));
        assert!(clean.contains("[已隐去私钥]"));
    }

    #[test]
    fn title_falls_back_to_id() {
        let mut s = sample();
        s.first_user_message = String::new();
        assert_eq!(derive_title(&s), format!("Codex 会话 {}", "0199abcd"));
    }
}
