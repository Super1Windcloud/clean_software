use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const UNINSTALL: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)] // 使用 Windows 标准缩写。
pub enum Hive {
    HKCU,
    HKLM,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum View {
    Registry32,
    Registry64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Location {
    pub hive: Hive,
    pub view: View,
    pub key: String,
}

impl Location {
    pub fn id(&self) -> String {
        format!(
            "{:?}/{}/{}",
            self.hive,
            if self.view == View::Registry64 {
                "64"
            } else {
                "32"
            },
            self.key
        )
    }
    pub fn validate(&self) -> Result<()> {
        validate_key_name(&self.key)
    }
}

pub fn validate_key_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !name.contains(['\\', '/', '\0', '\u{fffd}'])
            && name != "."
            && name != "..",
        "非法注册表子键名"
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RawValue {
    pub kind: u32,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Tree {
    pub values: BTreeMap<String, RawValue>,
    pub children: BTreeMap<String, Tree>,
}

impl Tree {
    pub fn value(&self, name: &str) -> Option<&RawValue> {
        self.values
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }
    pub fn string(&self, name: &str) -> Result<Option<String>> {
        let Some(value) = self.value(name) else {
            return Ok(None);
        };
        ensure!(
            matches!(value.kind, 1 | 2) && value.bytes.len() % 2 == 0,
            "{name} 类型/编码异常"
        );
        let units: Vec<_> = value
            .bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        let decoded = String::from_utf16(&units)?;
        let trimmed = decoded.trim_end_matches('\0');
        ensure!(!trimmed.contains('\0'), "{name} 含嵌入 NUL");
        Ok(Some(trimmed.trim().to_string()))
    }
    pub fn nonzero(&self, name: &str) -> bool {
        self.value(name).is_some_and(|value| {
            // 非标准类型也按保护标志处理，避免损坏的值解除保护。
            value.kind != 4 || value.bytes.len() != 4 || value.bytes != [0, 0, 0, 0]
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub location: Location,
    pub name: String,
    pub version: String,
    #[serde(skip)]
    pub tree: Tree,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Candidate,
    Review,
    Keep,
    Protected,
}
impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Candidate => "残留候选",
            Self::Review => "待核实",
            Self::Keep => "保留",
            Self::Protected => "受保护",
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    Present,
    Missing,
    Unknown,
}
impl PathState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Present => "存在",
            Self::Missing => "本地固定磁盘上不存在",
            Self::Unknown => "无法可靠判断",
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Evidence {
    pub field: String,
    pub source: String,
    pub state: PathState,
}
#[derive(Debug, Serialize)]
pub struct Assessment {
    pub id: String,
    pub entry: Entry,
    pub status: Status,
    pub reasons: Vec<String>,
    pub evidence: Vec<Evidence>,
}
