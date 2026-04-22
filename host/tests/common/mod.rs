// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Taktflow Systems

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
};

#[derive(Clone, Debug)]
pub struct RspCase {
    #[allow(dead_code)]
    pub section: Option<String>,
    pub fields: BTreeMap<String, String>,
}

pub fn load_rsp(path: impl AsRef<Path>) -> Vec<RspCase> {
    let text = fs::read_to_string(path).expect("failed to read .rsp file");
    let mut cases = Vec::new();
    let mut section: Option<String> = None;
    let mut defaults = BTreeMap::new();
    let mut current = BTreeMap::new();

    fn is_case(fields: &BTreeMap<String, String>) -> bool {
        fields.contains_key("COUNT") || fields.contains_key("Count") || fields.contains_key("Len")
    }

    fn flush_block(
        section: &Option<String>,
        defaults: &mut BTreeMap<String, String>,
        current: &mut BTreeMap<String, String>,
        cases: &mut Vec<RspCase>,
    ) {
        if current.is_empty() {
            return;
        }

        if is_case(current) {
            let mut merged = defaults.clone();
            merged.extend(current.clone());
            cases.push(RspCase {
                section: section.clone(),
                fields: merged,
            });
        } else {
            defaults.extend(current.clone());
        }

        current.clear();
    }

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            flush_block(&section, &mut defaults, &mut current, &mut cases);
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush_block(&section, &mut defaults, &mut current, &mut cases);
            section = Some(line[1..line.len() - 1].trim().to_owned());
            defaults.clear();
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            current.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }

    flush_block(&section, &mut defaults, &mut current, &mut cases);
    cases
}

pub fn field<'a>(case: &'a RspCase, name: &str) -> &'a str {
    case.fields
        .get(name)
        .unwrap_or_else(|| panic!("missing field `{name}` in {case:?}"))
}

pub fn hex_field(case: &RspCase, name: &str) -> Vec<u8> {
    hex::decode(field(case, name)).unwrap_or_else(|e| {
        panic!("failed to decode hex field `{name}` in {case:?}: {e}")
    })
}
