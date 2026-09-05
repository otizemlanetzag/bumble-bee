/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Execution-sandbox policy used before untrusted source reaches SpiderMonkey.
//!
//! This is an in-process capability and resource boundary. It deliberately
//! does not claim to be an OS process sandbox: a real process/OS sandbox must
//! be added around the browser executable for protection against engine-level
//! memory-corruption bugs.

pub(crate) const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_LINE_BYTES: usize = 256 * 1024;
pub(crate) const MAX_NESTING_HINT: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SandboxAction {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SandboxResult {
    pub action: SandboxAction,
    pub reason: Option<&'static str>,
}

/// Enforce cheap deterministic limits before parsing/lowering.
///
/// These limits prevent oversized source and pathological nesting from being
/// handed to the scripting engine. They are intentionally conservative so a
/// malicious page cannot turn the security layer into an unbounded parser.
pub(crate) fn preflight(source: &str) -> SandboxResult {
    if source.len() > MAX_SOURCE_BYTES {
        return blocked("Source exceeds the execution sandbox size limit");
    }

    if source.lines().any(|line| line.len() > MAX_LINE_BYTES) {
        return blocked("A source line exceeds the execution sandbox line limit");
    }

    let mut depth = 0usize;
    let mut max_depth = 0usize;
    for byte in source.bytes() {
        match byte {
            b'{' | b'(' | b'[' => {
                depth = depth.saturating_add(1);
                max_depth = max_depth.max(depth);
                if max_depth > MAX_NESTING_HINT {
                    return blocked("Source nesting exceeds the execution sandbox limit");
                }
            }
            b'}' | b')' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    SandboxResult {
        action: SandboxAction::Allow,
        reason: None,
    }
}

fn blocked(reason: &'static str) -> SandboxResult {
    SandboxResult {
        action: SandboxAction::Block,
        reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_source_is_allowed() {
        assert_eq!(preflight("const x = {a: 1};").action, SandboxAction::Allow);
    }

    #[test]
    fn oversized_source_is_blocked() {
        let source = "x".repeat(MAX_SOURCE_BYTES + 1);
        assert_eq!(preflight(&source).action, SandboxAction::Block);
    }

    #[test]
    fn excessive_nesting_is_blocked() {
        let source = "(".repeat(MAX_NESTING_HINT + 1);
        assert_eq!(preflight(&source).action, SandboxAction::Block);
    }
}
