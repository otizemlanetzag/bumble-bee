/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Local pre-execution security gate for downloaded/injected source code.
//!
//! This is a defense-in-depth layer, not a malware detector. It performs no
//! network lookup and never sends source code outside the browser process.

mod execution_sandbox;

pub(crate) use execution_sandbox::{preflight, SandboxAction, SandboxResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScanAction {
    Allow,
    Block,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Finding {
    pub rule: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScanResult {
    pub action: ScanAction,
    pub findings: Vec<Finding>,
}

/// Run the scanner after the resource has been fetched and before language
/// lowering/execution. The sandbox preflight runs first so resource limits are
/// enforced even when a source contains no known malicious signature.
pub(crate) fn scan_source(source: &str) -> ScanResult {
    let mut findings = Vec::new();

    if let SandboxAction::Block = preflight(source).action {
        findings.push(Finding {
            rule: "execution-sandbox",
            reason: preflight(source)
                .reason
                .unwrap_or("Source rejected by the execution sandbox"),
        });
    }

    let normalized = normalize(source);

    match_pattern(&normalized, &mut findings, "dynamic-code", "eval(", "Dynamic code evaluation is blocked");
    match_pattern(&normalized, &mut findings, "dynamic-code", "function(", "Dynamic Function construction is blocked");
    match_pattern(&normalized, &mut findings, "javascript-url", "javascript:", "javascript: URLs are blocked");

    match_pattern(&normalized, &mut findings, "html-injection", ".innerhtml=", "innerHTML assignment is blocked by the pre-execution policy");
    match_pattern(&normalized, &mut findings, "html-injection", ".outerhtml=", "outerHTML assignment is blocked by the pre-execution policy");
    match_pattern(&normalized, &mut findings, "html-injection", "insertadjacenthtml(", "insertAdjacentHTML is blocked by the pre-execution policy");
    match_pattern(&normalized, &mut findings, "html-injection", "document.write(", "document.write is blocked by the pre-execution policy");

    match_pattern(&normalized, &mut findings, "script-url", "data:text/javascript", "data: JavaScript URLs are blocked");
    match_pattern(&normalized, &mut findings, "script-url", "blob:", "Blob URLs are blocked in source execution");

    match_pattern(&normalized, &mut findings, "native-escape", "child_process", "Native process APIs are unavailable to page code");
    match_pattern(&normalized, &mut findings, "native-escape", "require('child_process')", "Native process APIs are unavailable to page code");
    match_pattern(&normalized, &mut findings, "native-escape", "require(\"child_process\")", "Native process APIs are unavailable to page code");
    match_pattern(&normalized, &mut findings, "native-escape", "pyinstaller", "External compiler execution is blocked");
    match_pattern(&normalized, &mut findings, "native-escape", "subprocess", "External process execution is blocked");

    if normalized.contains("createelement('script')") || normalized.contains("createelement(\"script\")") {
        findings.push(Finding {
            rule: "script-injection",
            reason: "Dynamic script-element creation is blocked by the pre-execution policy",
        });
    }

    let action = if findings.is_empty() { ScanAction::Allow } else { ScanAction::Block };
    ScanResult { action, findings }
}

fn match_pattern(
    normalized: &str,
    findings: &mut Vec<Finding>,
    rule: &'static str,
    needle: &str,
    reason: &'static str,
) {
    if normalized.contains(needle) {
        findings.push(Finding { rule, reason });
    }
}

fn normalize(source: &str) -> String {
    source
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_source_is_allowed() {
        assert_eq!(scan_source("const x = 1; console.log(x);").action, ScanAction::Allow);
    }

    #[test]
    fn eval_is_blocked() {
        assert_eq!(scan_source("eval(userInput);").action, ScanAction::Block);
    }

    #[test]
    fn html_execution_sink_is_blocked() {
        assert_eq!(scan_source("node.innerHTML = input;").action, ScanAction::Block);
    }

    #[test]
    fn sandbox_limits_are_enforced() {
        let source = "x".repeat(execution_sandbox::MAX_SOURCE_BYTES + 1);
        assert_eq!(scan_source(&source).action, ScanAction::Block);
    }
}
