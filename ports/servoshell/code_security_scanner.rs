/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Local pre-execution scanner for downloaded/injected source code.
//!
//! This is a defense-in-depth gate, not a malware detector. It blocks or
//! quarantines high-risk browser escape patterns before source reaches the
//! language lowering layer. It performs no network lookup and sends no source
//! code anywhere.

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

pub(crate) fn scan_source(source: &str) -> ScanResult {
    let normalized = normalize(source);
    let mut findings = Vec::new();

    // Dynamic code generation is a frequent injection primitive. The browser
    // engine does not need these APIs for ordinary page scripts.
    match_pattern(&normalized, &mut findings, "dynamic-code", "eval(", "Dynamic code evaluation is blocked");
    match_pattern(&normalized, &mut findings, "dynamic-code", "function(", "Dynamic Function construction is blocked");

    // JavaScript URL execution can turn data supplied to a URL/DOM sink into
    // executable script.
    match_pattern(&normalized, &mut findings, "javascript-url", "javascript:", "javascript: URLs are blocked");

    // Common string-to-DOM execution sinks. textContent/DOM node creation is
    // intentionally not blocked because they do not parse HTML as script.
    match_pattern(&normalized, &mut findings, "html-injection", ".innerhtml=", "innerHTML assignment is blocked by the pre-execution policy");
    match_pattern(&normalized, &mut findings, "html-injection", ".outerhtml=", "outerHTML assignment is blocked by the pre-execution policy");
    match_pattern(&normalized, &mut findings, "html-injection", "insertadjacenthtml(", "insertAdjacentHTML is blocked by the pre-execution policy");
    match_pattern(&normalized, &mut findings, "html-injection", "document.write(", "document.write is blocked by the pre-execution policy");

    // Explicit attempts to execute a Blob/data URL as a script are rejected.
    match_pattern(&normalized, &mut findings, "script-url", "data:text/javascript", "data: JavaScript URLs are blocked");
    match_pattern(&normalized, &mut findings, "script-url", "blob:", "Blob URLs are blocked in source execution");

    // Browser-to-native escape mechanisms. These are especially important for
    // INFRA because its old desktop interpreter used subprocess/PyInstaller.
    match_pattern(&normalized, &mut findings, "native-escape", "child_process", "Native process APIs are unavailable to page code");
    match_pattern(&normalized, &mut findings, "native-escape", "require('child_process')", "Native process APIs are unavailable to page code");
    match_pattern(&normalized, &mut findings, "native-escape", "require(\"child_process\")", "Native process APIs are unavailable to page code");
    match_pattern(&normalized, &mut findings, "native-escape", "pyinstaller", "External compiler execution is blocked");
    match_pattern(&normalized, &mut findings, "native-escape", "subprocess", "External process execution is blocked");

    // Suspicious attempts to dynamically add executable script elements.
    if normalized.contains("createelement('script')") || normalized.contains("createelement(\"script\")") {
        findings.push(Finding {
            rule: "script-injection",
            reason: "Dynamic script-element creation is blocked by the pre-execution policy",
        });
    }

    let action = if findings.is_empty() {
        ScanAction::Allow
    } else {
        ScanAction::Block
    };

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
    fn infra_native_escape_is_blocked() {
        assert_eq!(scan_source("PACK").action, ScanAction::Allow);
        assert_eq!(scan_source("subprocess.run(command)").action, ScanAction::Block);
    }
}
