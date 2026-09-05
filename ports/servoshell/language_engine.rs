/* Copyright (C) 2026 Bumble Bee contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

//! Bumble Bee source-language front end.
//!
//! The browser engine executes JavaScript through Servo/SpiderMonkey. This
//! module therefore does not create a desktop UI or spawn another interpreter.
//! Instead it detects `.ts`, `.tss`, and `.inf/.infra` sources and lowers them
//! to JavaScript suitable for Servo's existing script engine.
//!
//! INFRA is deliberately a browser-engine dialect: desktop-only operations
//! from the original Python interpreter (Tkinter, winsound, PyInstaller and
//! subprocess) are not imported into the browser process. UI commands become
//! DOM operations and SOUND commands become browser-safe Web Audio operations.

use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceLanguage {
    JavaScript,
    TypeScript,
    Tss,
    Infra,
}

pub(crate) fn detect_language(path: Option<&Path>, source: &str) -> SourceLanguage {
    if let Some(extension) = path.and_then(|p| p.extension()).and_then(|e| e.to_str()) {
        match extension.to_ascii_lowercase().as_str() {
            "ts" => return SourceLanguage::TypeScript,
            "tss" => return SourceLanguage::Tss,
            "inf" | "infra" => return SourceLanguage::Infra,
            "js" | "mjs" | "cjs" => return SourceLanguage::JavaScript,
            _ => {}
        }
    }

    let trimmed = source.trim_start();
    if trimmed.starts_with("getlib ") || trimmed.starts_with("PACK") {
        SourceLanguage::Infra
    } else {
        SourceLanguage::JavaScript
    }
}

pub(crate) fn lower_to_javascript(
    path: Option<&Path>,
    source: &str,
) -> Result<String, String> {
    match detect_language(path, source) {
        SourceLanguage::JavaScript => Ok(source.to_owned()),
        SourceLanguage::TypeScript | SourceLanguage::Tss => lower_typescript(source),
        SourceLanguage::Infra => lower_infra(source),
    }
}

/// A deliberately conservative TypeScript-to-JavaScript lowering pass.
///
/// This is not advertised as a complete TypeScript compiler. It handles the
/// common browser-script subset without adding a second JavaScript runtime.
/// Unsupported TypeScript syntax is left intact so SpiderMonkey can report a
/// normal syntax error rather than silently changing program meaning.
fn lower_typescript(source: &str) -> Result<String, String> {
    let mut output = String::with_capacity(source.len());
    let mut skip_interface = false;
    let mut brace_depth = 0usize;

    for line in source.lines() {
        let trimmed = line.trim_start();

        if skip_interface {
            brace_depth = brace_depth
                .saturating_add(line.matches('{').count())
                .saturating_sub(line.matches('}').count());
            if brace_depth == 0 && line.contains('}') {
                skip_interface = false;
            }
            continue;
        }

        if trimmed.starts_with("interface ") || trimmed.starts_with("declare interface ") {
            skip_interface = true;
            brace_depth = line.matches('{').count().saturating_sub(line.matches('}').count());
            if brace_depth == 0 {
                skip_interface = false;
            }
            continue;
        }

        if trimmed.starts_with("type ") && trimmed.contains('=') {
            continue;
        }

        let mut line_out = line.to_owned();
        line_out = strip_typescript_assertions(&line_out);
        line_out = strip_parameter_and_variable_types(&line_out);
        output.push_str(&line_out);
        output.push('\n');
    }

    Ok(output)
}

fn strip_typescript_assertions(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' || bytes[i] == b'`' {
            let quote = bytes[i];
            let start = i;
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str(&line[start..i]);
            continue;
        }

        // `value as SomeType` -> `value`. This intentionally only removes
        // the assertion when the right side looks like a type identifier.
        if line[i..].starts_with(" as ") {
            i += 4;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || b"_.$<>[]| &".contains(&bytes[i]))
            {
                i += 1;
            }
            continue;
        }

        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn strip_parameter_and_variable_types(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == ':' {
            // Only treat a colon as a TS type annotation when it is followed
            // by a type-like token. Object-literal colons are preserved.
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            let start = j;
            while j < chars.len()
                && (chars[j].is_alphanumeric()
                    || "_.$[]<>| &".contains(chars[j]))
            {
                j += 1;
            }
            let type_text: String = chars[start..j].iter().collect();
            if !type_text.is_empty()
                && (j == chars.len() || matches!(chars[j], ',' | ')' | '=' | '{' | ';'))
                && !type_text.contains('.')
            {
                i = j;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    // Access modifiers are meaningless after lowering.
    for keyword in ["public ", "private ", "protected ", "readonly ", "abstract "] {
        out = out.replace(keyword, "");
    }
    out
}

fn lower_infra(source: &str) -> Result<String, String> {
    let mut js = String::from("// Bumble Bee INFRA engine\n(() => {\n");
    js.push_str("\"use strict\";\n");

    let mut memory = Vec::new();
    let mut saw_command = false;

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for command in line.split("//").map(str::trim).filter(|s| !s.is_empty()) {
            if command == "end" {
                continue;
            }
            saw_command = true;

            if command.starts_with("getlib ") {
                // Libraries are capabilities in the source language. The
                // browser implementation exposes only safe browser primitives.
                continue;
            }

            if command.starts_with("PACK") {
                return Err("INFRA PACK is disabled inside the browser engine; it would invoke an external compiler".to_owned());
            }

            if let Some(rest) = command.strip_prefix("send ") {
                js.push_str("console.log(");
                js.push_str(&infra_expression_to_js(rest, &memory));
                js.push_str(");\n");
                continue;
            }

            if let Some(rest) = command.strip_prefix("SAY ") {
                let text = extract_parenthesized(rest).unwrap_or_else(|| rest.trim().to_owned());
                js.push_str("console.log(");
                js.push_str(&js_string(&text));
                js.push_str(");\n");
                continue;
            }

            if command.starts_with("play frequency ") {
                let hz = extract_angle_after(command, "play frequency").unwrap_or(440);
                let ms = extract_angle_after(command, "for").unwrap_or(400);
                js.push_str(&format!("__infraBeep({}, {});\n", hz, ms));
                continue;
            }

            if let Some(rest) = command.strip_prefix("BG =") {
                if let Some(color) = extract_percent(rest) {
                    js.push_str("document.documentElement.style.backgroundColor=");
                    js.push_str(&js_string(&color));
                    js.push_str(";document.body.style.backgroundColor=");
                    js.push_str(&js_string(&color));
                    js.push_str(";\n");
                    continue;
                }
            }

            if command.starts_with("AT X") {
                if let Some(element_js) = lower_infra_ui(command) {
                    js.push_str(&element_js);
                    continue;
                }
            }

            if let Some((name, value)) = command.split_once('=') {
                let name = name.trim();
                if is_identifier(name) {
                    let value_js = infra_expression_to_js(value.trim(), &memory);
                    js.push_str("let ");
                    js.push_str(name);
                    js.push('=');
                    js.push_str(&value_js);
                    js.push_str(";\n");
                    memory.push(name.to_owned());
                    continue;
                }
            }

            return Err(format!("INFRA syntax error: unsupported command: {command}"));
        }
    }

    if !saw_command {
        return Err("INFRA source contains no executable commands".to_owned());
    }

    // Browser-safe tone primitive. No Windows API, Tkinter, subprocess or
    // external process is used. Audio is generated only when AudioContext is
    // available and the page permits it.
    js.push_str(
        "function __infraBeep(hz,ms){try{const C=window.AudioContext||window.webkitAudioContext;if(!C)return;const c=new C(),o=c.createOscillator(),g=c.createGain();o.frequency.value=Number(hz);g.gain.value=0.05;o.connect(g);g.connect(c.destination);o.start();o.stop(c.currentTime+Number(ms)/1000);}catch(_){}}\n",
    );
    js.push_str("})();\n");
    Ok(js)
}

fn lower_infra_ui(command: &str) -> Option<String> {
    let x = extract_angle_after(command, "AT X")?;
    let y = extract_angle_after(command, "Y")?;
    let size = command.split("CREATE <").nth(1)?.split('>').next()?;
    let (width, height) = size.to_ascii_uppercase().split_once('X')?;
    let text = command.split("WITH TEXT (").nth(1)?.split(')').next()?.trim();
    let bg = command.split("CLR=%").nth(1)?.split('%').next()?.trim();
    let fg = command.split("TXT CLR=%").nth(1)?.split('%').next()?.trim();

    let mut js = String::from("{const e=document.createElement('button');");
    js.push_str(&format!("e.textContent={};", js_string(text)));
    js.push_str(&format!("Object.assign(e.style,{{position:'absolute',left:'{}px',top:'{}px',width:'{}px',height:'{}px',background:{} ,color:{},border:'0'}});", x, y, width.trim(), height.trim(), js_string(bg), js_string(fg)));
    if let Some(click) = command.split("CLICK=").nth(1).and_then(|s| s.split("CLR=").next()) {
        let click = click.trim();
        if let Some(hz) = extract_angle_after(click, "play frequency") {
            let ms = extract_angle_after(click, "for").unwrap_or(400);
            js.push_str(&format!("e.addEventListener('click',()=>__infraBeep({},{}));", hz, ms));
        }
    }
    js.push_str("document.body.appendChild(e);}\n");
    Some(js)
}

fn infra_expression_to_js(value: &str, memory: &[String]) -> String {
    let value = value.trim();
    if value.starts_with('/') && value.ends_with('\\') {
        return value[1..value.len() - 1].trim().replace('<', "").replace('>', "");
    }
    if value.starts_with('<') && value.ends_with('>') {
        return value[1..value.len() - 1].trim().to_owned();
    }
    if value.starts_with('(') && value.ends_with(')') {
        return js_string(&value[1..value.len() - 1]);
    }
    if value.starts_with('{') && value.ends_with('}') {
        return if value[1..value.len() - 1].trim().eq_ignore_ascii_case("true") {
            "true".to_owned()
        } else {
            "false".to_owned()
        };
    }
    if value.starts_with('[') && value.ends_with(']') {
        let content = &value[1..value.len() - 1];
        let mut fields = Vec::new();
        for pair in content.split(',') {
            if let Some((k, v)) = pair.split_once(':') {
                fields.push(format!("{}:{}", js_string(k.trim()), infra_expression_to_js(v.trim(), memory)));
            }
        }
        return format!("{{{}}}", fields.join(","));
    }
    if memory.iter().any(|name| name == value) || value.parse::<f64>().is_ok() {
        return value.to_owned();
    }
    js_string(value)
}

fn extract_parenthesized(value: &str) -> Option<String> {
    Some(value.split_once('(')?.1.split_once(')')?.0.trim().to_owned())
}

fn extract_angle_after(value: &str, marker: &str) -> Option<i64> {
    let after = value.split_once(marker)?.1;
    let content = after.split_once('<')?.1.split_once('>')?.0.trim();
    content.parse().ok()
}

fn extract_percent(value: &str) -> Option<String> {
    let content = value.split_once('%')?.1.split_once('%')?.0.trim();
    Some(content.to_owned())
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn js_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects_extensions() {
        assert_eq!(detect_language(Some(Path::new("a.ts")), ""), SourceLanguage::TypeScript);
        assert_eq!(detect_language(Some(Path::new("a.tss")), ""), SourceLanguage::Tss);
        assert_eq!(detect_language(Some(Path::new("a.infra")), ""), SourceLanguage::Infra);
        assert_eq!(detect_language(Some(Path::new("a.js")), ""), SourceLanguage::JavaScript);
    }

    #[test]
    fn lowers_basic_typescript() {
        let js = lower_to_javascript(Some(Path::new("a.ts")), "const x: number = 3;\n").unwrap();
        assert!(js.contains("const x = 3;"));
    }

    #[test]
    fn lowers_infra_without_desktop_dependencies() {
        let infra = "getlib BASIC\ngetlib UI\nBG = %#ffffff%\nsend (hello)";
        let js = lower_to_javascript(Some(Path::new("a.infra")), infra).unwrap();
        assert!(js.contains("document.body.style.backgroundColor"));
        assert!(js.contains("console.log"));
        assert!(!js.contains("tkinter"));
        assert!(!js.contains("subprocess"));
    }
}
