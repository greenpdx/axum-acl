//! Axum endpoint parser with ACL rule extraction.
//!
//! Finds all endpoints and their associated ACL rules.
//!
//! Output format:
//!   endpoint METHOD  role, id, ip, time | action
//!   * = any/wildcard
//!
//! Usage:
//!   cargo run --bin endpoint_parser -- [OPTIONS] <directory>
//!
//! Options:
//!   --ast    Use AST-based parsing (requires --features ast-parser)
//!   --text   Use text-based parsing (default)
//!   --help   Show help

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// A discovered endpoint
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    pub line: usize,
}

/// An ACL rule extracted from code
#[derive(Debug, Clone)]
pub struct AclRule {
    pub pattern: String,       // exact path, prefix, glob, or "*" for any
    pub pattern_type: String,  // "exact", "prefix", "glob", "any"
    pub role_mask: String,     // "*" or bitmask like "0b001"
    pub id: String,            // "*" or specific id
    pub ip: String,            // "*" or IP/CIDR
    pub time: String,          // "*" or time window
    pub action: String,        // "allow", "deny", or custom
    pub file: String,
    pub line: usize,
}

impl AclRule {
    fn matches_path(&self, path: &str) -> bool {
        match self.pattern_type.as_str() {
            "any" => true,
            "exact" => self.pattern == path,
            "prefix" => path.starts_with(&self.pattern),
            "glob" => self.glob_matches(path),
            _ => false,
        }
    }

    fn glob_matches(&self, path: &str) -> bool {
        let pattern = &self.pattern;
        if pattern.contains("**") {
            // ** matches any path segments
            let prefix = pattern.split("**").next().unwrap_or("");
            path.starts_with(prefix)
        } else if pattern.contains('*') {
            // * matches single segment
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                path.starts_with(parts[0]) && path.ends_with(parts[1])
            } else {
                false
            }
        } else {
            self.pattern == path
        }
    }
}

/// Parsing mode
#[derive(Debug, Clone, Copy, PartialEq)]
enum ParseMode {
    Text,
    Ast,
}

/// Output format
#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputFormat {
    Table,
    Csv,
    Toml,
}

// ============================================================================
// Text-based Parser
// ============================================================================

mod text_parser {
    use super::*;

    pub struct TextParser {
        pub endpoints: Vec<Endpoint>,
        pub acl_rules: Vec<AclRule>,
        pending_nests: Vec<(String, String, String, usize)>,
        router_fns: HashMap<String, (String, String, usize)>,
    }

    impl TextParser {
        pub fn new() -> Self {
            Self {
                endpoints: Vec::new(),
                acl_rules: Vec::new(),
                pending_nests: Vec::new(),
                router_fns: HashMap::new(),
            }
        }

        pub fn parse_dir(&mut self, dir: &Path) {
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.parse_dir(&path);
                } else if path.extension().map_or(false, |e| e == "rs") {
                    self.parse_file(&path);
                }
            }
        }

        fn parse_file(&mut self, path: &Path) {
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return,
            };

            let file_str = path.to_string_lossy().to_string();
            let lines: Vec<&str> = content.lines().collect();

            self.find_router_functions(&lines, &file_str);
            self.find_routes(&lines, &file_str, "");
            self.find_acl_rules(&lines, &file_str);
        }

        fn find_router_functions(&mut self, lines: &[&str], file: &str) {
            let mut i = 0;
            while i < lines.len() {
                let line = lines[i];

                if let Some(fn_name) = self.extract_fn_name(line) {
                    let mut sig_lines = vec![line.to_string()];
                    let mut j = i + 1;
                    let mut found_brace = line.contains('{');

                    while j < lines.len() && j < i + 10 && !found_brace {
                        sig_lines.push(lines[j].to_string());
                        if lines[j].contains('{') {
                            found_brace = true;
                        }
                        j += 1;
                    }

                    let signature = sig_lines.join(" ");
                    if signature.contains("-> Router") {
                        if let Some((start, end)) = self.find_fn_body(lines, i) {
                            let body: String = lines[start..=end].join("\n");
                            self.router_fns.insert(fn_name, (file.to_string(), body, i + 1));
                        }
                    }
                }
                i += 1;
            }
        }

        fn extract_fn_name(&self, line: &str) -> Option<String> {
            let trimmed = line.trim();
            let fn_pos = trimmed.find("fn ")?;
            let after_fn = &trimmed[fn_pos + 3..];
            let name_end = after_fn.find(|c| c == '(' || c == '<')?;
            let name = after_fn[..name_end].trim();

            if name.is_empty() || name == "main" {
                return None;
            }
            Some(name.to_string())
        }

        fn find_fn_body(&self, lines: &[&str], start: usize) -> Option<(usize, usize)> {
            let mut brace_count = 0;
            let mut body_start = start;
            let mut started = false;

            for i in start..lines.len() {
                for ch in lines[i].chars() {
                    if ch == '{' {
                        if !started {
                            body_start = i;
                            started = true;
                        }
                        brace_count += 1;
                    } else if ch == '}' {
                        brace_count -= 1;
                        if started && brace_count == 0 {
                            return Some((body_start, i));
                        }
                    }
                }
            }
            None
        }

        fn find_routes(&mut self, lines: &[&str], file: &str, prefix: &str) {
            for (line_num, line) in lines.iter().enumerate() {
                self.extract_routes_from_line(line, file, line_num + 1, prefix);

                if let Some((nest_prefix, nested)) = self.extract_nest(line) {
                    let full_prefix = format!("{}{}", prefix, nest_prefix);
                    self.pending_nests.push((full_prefix, nested, file.to_string(), line_num + 1));
                }
            }
        }

        fn extract_routes_from_line(&mut self, line: &str, file: &str, line_num: usize, prefix: &str) {
            let mut search_pos = 0;
            while let Some(pos) = line[search_pos..].find(".route(") {
                let actual_pos = search_pos + pos;
                let after_route = &line[actual_pos + 7..];

                if let Some(path) = self.extract_string_literal(after_route) {
                    let full_path = format!("{}{}", prefix, path);
                    let methods = ["get", "post", "put", "delete", "patch", "head", "options", "trace"];

                    for method in &methods {
                        if let Some(handler) = self.extract_method_handler(after_route, method) {
                            self.endpoints.push(Endpoint {
                                method: method.to_uppercase(),
                                path: full_path.clone(),
                                handler,
                                file: file.to_string(),
                                line: line_num,
                            });
                        }
                    }
                }
                search_pos = actual_pos + 7;
            }
        }

        fn extract_string_literal(&self, text: &str) -> Option<String> {
            let q1 = text.find('"')?;
            let after_q1 = &text[q1 + 1..];
            let q2 = after_q1.find('"')?;
            Some(after_q1[..q2].to_string())
        }

        fn extract_method_handler(&self, text: &str, method: &str) -> Option<String> {
            let pattern = format!("{}(", method);
            let pos = text.find(&pattern)?;
            let after = &text[pos + pattern.len()..];
            let end = after.find(|c| c == ')' || c == '.')?;
            let handler = after[..end].trim();

            if handler.is_empty() || handler.starts_with('|') || handler.starts_with('{') {
                return None;
            }
            Some(handler.to_string())
        }

        fn extract_nest(&self, line: &str) -> Option<(String, String)> {
            let nest_pos = line.find(".nest(")?;
            let after_nest = &line[nest_pos + 6..];

            let prefix = self.extract_string_literal(after_nest)?;

            let q1 = after_nest.find('"')?;
            let q2 = after_nest[q1 + 1..].find('"')?;
            let after_prefix = &after_nest[q1 + q2 + 2..];

            let comma = after_prefix.find(',')?;
            let after_comma = after_prefix[comma + 1..].trim();

            let name_end = after_comma.find(|c: char| c == '(' || c == ')' || c.is_whitespace())?;
            let router_name = after_comma[..name_end].trim();

            if router_name.is_empty() {
                return None;
            }
            Some((prefix, router_name.to_string()))
        }

        /// Find ACL rules in the code
        fn find_acl_rules(&mut self, lines: &[&str], file: &str) {
            let full_content = lines.join("\n");

            // Find .add_exact, .add_prefix, .add_glob, .add_any patterns
            self.extract_add_exact_rules(&full_content, file);
            self.extract_add_prefix_rules(&full_content, file);
            self.extract_add_glob_rules(&full_content, file);
            self.extract_add_any_rules(&full_content, file);
        }

        fn extract_add_exact_rules(&mut self, content: &str, file: &str) {
            let mut pos = 0;
            while let Some(start) = content[pos..].find(".add_exact(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;

                let after = &content[actual_start + 11..];
                if let Some(path) = self.extract_string_literal(after) {
                    let rule = self.extract_rule_filter(after, "exact", &path, file, line_num);
                    self.acl_rules.push(rule);
                }
                pos = actual_start + 11;
            }
        }

        fn extract_add_prefix_rules(&mut self, content: &str, file: &str) {
            let mut pos = 0;
            while let Some(start) = content[pos..].find(".add_prefix(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;

                let after = &content[actual_start + 12..];
                if let Some(path) = self.extract_string_literal(after) {
                    let rule = self.extract_rule_filter(after, "prefix", &path, file, line_num);
                    self.acl_rules.push(rule);
                }
                pos = actual_start + 12;
            }
        }

        fn extract_add_glob_rules(&mut self, content: &str, file: &str) {
            let mut pos = 0;
            while let Some(start) = content[pos..].find(".add_glob(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;

                let after = &content[actual_start + 10..];
                if let Some(path) = self.extract_string_literal(after) {
                    let rule = self.extract_rule_filter(after, "glob", &path, file, line_num);
                    self.acl_rules.push(rule);
                }
                pos = actual_start + 10;
            }
        }

        fn extract_add_any_rules(&mut self, content: &str, file: &str) {
            let mut pos = 0;
            while let Some(start) = content[pos..].find(".add_any(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;

                let after = &content[actual_start + 9..];
                let rule = self.extract_rule_filter(after, "any", "*", file, line_num);
                self.acl_rules.push(rule);
                pos = actual_start + 9;
            }
        }

        fn extract_rule_filter(&self, text: &str, pattern_type: &str, pattern: &str, file: &str, line: usize) -> AclRule {
            let role_mask = self.extract_role_mask(text);
            let id = self.extract_id_filter(text);
            let ip = self.extract_ip_filter(text);
            let time = self.extract_time_filter(text);
            let action = self.extract_action(text);

            AclRule {
                pattern: pattern.to_string(),
                pattern_type: pattern_type.to_string(),
                role_mask,
                id,
                ip,
                time,
                action,
                file: file.to_string(),
                line,
            }
        }

        fn extract_role_mask(&self, text: &str) -> String {
            // Look for .role_mask(value) or role_mask: value
            if let Some(pos) = text.find(".role_mask(") {
                let after = &text[pos + 11..];
                if let Some(end) = after.find(')') {
                    let value = after[..end].trim();
                    if value == "u32::MAX" {
                        return "*".to_string();
                    }
                    return value.to_string();
                }
            }
            "*".to_string()
        }

        fn extract_id_filter(&self, text: &str) -> String {
            // Look for .id("value")
            if let Some(pos) = text.find(".id(") {
                let after = &text[pos + 4..];
                if let Some(id) = self.extract_string_literal(after) {
                    return id;
                }
            }
            "*".to_string()
        }

        fn extract_ip_filter(&self, text: &str) -> String {
            // Look for .ip(IpMatcher::parse("..."))
            if let Some(pos) = text.find(".ip(") {
                let after = &text[pos + 4..];
                if let Some(ip) = self.extract_string_literal(after) {
                    return ip;
                }
            }
            "*".to_string()
        }

        fn extract_time_filter(&self, text: &str) -> String {
            // Look for .time(TimeWindow::...)
            if let Some(pos) = text.find(".time(") {
                let after = &text[pos + 6..];
                // Extract the TimeWindow pattern
                if after.contains("hours_on_days") {
                    // Try to extract hours and days
                    if let Some(paren) = after.find('(') {
                        let params = &after[paren + 1..];
                        if let Some(end) = params.find(')') {
                            let args = &params[..end];
                            return format!("hours_on_days({})", args.split(',').take(2).collect::<Vec<_>>().join(","));
                        }
                    }
                } else if after.contains("hours(") {
                    if let Some(paren) = after.find("hours(") {
                        let params = &after[paren + 6..];
                        if let Some(end) = params.find(')') {
                            return format!("hours({})", &params[..end]);
                        }
                    }
                }
                return "custom".to_string();
            }
            "*".to_string()
        }

        fn extract_action(&self, text: &str) -> String {
            // Look for .action(...) and extract the value
            if let Some(pos) = text.find(".action(") {
                let after = &text[pos + 8..];
                // Find matching closing paren, handling nested parens
                let mut depth = 1;
                let mut end = 0;
                for (i, ch) in after.chars().enumerate() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if end > 0 {
                    let action_str = after[..end].trim();
                    // Clean up common patterns
                    let action = action_str
                        .replace("AclAction::", "")
                        .replace("Action::", "")
                        .trim()
                        .to_string();

                    // For complex actions like Error { code: 403, ... }, simplify
                    if action.starts_with("Error") {
                        if let Some(code) = self.extract_error_code(&action) {
                            return format!("error({})", code);
                        }
                        return "error".to_string();
                    }
                    if action.starts_with("Reroute") || action.starts_with("reroute") {
                        if let Some(target) = self.extract_string_literal(&action) {
                            return format!("reroute({})", target);
                        }
                        return "reroute".to_string();
                    }
                    // Return as-is for custom actions
                    return action.to_lowercase();
                }
            }
            "*".to_string() // no action specified = default
        }

        fn extract_error_code(&self, text: &str) -> Option<String> {
            // Look for code: 403 or code = 403
            if let Some(pos) = text.find("code") {
                let after = &text[pos + 4..];
                let after = after.trim_start_matches(|c| c == ':' || c == '=' || c == ' ');
                let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
                if end > 0 {
                    return Some(after[..end].to_string());
                }
            }
            None
        }

        pub fn resolve_nests(&mut self) {
            let mut iterations = 0;

            while !self.pending_nests.is_empty() && iterations < 10 {
                let nests: Vec<_> = self.pending_nests.drain(..).collect();

                for (prefix, fn_name, _file, _line) in nests {
                    if let Some((file, content, start_line)) = self.router_fns.get(&fn_name).cloned() {
                        let lines: Vec<&str> = content.lines().collect();

                        for (offset, line) in lines.iter().enumerate() {
                            self.extract_routes_from_line(line, &file, start_line + offset, &prefix);

                            if let Some((nest_prefix, nested)) = self.extract_nest(line) {
                                let full_prefix = format!("{}{}", prefix, nest_prefix);
                                self.pending_nests.push((full_prefix, nested, file.clone(), start_line + offset));
                            }
                        }
                    }
                }
                iterations += 1;
            }
        }

        pub fn router_fn_count(&self) -> usize {
            self.router_fns.len()
        }
    }
}

// ============================================================================
// AST-based Parser (requires ast-parser feature)
// ============================================================================

#[cfg(feature = "ast-parser")]
mod ast_parser {
    use super::*;
    use syn::{
        visit::Visit, Expr, ExprCall, ExprMethodCall, ExprPath, File, ItemFn, Lit, ReturnType,
        Type, TypePath,
    };

    pub struct AstParser {
        pub endpoints: Vec<Endpoint>,
        pub acl_rules: Vec<AclRule>,
        current_file: String,
        router_fns: HashMap<String, (String, String, usize)>,
        pending_nests: Vec<(String, String)>,
    }

    impl AstParser {
        pub fn new() -> Self {
            Self {
                endpoints: Vec::new(),
                acl_rules: Vec::new(),
                current_file: String::new(),
                router_fns: HashMap::new(),
                pending_nests: Vec::new(),
            }
        }

        pub fn parse_dir(&mut self, dir: &Path) {
            let entries = match fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    self.parse_dir(&path);
                } else if path.extension().map_or(false, |e| e == "rs") {
                    self.parse_file(&path);
                }
            }
        }

        fn parse_file(&mut self, path: &Path) {
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => return,
            };

            self.current_file = path.to_string_lossy().to_string();

            // Also do text-based ACL rule extraction
            let lines: Vec<&str> = content.lines().collect();
            self.extract_acl_rules_text(&lines);

            let syntax: File = match syn::parse_file(&content) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to parse {}: {}", path.display(), e);
                    return;
                }
            };

            for item in &syntax.items {
                if let syn::Item::Fn(func) = item {
                    if self.returns_router(func) && func.sig.ident != "main" {
                        let fn_name = func.sig.ident.to_string();
                        let start_line = func.sig.ident.span().start().line;
                        let fn_content = quote::quote!(#func).to_string();
                        self.router_fns.insert(
                            fn_name,
                            (self.current_file.clone(), fn_content, start_line),
                        );
                    }
                }
            }

            self.visit_file(&syntax);
        }

        fn extract_acl_rules_text(&mut self, lines: &[&str]) {
            let content = lines.join("\n");
            let file = self.current_file.clone();

            // Reuse text parser logic for ACL rules
            let mut pos = 0;
            while let Some(start) = content[pos..].find(".add_exact(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;
                let after = &content[actual_start + 11..];
                if let Some(path) = self.extract_string_literal(after) {
                    let rule = self.extract_rule_filter(after, "exact", &path, &file, line_num);
                    self.acl_rules.push(rule);
                }
                pos = actual_start + 11;
            }

            pos = 0;
            while let Some(start) = content[pos..].find(".add_prefix(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;
                let after = &content[actual_start + 12..];
                if let Some(path) = self.extract_string_literal(after) {
                    let rule = self.extract_rule_filter(after, "prefix", &path, &file, line_num);
                    self.acl_rules.push(rule);
                }
                pos = actual_start + 12;
            }

            pos = 0;
            while let Some(start) = content[pos..].find(".add_any(") {
                let actual_start = pos + start;
                let line_num = content[..actual_start].matches('\n').count() + 1;
                let after = &content[actual_start + 9..];
                let rule = self.extract_rule_filter(after, "any", "*", &file, line_num);
                self.acl_rules.push(rule);
                pos = actual_start + 9;
            }
        }

        fn extract_string_literal(&self, text: &str) -> Option<String> {
            let q1 = text.find('"')?;
            let after_q1 = &text[q1 + 1..];
            let q2 = after_q1.find('"')?;
            Some(after_q1[..q2].to_string())
        }

        fn extract_rule_filter(&self, text: &str, pattern_type: &str, pattern: &str, file: &str, line: usize) -> AclRule {
            AclRule {
                pattern: pattern.to_string(),
                pattern_type: pattern_type.to_string(),
                role_mask: self.extract_role_mask(text),
                id: self.extract_id_filter(text),
                ip: self.extract_ip_filter(text),
                time: self.extract_time_filter(text),
                action: self.extract_action(text),
                file: file.to_string(),
                line,
            }
        }

        fn extract_role_mask(&self, text: &str) -> String {
            if let Some(pos) = text.find(".role_mask(") {
                let after = &text[pos + 11..];
                if let Some(end) = after.find(')') {
                    let value = after[..end].trim();
                    if value == "u32::MAX" { return "*".to_string(); }
                    return value.to_string();
                }
            }
            "*".to_string()
        }

        fn extract_id_filter(&self, text: &str) -> String {
            if let Some(pos) = text.find(".id(") {
                let after = &text[pos + 4..];
                if let Some(id) = self.extract_string_literal(after) {
                    return id;
                }
            }
            "*".to_string()
        }

        fn extract_ip_filter(&self, text: &str) -> String {
            if let Some(pos) = text.find(".ip(") {
                let after = &text[pos + 4..];
                if let Some(ip) = self.extract_string_literal(after) {
                    return ip;
                }
            }
            "*".to_string()
        }

        fn extract_time_filter(&self, text: &str) -> String {
            if text.contains(".time(") {
                if text.contains("hours_on_days") {
                    return "business_hours".to_string();
                } else if text.contains("hours(") {
                    return "hours".to_string();
                }
                return "custom".to_string();
            }
            "*".to_string()
        }

        fn extract_action(&self, text: &str) -> String {
            // Look for .action(...) and extract the value
            if let Some(pos) = text.find(".action(") {
                let after = &text[pos + 8..];
                let mut depth = 1;
                let mut end = 0;
                for (i, ch) in after.chars().enumerate() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if end > 0 {
                    let action = after[..end].trim()
                        .replace("AclAction::", "")
                        .replace("Action::", "")
                        .to_lowercase();
                    if action.starts_with("error") {
                        return "error".to_string();
                    }
                    if action.starts_with("reroute") {
                        return "reroute".to_string();
                    }
                    return action;
                }
            }
            "*".to_string()
        }

        fn returns_router(&self, func: &ItemFn) -> bool {
            match &func.sig.output {
                ReturnType::Type(_, ty) => self.is_router_type(ty),
                ReturnType::Default => false,
            }
        }

        fn is_router_type(&self, ty: &Type) -> bool {
            if let Type::Path(TypePath { path, .. }) = ty {
                if let Some(segment) = path.segments.last() {
                    return segment.ident == "Router";
                }
            }
            false
        }

        pub fn resolve_nests(&mut self) {
            // Similar to text parser
        }

        pub fn router_fn_count(&self) -> usize {
            self.router_fns.len()
        }
    }

    impl<'ast> Visit<'ast> for AstParser {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            let method_name = node.method.to_string();

            if method_name == "route" && node.args.len() >= 2 {
                if let Some(path) = self.extract_lit_str(&node.args[0]) {
                    let line = node.method.span().start().line;
                    self.extract_handlers_from_expr(&node.args[1], &path, line);
                }
            }

            if method_name == "nest" && node.args.len() >= 2 {
                if let Some(prefix) = self.extract_lit_str(&node.args[0]) {
                    if let Some(fn_name) = self.extract_fn_call_name(&node.args[1]) {
                        self.pending_nests.push((prefix, fn_name));
                    }
                }
            }

            syn::visit::visit_expr_method_call(self, node);
        }
    }

    impl AstParser {
        fn extract_lit_str(&self, expr: &Expr) -> Option<String> {
            if let Expr::Lit(expr_lit) = expr {
                if let Lit::Str(lit_str) = &expr_lit.lit {
                    return Some(lit_str.value());
                }
            }
            None
        }

        fn extract_fn_call_name(&self, expr: &Expr) -> Option<String> {
            match expr {
                Expr::Call(ExprCall { func, .. }) => {
                    if let Expr::Path(ExprPath { path, .. }) = func.as_ref() {
                        if let Some(seg) = path.segments.last() {
                            return Some(seg.ident.to_string());
                        }
                    }
                    None
                }
                Expr::Path(ExprPath { path, .. }) => {
                    path.segments.last().map(|s| s.ident.to_string())
                }
                _ => None,
            }
        }

        fn extract_handlers_from_expr(&mut self, expr: &Expr, path: &str, line: usize) {
            let methods = ["get", "post", "put", "delete", "patch", "head", "options", "trace"];

            match expr {
                Expr::Call(call) => {
                    if let Expr::Path(ExprPath { path: fn_path, .. }) = call.func.as_ref() {
                        if let Some(seg) = fn_path.segments.last() {
                            let method = seg.ident.to_string();
                            if methods.contains(&method.as_str()) {
                                if let Some(handler) = self.extract_handler_name(&call.args) {
                                    self.endpoints.push(Endpoint {
                                        method: method.to_uppercase(),
                                        path: path.to_string(),
                                        handler,
                                        file: self.current_file.clone(),
                                        line,
                                    });
                                }
                            }
                        }
                    }
                }
                Expr::MethodCall(method_call) => {
                    let method = method_call.method.to_string();
                    if methods.contains(&method.as_str()) {
                        if let Some(handler) = self.extract_handler_name(&method_call.args) {
                            self.endpoints.push(Endpoint {
                                method: method.to_uppercase(),
                                path: path.to_string(),
                                handler,
                                file: self.current_file.clone(),
                                line,
                            });
                        }
                    }
                    self.extract_handlers_from_expr(&method_call.receiver, path, line);
                }
                _ => {}
            }
        }

        fn extract_handler_name(&self, args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>) -> Option<String> {
            if let Some(first_arg) = args.first() {
                if let Expr::Path(ExprPath { path, .. }) = first_arg {
                    return Some(path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"));
                }
            }
            None
        }
    }
}

// ============================================================================
// Output formatting
// ============================================================================

fn print_results(endpoints: &[Endpoint], acl_rules: &[AclRule], format: OutputFormat) {
    if endpoints.is_empty() {
        println!("\nNo endpoints found.");
        return;
    }

    match format {
        OutputFormat::Table => print_table(endpoints, acl_rules),
        OutputFormat::Csv => print_csv(endpoints, acl_rules),
        OutputFormat::Toml => print_toml(endpoints, acl_rules),
    }
}

fn print_table(endpoints: &[Endpoint], acl_rules: &[AclRule]) {
    println!("\n{:<30} {:<7}  {:>10}, {:>4}, {:>12}, {:>8} | {:<6}  {:<20} {}",
        "ENDPOINT", "METHOD", "ROLE", "ID", "IP", "TIME", "ACTION", "HANDLER", "LOCATION");
    println!("{}", "-".repeat(120));

    let mut sorted_endpoints = endpoints.to_vec();
    sorted_endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    for ep in &sorted_endpoints {
        let matching_rules: Vec<&AclRule> = acl_rules.iter()
            .filter(|r| r.matches_path(&ep.path))
            .collect();

        let location = format!("{}:{}", short_path(&ep.file), ep.line);

        if matching_rules.is_empty() {
            println!("{:<30} {:<7}  {:>10}, {:>4}, {:>12}, {:>8} | {:<6}  {:<20} {}",
                truncate(&ep.path, 30),
                &ep.method,
                "*", "*", "*", "*",
                "allow",
                truncate(&ep.handler, 20),
                location
            );
        } else {
            let rule = matching_rules[0];
            println!("{:<30} {:<7}  {:>10}, {:>4}, {:>12}, {:>8} | {:<6}  {:<20} {}",
                truncate(&ep.path, 30),
                &ep.method,
                truncate(&rule.role_mask, 10),
                truncate(&rule.id, 4),
                truncate(&rule.ip, 12),
                truncate(&rule.time, 8),
                &rule.action,
                truncate(&ep.handler, 20),
                location
            );
            for rule in matching_rules.iter().skip(1) {
                println!("{:<30} {:<7}  {:>10}, {:>4}, {:>12}, {:>8} | {:<6}",
                    "", "",
                    truncate(&rule.role_mask, 10),
                    truncate(&rule.id, 4),
                    truncate(&rule.ip, 12),
                    truncate(&rule.time, 8),
                    &rule.action
                );
            }
        }
    }

    println!("\n{} endpoints, {} ACL rules", endpoints.len(), acl_rules.len());
}

fn print_csv(endpoints: &[Endpoint], acl_rules: &[AclRule]) {
    // CSV header
    println!("endpoint,method,role,id,ip,time,action,handler,file,line");

    let mut sorted_endpoints = endpoints.to_vec();
    sorted_endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    for ep in &sorted_endpoints {
        let matching_rules: Vec<&AclRule> = acl_rules.iter()
            .filter(|r| r.matches_path(&ep.path))
            .collect();

        if matching_rules.is_empty() {
            println!("{},{},*,*,*,*,allow,{},{},{}",
                escape_csv(&ep.path),
                &ep.method,
                escape_csv(&ep.handler),
                escape_csv(&ep.file),
                ep.line
            );
        } else {
            for rule in &matching_rules {
                println!("{},{},{},{},{},{},{},{},{},{}",
                    escape_csv(&ep.path),
                    &ep.method,
                    escape_csv(&rule.role_mask),
                    escape_csv(&rule.id),
                    escape_csv(&rule.ip),
                    escape_csv(&rule.time),
                    &rule.action,
                    escape_csv(&ep.handler),
                    escape_csv(&ep.file),
                    ep.line
                );
            }
        }
    }
}

fn print_toml(endpoints: &[Endpoint], acl_rules: &[AclRule]) {
    println!("# Generated ACL configuration");
    println!("# {} endpoints, {} rules\n", endpoints.len(), acl_rules.len());

    println!("[settings]");
    println!("default_action = \"deny\"\n");

    let mut sorted_endpoints = endpoints.to_vec();
    sorted_endpoints.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    // Group by unique rules
    let mut seen_rules: Vec<String> = Vec::new();

    for ep in &sorted_endpoints {
        let matching_rules: Vec<&AclRule> = acl_rules.iter()
            .filter(|r| r.matches_path(&ep.path))
            .collect();

        if matching_rules.is_empty() {
            // Generate a rule for unrestricted endpoint
            let rule_key = format!("{}:*", ep.path);
            if !seen_rules.contains(&rule_key) {
                seen_rules.push(rule_key);
                println!("[[rules]]");
                println!("endpoint = \"{}\"", ep.path);
                println!("role_mask = \"*\"");
                println!("action = \"allow\"");
                println!("# handler: {} ({}:{})", ep.handler, short_path(&ep.file), ep.line);
                println!();
            }
        } else {
            for rule in &matching_rules {
                let rule_key = format!("{}:{}:{}:{}:{}",
                    rule.pattern, rule.role_mask, rule.id, rule.ip, rule.time);
                if !seen_rules.contains(&rule_key) {
                    seen_rules.push(rule_key);
                    println!("[[rules]]");
                    println!("endpoint = \"{}\"", rule.pattern);
                    if rule.role_mask != "*" {
                        println!("role_mask = {}", rule.role_mask);
                    } else {
                        println!("role_mask = \"*\"");
                    }
                    if rule.id != "*" {
                        println!("id = \"{}\"", rule.id);
                    }
                    if rule.ip != "*" {
                        println!("ip = \"{}\"", rule.ip);
                    }
                    if rule.time != "*" {
                        println!("# time = \"{}\"", rule.time);
                    }
                    println!("action = \"{}\"", rule.action);
                    println!();
                }
            }
        }
    }
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn short_path(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max-1])
    } else {
        s.to_string()
    }
}

fn print_help() {
    println!("Axum Endpoint Parser with ACL Rules");
    println!();
    println!("Usage: endpoint_parser [OPTIONS] <directory>");
    println!();
    println!("Output format:");
    println!("  ENDPOINT METHOD  ROLE, ID, IP, TIME | ACTION  HANDLER  file:line");
    println!("  * = any/wildcard");
    println!();
    println!("Options:");
    println!("  --text    Use text-based parsing (default, fast)");
    #[cfg(feature = "ast-parser")]
    println!("  --ast     Use AST-based parsing (more accurate)");
    #[cfg(not(feature = "ast-parser"))]
    println!("  --ast     Use AST-based parsing (requires --features ast-parser)");
    println!();
    println!("  --table   Output as formatted table (default)");
    println!("  --csv     Output as CSV");
    println!("  --toml    Output as TOML config file");
    println!();
    println!("  --help    Show this help message");
    println!();
    println!("Examples:");
    println!("  endpoint_parser examples/");
    println!("  endpoint_parser --csv examples/ > endpoints.csv");
    println!("  endpoint_parser --toml examples/ > acl.toml");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args.contains(&"--help".to_string()) {
        print_help();
        return;
    }

    let mut mode = ParseMode::Text;
    let mut format = OutputFormat::Table;
    let mut dir_path: Option<PathBuf> = None;

    for arg in &args {
        match arg.as_str() {
            "--text" => mode = ParseMode::Text,
            "--ast" => mode = ParseMode::Ast,
            "--table" => format = OutputFormat::Table,
            "--csv" => format = OutputFormat::Csv,
            "--toml" => format = OutputFormat::Toml,
            "--help" => {
                print_help();
                return;
            }
            _ if !arg.starts_with('-') => {
                dir_path = Some(PathBuf::from(arg));
            }
            _ => {
                eprintln!("Unknown option: {}", arg);
                std::process::exit(1);
            }
        }
    }

    let dir = dir_path.unwrap_or_else(|| PathBuf::from("src"));

    // Only print header for table format
    if format == OutputFormat::Table {
        eprintln!("Parsing axum endpoints in: {}", dir.display());
        eprintln!("Mode: {:?}\n", mode);
    }

    match mode {
        ParseMode::Text => {
            let mut parser = text_parser::TextParser::new();
            parser.parse_dir(&dir);
            parser.resolve_nests();
            print_results(&parser.endpoints, &parser.acl_rules, format);
        }
        ParseMode::Ast => {
            #[cfg(feature = "ast-parser")]
            {
                let mut parser = ast_parser::AstParser::new();
                parser.parse_dir(&dir);
                parser.resolve_nests();
                print_results(&parser.endpoints, &parser.acl_rules, format);
            }
            #[cfg(not(feature = "ast-parser"))]
            {
                eprintln!("Error: AST parsing requires the 'ast-parser' feature.");
                eprintln!("Run with: cargo run --bin endpoint_parser --features ast-parser -- --ast <dir>");
                std::process::exit(1);
            }
        }
    }
}
