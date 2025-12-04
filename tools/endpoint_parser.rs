//! Axum endpoint parser with two parsing modes:
//!
//! 1. **Text mode** (default): Fast line-by-line text analysis
//! 2. **AST mode** (requires `ast-parser` feature): Full Rust AST parsing with `syn`
//!
//! Usage:
//!   cargo run --bin endpoint_parser -- [OPTIONS] <directory>
//!   cargo run --bin endpoint_parser --features ast-parser -- --ast <directory>
//!
//! Options:
//!   --ast    Use AST-based parsing (requires ast-parser feature)
//!   --text   Use text-based parsing (default)
//!   --help   Show help

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// A discovered endpoint
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub method: String,      // GET, POST, PUT, DELETE, etc.
    pub path: String,        // Full path including nest prefixes
    pub handler: String,     // Handler function name
    pub file: String,        // Source file
    pub line: usize,         // Line number
}

/// Parsing mode
#[derive(Debug, Clone, Copy, PartialEq)]
enum ParseMode {
    Text,
    Ast,
}

// ============================================================================
// Text-based Parser (default, fast)
// ============================================================================

mod text_parser {
    use super::*;

    pub struct TextParser {
        pub endpoints: Vec<Endpoint>,
        pending_nests: Vec<(String, String, String, usize)>,
        router_fns: HashMap<String, (String, String, usize)>,
    }

    impl TextParser {
        pub fn new() -> Self {
            Self {
                endpoints: Vec::new(),
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

        pub fn router_fns(&self) -> impl Iterator<Item = (&String, &(String, String, usize))> {
            self.router_fns.iter()
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
        current_file: String,
        router_fns: HashMap<String, (String, String, usize)>, // fn_name -> (file, content, line)
        pending_nests: Vec<(String, String)>,                  // (prefix, fn_name)
    }

    impl AstParser {
        pub fn new() -> Self {
            Self {
                endpoints: Vec::new(),
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

            let syntax: File = match syn::parse_file(&content) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to parse {}: {}", path.display(), e);
                    return;
                }
            };

            // First pass: find router-returning functions
            for item in &syntax.items {
                if let syn::Item::Fn(func) = item {
                    if self.returns_router(func) && func.sig.ident != "main" {
                        let fn_name = func.sig.ident.to_string();
                        let start_line = func.sig.ident.span().start().line;
                        // Store the function content for later nest resolution
                        let fn_content = quote::quote!(#func).to_string();
                        self.router_fns.insert(
                            fn_name,
                            (self.current_file.clone(), fn_content, start_line),
                        );
                    }
                }
            }

            // Second pass: visit all expressions
            self.visit_file(&syntax);
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
            let mut iterations = 0;

            while !self.pending_nests.is_empty() && iterations < 10 {
                let nests: Vec<_> = self.pending_nests.drain(..).collect();

                for (prefix, fn_name) in nests {
                    if let Some((file, content, _)) = self.router_fns.get(&fn_name).cloned() {
                        // Re-parse this function's content with the prefix
                        self.parse_nested_router(&content, &file, &prefix);
                    }
                }
                iterations += 1;
            }
        }

        fn parse_nested_router(&mut self, content: &str, file: &str, prefix: &str) {
            // Parse the function content and extract routes with prefix
            // This is a simplified version - for full accuracy we'd need to track context
            let lines: Vec<&str> = content.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                self.extract_routes_from_text(line, file, i + 1, prefix);
            }
        }

        fn extract_routes_from_text(&mut self, line: &str, file: &str, line_num: usize, prefix: &str) {
            // Fallback to text parsing for nested content
            if let Some(pos) = line.find(".route(") {
                let after = &line[pos + 7..];
                if let Some(path) = self.extract_string_literal(after) {
                    let full_path = format!("{}{}", prefix, path);
                    let methods = ["get", "post", "put", "delete", "patch", "head", "options", "trace"];

                    for method in &methods {
                        if let Some(handler) = self.extract_method_handler(after, method) {
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

        pub fn router_fn_count(&self) -> usize {
            self.router_fns.len()
        }

        pub fn router_fns(&self) -> impl Iterator<Item = (&String, &(String, String, usize))> {
            self.router_fns.iter()
        }
    }

    impl<'ast> Visit<'ast> for AstParser {
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            let method_name = node.method.to_string();

            // Check for .route("path", handler)
            if method_name == "route" && node.args.len() >= 2 {
                if let Some(path) = self.extract_lit_str(&node.args[0]) {
                    let line = node.method.span().start().line;

                    // Check the second argument for method calls
                    self.extract_handlers_from_expr(&node.args[1], &path, line);
                }
            }

            // Check for .nest("prefix", router)
            if method_name == "nest" && node.args.len() >= 2 {
                if let Some(prefix) = self.extract_lit_str(&node.args[0]) {
                    // Try to get the router function name
                    if let Some(fn_name) = self.extract_fn_call_name(&node.args[1]) {
                        self.pending_nests.push((prefix, fn_name));
                    }
                }
            }

            // Continue visiting
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
                // Direct call: get(handler)
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
                // Chained: get(h1).post(h2)
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
                    // Continue checking the receiver
                    self.extract_handlers_from_expr(&method_call.receiver, path, line);
                }
                _ => {}
            }
        }

        fn extract_handler_name(&self, args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>) -> Option<String> {
            if let Some(first_arg) = args.first() {
                match first_arg {
                    Expr::Path(ExprPath { path, .. }) => {
                        Some(path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"))
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
    }
}

// ============================================================================
// Output formatting
// ============================================================================

fn print_results(endpoints: &[Endpoint]) {
    if endpoints.is_empty() {
        println!("\nNo endpoints found.");
        return;
    }

    println!("\n=== Discovered Endpoints ===\n");

    let mut by_path: HashMap<String, Vec<&Endpoint>> = HashMap::new();
    for ep in endpoints {
        by_path.entry(ep.path.clone()).or_default().push(ep);
    }

    let mut paths: Vec<_> = by_path.keys().cloned().collect();
    paths.sort();

    for path in &paths {
        let eps = &by_path[path];
        println!("{}", path);
        for ep in eps {
            println!("  {:7} -> {}  ({}:{})", ep.method, ep.handler, ep.file, ep.line);
        }
    }

    println!(
        "\n{} endpoints found across {} paths",
        endpoints.len(),
        paths.len()
    );
}

fn print_help() {
    println!("Axum Endpoint Parser");
    println!();
    println!("Usage: endpoint_parser [OPTIONS] <directory>");
    println!();
    println!("Options:");
    println!("  --text   Use text-based parsing (default, fast)");
    #[cfg(feature = "ast-parser")]
    println!("  --ast    Use AST-based parsing (more accurate)");
    #[cfg(not(feature = "ast-parser"))]
    println!("  --ast    Use AST-based parsing (requires --features ast-parser)");
    println!("  --help   Show this help message");
    println!();
    println!("Examples:");
    println!("  endpoint_parser src/");
    println!("  endpoint_parser --text examples/");
    #[cfg(feature = "ast-parser")]
    println!("  endpoint_parser --ast src/");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args.contains(&"--help".to_string()) {
        print_help();
        return;
    }

    let mut mode = ParseMode::Text;
    let mut dir_path: Option<PathBuf> = None;

    for arg in &args {
        match arg.as_str() {
            "--text" => mode = ParseMode::Text,
            "--ast" => mode = ParseMode::Ast,
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

    println!("Parsing axum endpoints in: {}", dir.display());
    println!("Mode: {:?}", mode);
    println!();

    match mode {
        ParseMode::Text => {
            let mut parser = text_parser::TextParser::new();
            parser.parse_dir(&dir);

            println!("Found {} router-returning functions", parser.router_fn_count());
            for (name, (file, _, line)) in parser.router_fns() {
                println!("  {} ({}:{})", name, file, line);
            }

            parser.resolve_nests();
            print_results(&parser.endpoints);
        }
        ParseMode::Ast => {
            #[cfg(feature = "ast-parser")]
            {
                let mut parser = ast_parser::AstParser::new();
                parser.parse_dir(&dir);

                println!("Found {} router-returning functions", parser.router_fn_count());
                for (name, (file, _, line)) in parser.router_fns() {
                    println!("  {} ({}:{})", name, file, line);
                }

                parser.resolve_nests();
                print_results(&parser.endpoints);
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
