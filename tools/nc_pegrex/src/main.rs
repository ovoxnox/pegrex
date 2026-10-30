//! Versioned, offline JSON reporting boundary for PegRex and neural-codegen.
use nc_ir::ApiEndpoint;
use nc_parser::SexpNode;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

const SCHEMA: &str = "pegrex.neural-codegen-backend.v1";

fn escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn report(path: &PathBuf, status: &str, endpoints: usize, error: Option<&str>) {
    let error_json = match error {
        Some(row) => format!("\"{}\"", escape(row)),
        None => "null".to_string(),
    };
    let payload = format!(
        "{{\n  \"schema\": \"{SCHEMA}\",\n  \"status\": \"{status}\",\n  \"backend\": \"neural-codegen\",\n  \"backend_version\": \"0.1.0\",\n  \"generated_file\": \"generated.rs\",\n  \"endpoints\": {endpoints},\n  \"error\": {error_json}\n}}\n"
    );
    let _ = fs::write(path, payload);
}

fn argument(name: &str) -> Result<PathBuf, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let index = args.iter().position(|row| row == name)
        .ok_or_else(|| format!("missing required argument {name}"))?;
    if index + 1 >= args.len() {
        return Err(format!("missing value for {name}"));
    }
    Ok(PathBuf::from(&args[index + 1]))
}

fn run() -> Result<(usize, PathBuf, PathBuf), String> {
    let input = argument("--input")?;
    let output = argument("--output-dir")?;
    let report_path = argument("--report")?;
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 6 {
        return Err("expected exactly --input, --output-dir, and --report".into());
    }
    let source = fs::read_to_string(&input)
        .map_err(|error| format!("cannot read UTF-8 input: {error}"))?;
    let nodes = SexpNode::parse(&source).map_err(|error| error.to_string())?;
    if nodes.is_empty() || nodes.len() > 128 {
        return Err("endpoint count must be between 1 and 128".into());
    }
    let mut endpoints = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        let endpoint = ApiEndpoint::from_sexp(node)
            .map_err(|error| format!("endpoint {}: {error}", index + 1))?;
        endpoints.push(endpoint);
    }
    let generated = nc_codegen::generate(&endpoints);
    fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    let generated_path = output.join("generated.rs");
    fs::write(&generated_path, generated).map_err(|error| error.to_string())?;
    Ok((endpoints.len(), generated_path, report_path))
}

fn main() -> ExitCode {
    let fallback = PathBuf::from("backend-report.json");
    let report_path = argument("--report").unwrap_or(fallback);
    match run() {
        Ok((count, _, path)) => {
            report(&path, "generated", count, None);
            ExitCode::SUCCESS
        }
        Err(error) => {
            report(&report_path, "rejected", 0, Some(&error));
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}
