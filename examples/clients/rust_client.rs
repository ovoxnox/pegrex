// rust_client.rs -- minimal pegrex service client (JSON-lines over stdio).
// Deps: serde_json.  Run the service: `python service.py`, spawn it from
// Rust with std::process::Command, then speak one JSON object per line.
//
// This is the entire integration surface for Rust consumers.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn main() {
    let mut child = Command::new("python")
        .arg("service.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn pegrex service");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let request = r#"{"method":"contracts","params":{"language":"lua","source":"local function fact(n) if n == 0 then return 1 else return n * fact(n - 1) end end"}}"#;
    writeln!(stdin, "{}", request).unwrap();

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
    println!("contract: {}", resp["contract"]);
}
