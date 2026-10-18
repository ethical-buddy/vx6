#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use once_cell::sync::Lazy;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

static NODE_PROCESS: Lazy<Mutex<Option<Child>>> = Lazy::new(|| Mutex::new(None));

#[tauri::command]
fn vx6_status() -> Result<String, String> {
    run_vx6(&["status"])
}

#[tauri::command]
fn vx6_init(name: String) -> Result<String, String> {
    run_vx6(&["init", "--name", &name, "--listen", "[::]:4242"])
}

#[tauri::command]
fn vx6_node_start() -> Result<String, String> {
    let mut guard = NODE_PROCESS
        .lock()
        .map_err(|_| "failed to lock node process state".to_string())?;
    if guard.is_some() {
        return Ok("node already running in this app session".to_string());
    }
    let child = Command::new("vx6")
        .arg("node")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start node: {e}"))?;
    let pid = child.id();
    *guard = Some(child);
    Ok(format!("node started (pid={pid})"))
}

#[tauri::command]
fn vx6_node_stop() -> Result<String, String> {
    let mut guard = NODE_PROCESS
        .lock()
        .map_err(|_| "failed to lock node process state".to_string())?;
    if let Some(mut child) = guard.take() {
        child
            .kill()
            .map_err(|e| format!("failed to stop node process: {e}"))?;
        return Ok("node stopped".to_string());
    }
    Ok("no in-app node process to stop".to_string())
}

#[tauri::command]
fn vx6_exec(args: Vec<String>) -> Result<String, String> {
    let owned: Vec<&str> = args.iter().map(String::as_str).collect();
    run_vx6(&owned)
}

fn run_vx6(args: &[&str]) -> Result<String, String> {
    let out = Command::new("vx6")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run vx6: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{stdout}\n{stderr}"))
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            vx6_status,
            vx6_init,
            vx6_node_start,
            vx6_node_stop,
            vx6_exec
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
