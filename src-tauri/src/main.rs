#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// 前置模块声明
mod chars;
mod game;
mod memory;

// Tauri 命令
#[tauri::command]
fn get_game_status() -> game::GameStatus {
    game::game_status()
}

#[tauri::command]
fn get_chars() -> Vec<chars::CharInfo> {
    chars::all_chars()
}

#[tauri::command]
fn set_slot(slot: u32, id: u32) -> Result<game::SlotUpdate, String> {
    game::set_slot(slot, id)
}

#[tauri::command]
fn lyria_switch(mode: String) -> Result<String, String> {
    game::lyria_switch(&mode)
}

#[tauri::command]
fn set_no_cd(enable: bool) -> Result<(), String> {
    game::apply_patch(&game::NO_CD, enable)
}

#[tauri::command]
fn set_infinite_hp(enable: bool) -> Result<(), String> {
    game::apply_patch(&game::INFINITE_HP, enable)
}

// 选中角色修改 (罗兰因子方法)
#[tauri::command]
fn scan_selected(role_id: u32) -> Vec<u64> {
    game::scan_u32_all(role_id)
}

#[tauri::command]
fn filter_selected(addrs: Vec<u64>, role_id: u32) -> Vec<u64> {
    game::filter_selected(&addrs, role_id)
}

#[tauri::command]
fn write_selected(addrs: Vec<u64>, role_id: u32) -> usize {
    let pid = match memory::Process::find_by_name(game::GAME_PROCESS) {
        Some(p) => p,
        None => return 0,
    };
    let proc = match memory::Process::open(pid) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let mut n = 0;
    for a in &addrs {
        if proc.write_u32(*a, role_id) {
            n += 1;
        }
    }
    n
}

// 连接控制
#[tauri::command]
fn connect() -> Result<game::ConnState, String> {
    game::connect()
}

#[tauri::command]
fn disconnect() -> Result<game::ConnState, String> {
    game::disconnect()
}

#[tauri::command]
fn conn_state() -> game::ConnState {
    game::conn_state()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_game_status,
            get_chars,
            set_slot,
            lyria_switch,
            set_no_cd,
            set_infinite_hp,
            scan_selected,
            filter_selected,
            write_selected,
            connect,
            disconnect,
            conn_state
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
