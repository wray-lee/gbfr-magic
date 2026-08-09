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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_game_status,
            get_chars,
            set_slot,
            lyria_switch
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
