// GBFR SDK 正向实现 DLL
// 基于 B17/B18 静态逆向: 直接调 PlayFabMultiplayerWin.dll 导出实现
// 1) 房间扫描: PFMultiplayerFindLobbies + StartProcessing 轮询 (scan.rs)
// 2) 踢人: PFLobbyForceRemoveMember (kick.rs)
// 3) 防踢: hook SDK 内部 0x63C90 (antikick.rs)
//
// 注入方式: 主程序 CreateRemoteThread + LoadLibraryW 加载本 DLL
// 通信: 命令文件 (scan/kick <id>/antikick_on/antikick_off/setid <hex>/state) + 结果文件

mod scan;
mod kick;
mod antikick;
mod sdk;
mod detour;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use windows_sys::Win32::System::Threading::CreateThread;

// 全局状态 (注入进程内)
pub static SDK_BASE: AtomicU64 = AtomicU64::new(0);          // PlayFabMultiplayerWin.dll 基址
pub static MP_HANDLE: AtomicU64 = AtomicU64::new(0);         // PFMultiplayerHandle (游戏初始化好的)
pub static MY_ID: AtomicU64 = AtomicU64::new(0);             // 自己 entity id (C 字符串指针, setid 命令设置)
pub static ANTIKICK: AtomicBool = AtomicBool::new(false);    // 防踢开关

const CMD_FILE: &str = r"C:\Users\Wray\AppData\Local\Temp\opencode\gbfr_sdk_cmd.txt";
const OUT_FILE: &str = r"C:\Users\Wray\AppData\Local\Temp\opencode\gbfr_sdk_out.txt";

pub fn log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(OUT_FILE) {
        let _ = writeln!(f, "{}", msg);
    }
}

// 命令处理线程
unsafe extern "system" fn cmd_thread(_p: *mut core::ffi::c_void) -> u32 {
    use std::io::Read;
    log("[dll] cmd thread started");
    let mut last = String::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(CMD_FILE) {
            if f.read_to_string(&mut s).is_ok() {
                let s = s.trim().to_string();
                if !s.is_empty() && s != last {
                    last = s.clone();
                    log(&format!("[dll] CMD: {}", s));
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    match parts[0] {
                        "scan" => scan::do_scan(),
                        "kick" => {
                            if parts.len() >= 2 {
                                kick::do_kick(parts[1]);
                            } else {
                                log("[dll] kick <id>");
                            }
                        }
                        "setid" => {
                            if parts.len() >= 2 {
                                let id = std::ffi::CString::new(parts[1]).unwrap_or_default();
                                // ponytail: into_raw 泄漏 — 每次 setid 泄漏一份字符串 (进程级工具, 可接受);
                                // 需释放时: 保存旧 ptr, CString::from_raw 重建后 drop
                                let ptr = id.into_raw();
                                MY_ID.store(ptr as u64, Ordering::Relaxed);
                                log(&format!("[dll] MY_ID set: {}", parts[1]));
                            }
                        }
                        "antikick_on" => {
                            ANTIKICK.store(true, Ordering::Relaxed);
                            antikick::install();
                            antikick::set_enabled(true);
                            log("[dll] antikick ON");
                        }
                        "antikick_off" => {
                            ANTIKICK.store(false, Ordering::Relaxed);
                            antikick::set_enabled(false);
                            log("[dll] antikick OFF");
                        }
                        "state" => {
                            sdk::check_handle();
                            log(&format!(
                                "[dll] STATE sdk=0x{:X} handle=0x{:X} lobby=0x{:X} myid=0x{:X} antikick={}",
                                SDK_BASE.load(Ordering::Relaxed),
                                MP_HANDLE.load(Ordering::Relaxed),
                                kick::lobby_handle(),
                                MY_ID.load(Ordering::Relaxed),
                                ANTIKICK.load(Ordering::Relaxed)
                            ));
                        }
                        _ => log("[dll] unknown cmd"),
                    }
                }
            }
        }
    }
}

// DLL 入口: 注入后自动开命令线程
// B23/MINOR-5: PROCESS_ATTACH (loader lock 内) 执行文件 I/O log — 注入工具常见实践, 已实测可行;
//   严格性限制已知 (loader lock 内 I/O 可能阻塞/死锁于极端情况, 且 log 失败静默), 不重构仅记录。
#[no_mangle]
pub unsafe extern "system" fn DllMain(_h: *mut core::ffi::c_void, reason: u32, _r: *mut core::ffi::c_void) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH
        log("[dll] attached");
        sdk::init();
        // 抓 handle: hook SDK StartProcessing 入口, 游戏下一帧调用时抓到
        sdk::install_grab_handle();
        // K1/B21-B22: hook SDK PFLobbyPostUpdate/PFLobbyGetLobbyId 导出抓 lobby handle (B12)
        kick::install_lobby_hooks();
        let mut tid = 0u32;
        CreateThread(std::ptr::null(), 0, Some(cmd_thread), std::ptr::null_mut(), 0, &mut tid);
    }
    1
}
