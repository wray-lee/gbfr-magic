// SDK 函数指针解析 + PFMultiplayerHandle 抓取
// 基于 B17 静态逆向: 导出名已知, 注入后 GetProcAddress 解析
// handle 获取 (K5/B20): detour::install_capture hook SDK StartProcessing 导出入口
//   — 近块内联保存 rcx (PFMultiplayerHandle), 抓到即 restore
//   — hook 区域 6 字节 (dll 0x3FA90 序言 40 55|56|57|41 54, 边界 {2,3,4,6,8,10,12} 7×push 完整集, len=6 在边界上, 2026-08-11 静态验证)
use std::sync::atomic::Ordering;
use crate::detour;
use crate::{log, MP_HANDLE, SDK_BASE};

// SDK 导出函数指针 (注入后解析一次)
pub static mut FN_FIND_LOBBIES: usize = 0;
pub static mut FN_START_PROCESSING: usize = 0;
pub static mut FN_FINISH_PROCESSING: usize = 0;
pub static mut FN_FORCE_REMOVE: usize = 0;
pub static mut FN_GET_LOBBY_ID: usize = 0;
pub static mut FN_GET_MEMBERS: usize = 0;
pub static mut FN_POST_UPDATE: usize = 0;

pub fn sdk_base() -> u64 {
    unsafe {
        let h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
            windows_sys::core::w!("PlayFabMultiplayerWin.dll"),
        );
        if h.is_null() { return 0; }
        h as u64
    }
}

fn resolve(name: &str) -> usize {
    unsafe {
        let h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
            windows_sys::core::w!("PlayFabMultiplayerWin.dll"),
        );
        if h.is_null() { return 0; }
        let cname = std::ffi::CString::new(name).unwrap_or_default();
        let p = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            h,
            cname.as_ptr() as *const u8,
        );
        p.map(|f| f as usize).unwrap_or(0)
    }
}

// 初始化: 解析全部函数指针
pub fn init() {
    unsafe {
        let b = sdk_base();
        if b == 0 { log("[sdk] PlayFabMultiplayerWin.dll not loaded"); return; }
        SDK_BASE.store(b, Ordering::Relaxed);
        log(&format!("[sdk] base=0x{:X}", b));
        FN_FIND_LOBBIES = resolve("PFMultiplayerFindLobbies");
        FN_START_PROCESSING = resolve("PFMultiplayerStartProcessingLobbyStateChanges");
        FN_FINISH_PROCESSING = resolve("PFMultiplayerFinishProcessingLobbyStateChanges");
        FN_FORCE_REMOVE = resolve("PFLobbyForceRemoveMember");
        FN_GET_LOBBY_ID = resolve("PFLobbyGetLobbyId");
        FN_GET_MEMBERS = resolve("PFLobbyGetMembers");
        FN_POST_UPDATE = resolve("PFLobbyPostUpdate");
        let (f_find, f_start, f_finish, f_force, f_getid, f_members, f_post) =
            (FN_FIND_LOBBIES, FN_START_PROCESSING, FN_FINISH_PROCESSING, FN_FORCE_REMOVE, FN_GET_LOBBY_ID, FN_GET_MEMBERS, FN_POST_UPDATE);
        log(&format!(
            "[sdk] find=0x{:X} start=0x{:X} finish=0x{:X} force=0x{:X} getid=0x{:X} members=0x{:X} post=0x{:X}",
            f_find, f_start, f_finish, f_force, f_getid, f_members, f_post
        ));
    }
}

// ===== 抓取 PFMultiplayerHandle =====
// hook SDK StartProcessing 导出入口: 游戏每帧调用, rcx = PFMultiplayerHandle (B19.4)
// 抓到后 restore, 抓不到保持 hook (下次帧循环再试)
static mut GRAB_HOOK: *mut detour::Hook = std::ptr::null_mut();

pub fn install_grab_handle() -> bool {
    unsafe {
        if MP_HANDLE.load(Ordering::Relaxed) != 0 { return true; }
        let sp = FN_START_PROCESSING;
        if sp == 0 {
            log("[sdk] StartProcessing not resolved, grab hook skipped");
            return false;
        }
        // B20: hook 区域 = 6 字节 (完整指令边界, 2026-08-11 文件字节验证)
        match detour::install_capture(sp, 6) {
            Some(h) => {
                GRAB_HOOK = Box::into_raw(Box::new(h));
                log("[sdk] grab hook installed on StartProcessing");
                true
            }
            None => {
                log("[sdk] grab hook install FAILED (near alloc)");
                false
            }
        }
    }
}

// 检查是否抓到 handle; 抓到后恢复原代码
pub fn check_handle() {
    unsafe {
        if MP_HANDLE.load(Ordering::Relaxed) != 0 { return; }
        if GRAB_HOOK.is_null() { return; }
        let v = (*GRAB_HOOK).saved();
        if v != 0 {
            MP_HANDLE.store(v, Ordering::Relaxed);
            log(&format!("[sdk] grabbed PFMultiplayerHandle=0x{:X}", v));
            (*GRAB_HOOK).restore();
            log("[sdk] grab hook restored");
        }
    }
}
