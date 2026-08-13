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
// T9: 自动 lobby 捕获源 (B9 动态证据: 房内游戏持续轮询这些 accessor, rcx = lobby handle)
pub static mut FN_GET_OWNER: usize = 0;
pub static mut FN_GET_MEMBER_PROPERTY: usize = 0;
pub static mut FN_GET_LOBBY_PROPERTY: usize = 0;
pub static mut FN_GET_CONN_STRING: usize = 0;
pub static mut FN_GET_MEMBER_CONN_STATUS: usize = 0;
// T10: 官方异步入房入口 (out-param 槽捕获) — 签名 v1.8.0 header 验证, 见 kick.rs 汇编 stub
pub static mut FN_JOIN_LOBBY: usize = 0;
pub static mut FN_CREATE_JOIN: usize = 0;
// T1: 原生踢人链路 (memberToDelete → PFLobbyLeave), telemetry 被动记录
pub static mut FN_LEAVE: usize = 0;

// 游戏 exe 内函数 (B29 最终: 踢人 config 构建点 0x3B4CD8D — mov [rbp-0x48],rdi; rdi=目标成员 id,
// 随后 lea rax,[rbp-0x48] 放入 config → PFLobbyPostUpdate (IAT thunk 0x49AD690);
// hook 此点改写 rdi 即替换踢人目标。ForceRemoveMember 路径 (0x49AD720) 实测不触发, 弃用)
pub static mut GAME_KICK_CONFIG: usize = 0;

pub fn sdk_base() -> u64 {
    unsafe {
        let h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
            windows_sys::core::w!("PlayFabMultiplayerWin.dll"),
        );
        if h.is_null() { return 0; }
        h as u64
    }
}

// 游戏 exe 基址 (KICK_EXEC 调用需要)
pub fn game_base() -> u64 {
    unsafe {
        let h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
            windows_sys::core::w!("granblue_fantasy_relink.exe"),
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
        FN_GET_OWNER = resolve("PFLobbyGetOwner");
        FN_GET_MEMBER_PROPERTY = resolve("PFLobbyGetMemberProperty");
        FN_GET_LOBBY_PROPERTY = resolve("PFLobbyGetLobbyProperty");
        FN_GET_CONN_STRING = resolve("PFLobbyGetConnectionString");
        FN_GET_MEMBER_CONN_STATUS = resolve("PFLobbyGetMemberConnectionStatus");
        FN_JOIN_LOBBY = resolve("PFMultiplayerJoinLobby");
        FN_CREATE_JOIN = resolve("PFMultiplayerCreateAndJoinLobby");
        FN_LEAVE = resolve("PFLobbyLeave");
        let g = game_base();
        if g != 0 {
            GAME_KICK_CONFIG = (g + 0x3B4CD8D) as usize;
            let kick_config = GAME_KICK_CONFIG;
            log(&format!("[sdk] game=0x{:X} KICKCFG=0x{:X}", g, kick_config));
        } else {
            log("[sdk] game exe not loaded (KICKCFG unavailable)");
        }
        let (f_find, f_start, f_finish, f_force, f_getid, f_members, f_post, f_owner, f_getmp, f_getlp, f_conn, f_memconn, f_join, f_createjoin, f_leave) = (
            FN_FIND_LOBBIES, FN_START_PROCESSING, FN_FINISH_PROCESSING, FN_FORCE_REMOVE, FN_GET_LOBBY_ID, FN_GET_MEMBERS, FN_POST_UPDATE,
            FN_GET_OWNER, FN_GET_MEMBER_PROPERTY, FN_GET_LOBBY_PROPERTY, FN_GET_CONN_STRING, FN_GET_MEMBER_CONN_STATUS,
            FN_JOIN_LOBBY, FN_CREATE_JOIN, FN_LEAVE,
        );
        log(&format!(
            "[sdk] find=0x{:X} start=0x{:X} finish=0x{:X} force=0x{:X} getid=0x{:X} members=0x{:X} post=0x{:X} owner=0x{:X} getmp=0x{:X} getlp=0x{:X} conn=0x{:X} memconn=0x{:X} join=0x{:X} createjoin=0x{:X} leave=0x{:X}",
            f_find, f_start, f_finish, f_force, f_getid, f_members, f_post, f_owner, f_getmp, f_getlp, f_conn, f_memconn, f_join, f_createjoin, f_leave
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
        // 幂等: 已装 (如 `hooks` 路径 DllMain 已装, `grab` 首个 update 再来) → 静默早退
        if !GRAB_HOOK.is_null() { return true; }
        let sp = FN_START_PROCESSING;
        if sp == 0 {
            log("[sdk] StartProcessing not resolved, grab hook skipped");
            return false;
        }
        let expected = [0x40, 0x55, 0x56, 0x57, 0x41, 0x54];
        match detour::install_capture_checked(
            sp,
            &expected,
            "StartProcessing",
            "PlayFabMultiplayerWin.dll",
            detour::module_range("PlayFabMultiplayerWin.dll"),
        ) {
            Some(h) => {
                GRAB_HOOK = Box::into_raw(Box::new(h));
                log("[sdk] grab hook installed on StartProcessing (module=PlayFabMultiplayerWin.dll)");
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
            log(&format!(
                "[sdk] grabbed PFMultiplayerHandle=0x{:X} (invocations={})",
                v,
                (*GRAB_HOOK).counts()
            ));
            if !(*GRAB_HOOK).restore() {
                log("[sdk] grab hook restore FAILED — slot retained");
                return;
            }
            log("[sdk] grab hook restored");
        }
    }
}

// B29: unload 时恢复 grab hook (若尚未抓到)
// T5: 幂等 — 二次调用 (GRAB_HOOK 已空) → no-op 日志; Box::from_raw 恰好一次 (install 时 into_raw)
pub fn unhook_grab() {
    unsafe {
        if GRAB_HOOK.is_null() {
            log("[sdk] grab hook already unhooked");
            return;
        }
        if MP_HANDLE.load(Ordering::Relaxed) == 0 {
            (*GRAB_HOOK).restore();
        }
        let _ = Box::from_raw(GRAB_HOOK);
        GRAB_HOOK = std::ptr::null_mut();
        log("[sdk] grab hook freed");
    }
}
