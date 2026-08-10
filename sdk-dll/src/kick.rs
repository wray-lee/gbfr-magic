// 踢人 (B21 修正): PFLobbyForceRemoveMember — 官方移除 API
//
// 决策链 (B21, 2026-08-11 第二轮审查后, 以真实 DLL 反汇编为准):
// - 真实 DLL 导出表 (pefile 全量解析): PFLobbyForceRemoveMember = 0x37980,
//   签名实测: rcx=handle (0x35a80 校验), rdx=PFEntityKey* {id,type}, r8b=bool, r9=ctx (movzx r15d, r8b)
// - 游戏 UI 踢人 (B9/B12 动态) 走 PFLobbyPostUpdate + id_container 成员属性更新,
//   其容器字符串由游戏自定义 formatter 序列化 (格式未解, 0x240680/0x2a6f30 + 函数指针表)
//   → 复制该路径需臆造容器格式, 不可行
// - PostUpdate 配置的 memberToDelete 字段偏移无法纯静态收敛 (解析走 vtable 分发:
//   0x35290 → 0x743d0 → 0x351e0 → 0x607a0 移除; 审查者 +0x58/+0x60 与假设 +0x48/+0x50 均未获直接证据)
// - ForceRemoveMember 是唯一零未验证数据的移除路径 (B9 仅证明游戏 UI 不用它, 非 API 失效)
//
// lobby handle 抓取 (BLOCKER-3/B21 修正):
// - B16 "JOIN_LOBBY rcx=lobby 句柄" 为误标 — 官方 ABI: PFMultiplayerJoinLobby 的 rcx = PFMultiplayerHandle,
//   PFLobbyHandle 是 out-param, 调用入口结构上不可能拿到 → 废弃 JOIN_LOBBY/CREATE_JOIN hook
// - 改为 hook SDK 导出 PFLobbyPostUpdate (B12 动态: 游戏调用时 rcx = [容器+0x1d0] = lobby handle)
//   + PFLobbyGetLobbyId (官方 ABI: rcx = lobby handle) 双捕获源
// - hook 区域长度 (B22, 2026-08-11 capstone 指令边界实测):
//   PFLobbyPostUpdate 0x39F60: 40 53|55|56|57|41 54|41 55|41 56|41 57 → 边界 {2,3,4,5,7,9,11,13}, len=7
//   PFLobbyGetLobbyId 0x38050: 40 55|56|57|41 56|41 57 → 边界 {2,3,4,6,8}, len=6
//   (B21 曾用 6/5 — 在 2 字节 push r12/push r14 中间断开, 悬空 REX 吞 E9 且被 hook 函数丢 callee-saved
//    push, 尾块 pop 恢复垃圾值 → 调用方寄存器破坏, B22 修正)
use crate::detour;
use crate::sdk::{FN_FORCE_REMOVE, FN_GET_LOBBY_ID, FN_POST_UPDATE};
use crate::scan::read_cstr;
use crate::log;

static mut POST_NEAR: usize = 0;
static mut GETID_NEAR: usize = 0;

// 安装 lobby handle 抓取 hook (注入时调用)
pub fn install_lobby_hooks() -> bool {
    unsafe {
        if FN_POST_UPDATE == 0 || FN_GET_LOBBY_ID == 0 {
            log("[kick] PostUpdate/GetLobbyId not resolved, lobby hooks skipped");
            return false;
        }
        // B12: 游戏调 PostUpdate 时 rcx = [容器+0x1d0] = lobby handle
        match detour::install_capture(FN_POST_UPDATE, 7) {
            Some(h) => POST_NEAR = h.near_addr(),
            None => { log("[kick] PostUpdate hook FAILED (near alloc)"); return false; }
        }
        // 官方 ABI: PFLobbyGetLobbyId(handle, &id), rcx = lobby handle
        match detour::install_capture(FN_GET_LOBBY_ID, 6) {
            Some(h) => GETID_NEAR = h.near_addr(),
            None => { log("[kick] GetLobbyId hook FAILED (near alloc)"); return false; }
        }
        log("[kick] lobby hooks installed (SDK PostUpdate/GetLobbyId export)");
        true
    }
}

// 读取捕获的 rcx (lobby handle)
// 优先级: POST_NEAR (PostUpdate 捕获, B12 动态验证源) 非零时覆盖 GETID 值;
//   GETID (GetLobbyId 捕获, 官方 ABI) 为兜底。两源均经 do_kick 的 GetLobbyId 自检, 功能等价。
pub fn lobby_handle() -> u64 {
    unsafe {
        let mut v = 0u64;
        if GETID_NEAR != 0 {
            v = std::ptr::read_unaligned((GETID_NEAR + 0x10) as *const u64);
        }
        if POST_NEAR != 0 {
            let w = std::ptr::read_unaligned((POST_NEAR + 0x10) as *const u64);
            if w != 0 { v = w; }
        }
        v
    }
}

pub fn do_kick(target_id: &str) {
    unsafe {
        // MINOR-7/B22: ForceRemoveMember 官方签名不依赖 PFMultiplayerHandle, 仅需有效 lobby handle
        if FN_FORCE_REMOVE == 0 { log("[kick] ForceRemoveMember not resolved"); return; }
        let lobby = lobby_handle();
        if lobby == 0 {
            log("[kick] lobby handle not captured — 需在房间内触发一次游戏 PostUpdate/GetLobbyId (K1: SDK 导出 hook, B12)");
            return;
        }
        let id = target_id.trim();
        if id.len() != 16 { log(&format!("[kick] invalid id: {}", id)); return; }
        // B27/MINOR-4: id 含 NUL 字节时 CString::new 返回 Err — unwrap 会 panic 并跨 extern FFI unwind (abort);
        // 与 setid 的 unwrap_or_default 一致, 构造失败按非法 id 处理
        let id_buf = match std::ffi::CString::new(id) {
            Ok(s) => s,
            Err(_) => { log(&format!("[kick] id 含 NUL: {}", id)); return; }
        };

        // K1 自检: PFLobbyGetLobbyId 验证 handle 语义 (B12 断言待动态确认, B21)
        let getid: unsafe extern "system" fn(u64, *mut *const u8) -> i32 =
            std::mem::transmute(FN_GET_LOBBY_ID);
        let mut lid: *const u8 = std::ptr::null();
        let gr = getid(lobby, &mut lid);
        if gr < 0 {
            log(&format!("[kick] GetLobbyId ret=0x{:X} — 捕获的 rcx 可能不是 lobby handle (待动态验证)", gr));
            return;
        }
        log(&format!("[kick] lobby id = {}", read_cstr(lid as usize)));

        // PFEntityKey = {char* id; char* type} (B12/B14 实测)
        let type_buf = std::ffi::CString::new("title_player_account").unwrap();
        let key: [u64; 2] = [id_buf.as_ptr() as u64, type_buf.as_ptr() as u64];

        // PFLobbyForceRemoveMember(handle, PFEntityKey*, bool isForced, void* ctx) — 0x37980 (pefile 复核)
        let force: unsafe extern "system" fn(u64, *const u64, u8, u64) -> i32 =
            std::mem::transmute(FN_FORCE_REMOVE);
        let ret = force(lobby, key.as_ptr(), 0, 0);
        log(&format!("[kick] ForceRemoveMember({}) ret=0x{:X} (0=提交成功)", id, ret));
    }
}
