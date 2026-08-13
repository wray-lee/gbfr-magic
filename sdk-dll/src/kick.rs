// 踢人 (B29 最终): hook 游戏踢人 config 构建点 @ exe+0x3B4CD8D 改写 rdi (目标 id)
//
// 决策链 (B29, 2026-08-11 动态实测后):
// - ForceRemoveMember 直接调用 ret=0x0 但服务器不执行; FORCE thunk (0x49AD720) hook 未触发
// - KICK_EXEC (0x3B4C8B0) 仅被动路径调用; UI_KICK (0x3B4BB70) hook 未触发 (UI 走另一封装)
// - B12/B13 动态+静态: 踢人本质 = 更新 lobby 属性 id_container → PFLobbyPostUpdate
// - 反汇编 0x3B4CDE0 调用点: rcx=[rsi+0x1d0](lobby handle), rdx+=0x90(config),
//   config key/value 数组来自 [rbp-0x50]/[rbp-0x48], [rbp-0x48]=rdi=目标成员 id (来自 [rbp-0x38])
// - 本方案: hook 0x3B4CD8D (mov [rbp-0x48],rdi; vxorps) 改写 rdi → 游戏用 pending id 构建 config
//
// lobby handle 抓取 (B29 新增第三源):
// - B12: 游戏踢人时调 PFLobbyPostUpdate (rcx = [容器+0x1d0] = lobby handle)
// - B29 动态: 打开成员列表时游戏调 PFLobbyGetMembers (rcx = lobby handle) — 新增 hook 源,
//   比 PostUpdate/GetLobbyId 更频繁触发
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::detour;
use crate::sdk::{
    FN_CREATE_JOIN, FN_FORCE_REMOVE, FN_GET_CONN_STRING, FN_GET_LOBBY_ID, FN_GET_LOBBY_PROPERTY,
    FN_GET_MEMBERS, FN_GET_MEMBER_CONN_STATUS, FN_GET_MEMBER_PROPERTY, FN_GET_OWNER, FN_JOIN_LOBBY,
    FN_POST_UPDATE, GAME_KICK_CONFIG,
};
use crate::log;

// T4: KICKCFG-rdi-swap 隔离开关 (默认关闭 — 实验性 rdi 改写, 会静默重定向游戏 UI 的任意踢人操作)
pub static KICKCFG_EXPERIMENTAL: AtomicBool = AtomicBool::new(false);

const SDK_PROLOGUE_RBP_R14: [u8; 6] = [0x40, 0x55, 0x56, 0x57, 0x41, 0x56];
const SDK_PROLOGUE_RBX_R12: [u8; 7] = [0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54];
const KICKCFG_PROLOGUE: [u8; 8] = [0x48, 0x89, 0x7D, 0xB8, 0xC5, 0xF8, 0x57, 0xC0];

static mut POST_NEAR: usize = 0;
static mut GETID_NEAR: usize = 0;
static mut MEMBERS_NEAR: usize = 0;
static mut KICKCFG_NEAR: usize = 0;
// T9: 自动捕获源 (B9 动态证据: 房内游戏持续轮询这些 accessor, rcx = lobby handle)
static mut OWNER_NEAR: usize = 0;
static mut GETMP_NEAR: usize = 0;
static mut GETLP_NEAR: usize = 0;
static mut CONN_NEAR: usize = 0;
static mut MEMCONN_NEAR: usize = 0;
// B29: 保存 Hook 实例供 unload 恢复 (原仅存 near 地址无法 restore)
static mut HOOK_POST: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_GETID: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_MEMBERS: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_KICKCFG: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_OWNER: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_GETMP: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_GETLP: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_CONN: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_MEMCONN: *mut detour::Hook = std::ptr::null_mut();
// T10: 异步入房 out-param 槽捕获 (JoinLobby/CreateAndJoinLobby, far hook)
static mut JOIN_NEAR: usize = 0;
static mut CREATEJOIN_NEAR: usize = 0;
static mut HOOK_JOIN: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_CREATEJOIN: *mut detour::Hook = std::ptr::null_mut();
// T10: 轮询捕获到的 lobby handle (异步写入 *lobby 后由 poll_join_out 存入; unhook 清零)
static mut LOBBY_JOIN: u64 = 0;

// ===== B29: 踢人 config 构建点改写 rdi 方案 =====
// 游戏 UI 踢人时 0x3B4CD8D 被调用 → stub 检查汇编侧 pending; 若有目标, rdi 替换为 pending key id 指针
// 静态存储保证 key 长期有效
static mut KICK_ID_BUF: [u8; 32] = [0; 32];
static KICK_TYPE: &[u8] = b"title_player_account\0";

// 汇编 stub: rdi 替换 (0x3B4CD8D 处 rdi=目标id; 有 pending 时改为 pending id 字符串指针)
// 入口 rsp%16=8 (call 后); 无 push → 保持; jmp [rip+tramp] 跳原逻辑 (mov [rbp-0x48],rdi; vxorps)
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_kick_stub
gbfr_kick_stub:
    cmp qword ptr [rip + gbfr_kick_pending], 0
    je gbfr_kick_pass
    mov rax, qword ptr [rip + gbfr_kick_id_ptr]
    mov rdi, rax
    mov qword ptr [rip + gbfr_kick_pending], 0
gbfr_kick_pass:
    jmp qword ptr [rip + gbfr_kick_tramp]
    .data
    .global gbfr_kick_pending
gbfr_kick_pending:
    .quad 0
    .global gbfr_kick_id_ptr
gbfr_kick_id_ptr:
    .quad 0
    .global gbfr_kick_tramp
gbfr_kick_tramp:
    .quad 0
    "#
);
unsafe extern "C" {
    fn gbfr_kick_stub();
    static mut gbfr_kick_pending: u64;
    static mut gbfr_kick_id_ptr: u64;
    static mut gbfr_kick_tramp: u64;
}

// ===== T10: 异步入房 out-param 槽捕获 (官方 API 契约, 无逆向) =====
// PFMultiplayerJoinLobby(handle, newMember, connString, config, asyncContext, _Outptr_opt_ lobby*)
//   → x64 入口 [rsp+0x28]=asyncContext, [rsp+0x30]=lobby* 槽地址 (第 6 参)
// PFMultiplayerCreateAndJoinLobby(handle, newMember, createCfg, joinCfg, memberCfg, asyncCtx, lobby*)
//   → [rsp+0x28]=memberCfg, [rsp+0x30]=asyncCtx, [rsp+0x38]=lobby* 槽地址 (第 7 参)
// 两 API 均异步: handle 在异步完成时写入 *lobby。stub 在入口保存槽地址 → poll_join_out 轮询槽值。
// 寄存器: 仅改 rax (volatile, 被 hook 序言 = push 系列不消费); mov/test/jmp 不改 flags 之外,
//   test 改 ZF/SF/PF — 无害 (调用方不依赖跨调用 flags, 序言不消费 flags, B24/MAJOR-1 同源推理)。
// 竞态 (B22/MINOR-6 同 KICKCFG): patch 生效与 tramp 写入间微窗口 — tramp=0 时 ret 返回垃圾
//   HRESULT (仅 install 时微秒级, 游戏帧间, 与 antikick 同 tradeoff)。
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_join_stub
gbfr_join_stub:
    mov rax, qword ptr [rsp + 0x30]
    test rax, rax
    je gbfr_join_skip
    mov qword ptr [rip + gbfr_join_out], rax
gbfr_join_skip:
    mov rax, qword ptr [rip + gbfr_join_tramp]
    test rax, rax
    je gbfr_join_not_ready
    jmp rax
gbfr_join_not_ready:
    ret
    .data
    .global gbfr_join_out
gbfr_join_out:
    .quad 0
    .global gbfr_join_tramp
gbfr_join_tramp:
    .quad 0
    "#
);
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_createjoin_stub
gbfr_createjoin_stub:
    mov rax, qword ptr [rsp + 0x38]
    test rax, rax
    je gbfr_createjoin_skip
    mov qword ptr [rip + gbfr_createjoin_out], rax
gbfr_createjoin_skip:
    mov rax, qword ptr [rip + gbfr_createjoin_tramp]
    test rax, rax
    je gbfr_createjoin_not_ready
    jmp rax
gbfr_createjoin_not_ready:
    ret
    .data
    .global gbfr_createjoin_out
gbfr_createjoin_out:
    .quad 0
    .global gbfr_createjoin_tramp
gbfr_createjoin_tramp:
    .quad 0
    "#
);
unsafe extern "C" {
    fn gbfr_join_stub();
    static mut gbfr_join_out: u64;
    static mut gbfr_join_tramp: u64;
    fn gbfr_createjoin_stub();
    static mut gbfr_createjoin_out: u64;
    static mut gbfr_createjoin_tramp: u64;
}

// 设置待踢目标 (pending); 用户需在游戏 UI 触发一次任意踢人操作生效
// T4: 双保险 — 实验开关必须为 ON 且存在 lobby handle 才允许设置 (pending_allowed 纯函数, 见测试)
fn pending_allowed(flag: bool, handle: u64) -> bool {
    flag && handle != 0
}

fn set_pending_kick(id: &str) {
    if !pending_allowed(KICKCFG_EXPERIMENTAL.load(Ordering::Relaxed), lobby_handle()) {
        return;
    }
    unsafe {
        let bytes = id.as_bytes();
        if bytes.len() > 30 { return; }
        for (i, b) in bytes.iter().enumerate() {
            KICK_ID_BUF[i] = *b;
        }
        KICK_ID_BUF[bytes.len()] = 0;
        gbfr_kick_id_ptr = std::ptr::addr_of!(KICK_ID_BUF).cast::<u8>() as u64;
        gbfr_kick_pending = 1;
    }
}

// T4: 开关命令 (lib.rs kickcfg_exp on|off); 关闭时清残留 pending,
// 防止已设未触发的 rdi-swap 在关闭后仍重定向下一次 UI 踢人
pub fn set_kickcfg_experimental(on: bool) {
    KICKCFG_EXPERIMENTAL.store(on, Ordering::Relaxed);
    if !on {
        unsafe { gbfr_kick_pending = 0; }
    }
}

// T2: 预检 + 安装单个 hook; 任何失败 (addr 不可用 / PREFLIGHT FAIL / 安装失败) → None
// 调用方负责 all-or-nothing 全量回滚
fn try_install(
    target: usize,
    len: usize,
    expected: &[u8],
    name: &str,
    module: &str,
    range: Option<(u64, usize)>,
    far: bool,
    stub: usize,
    trampoline_slot: *mut u64,
) -> Option<detour::Hook> {
    if target == 0 {
        log(&format!("[kick] {} addr unavailable", name));
        return None;
    }
    if !detour::preflight(target, module, range) {
        return None;
    }
    if len != expected.len() {
        log(&format!("[kick] {} invalid hook length len={} signature={}", name, len, expected.len()));
        return None;
    }
    let actual = unsafe { std::slice::from_raw_parts(target as *const u8, expected.len()) };
    if actual != expected {
        log(&format!(
            "[kick] {} signature mismatch want={} got={}",
            name,
            detour::hex16(expected),
            detour::hex16(actual)
        ));
        return None;
    }
    let h = if far {
        unsafe { detour::install_far(target, len, stub, trampoline_slot) }
    } else {
        detour::install_capture_checked(target, expected, name, module, range)
    };
    if h.is_some() {
        log(&format!("[kick] {} installed (module={})", name, module));
    }
    h
}

// T2: all-or-nothing 决策 (纯函数, 便于单测)
fn decide_all_or_nothing(results: &[bool]) -> bool {
    results.iter().all(|&b| b)
}

// ===== T5: hook 槽清理 (幂等) =====
// 纯决策: 槽是否持有已安装的 hook (null 校验, 单测可直接用哨兵指针)
fn slot_held(h: *const detour::Hook) -> bool {
    !h.is_null()
}

// 恢复并清空单个 hook 槽; 返回是否曾持有 hook (二次调用 = no-op, 无 double-free)
// 槽以裸指针传入 (addr_of_mut!), 避免对 static mut 产生 &mut (static_mut_refs 零新增)
unsafe fn clear_hook(h: *mut *mut detour::Hook) -> bool {
    let slot = std::ptr::read(h);
    if !slot_held(slot) {
        return false;
    }
    if !(*slot).restore() {
        return false;
    }
    let _ = Box::from_raw(slot);
    std::ptr::write(h, std::ptr::null_mut());
    true
}

// 安装 hook (注入时调用)
pub fn install_lobby_hooks(no_join: bool) -> bool {
    unsafe {
        let sdk_range = detour::module_range("PlayFabMultiplayerWin.dll");
        let game_range = detour::module_range("granblue_fantasy_relink.exe");
        let mut results: Vec<bool> = Vec::with_capacity(11);
        // addr_of_mut!: 静态 mut 用裸指针写, 不产生引用 (static_mut_refs 零新增)
        let record = |h: Option<detour::Hook>, near: *mut usize, slot: *mut *mut detour::Hook| -> bool {
            match h {
                Some(h) => {
                    std::ptr::write(near, h.near_addr());
                    std::ptr::write(slot, Box::into_raw(Box::new(h)));
                    true
                }
                None => false,
            }
        };
        // B12: 游戏调 PostUpdate 时 rcx = [容器+0x1d0] = lobby handle
        results.push(record(
            try_install(FN_POST_UPDATE, 7, &SDK_PROLOGUE_RBX_R12, "PostUpdate", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(POST_NEAR),
            std::ptr::addr_of_mut!(HOOK_POST),
        ));
        // 官方 ABI: PFLobbyGetLobbyId(handle, &id), rcx = lobby handle
        results.push(record(
            try_install(FN_GET_LOBBY_ID, 6, &SDK_PROLOGUE_RBP_R14, "GetLobbyId", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(GETID_NEAR),
            std::ptr::addr_of_mut!(HOOK_GETID),
        ));
        // B29: 打开成员列表 → PFLobbyGetMembers(handle, ...), rcx = lobby handle (高频源)
        // 序言: 40 53|55|56|57|41 54... → 边界 {2,3,4,5,7,...}, len=7
        results.push(record(
            try_install(FN_GET_MEMBERS, 7, &SDK_PROLOGUE_RBX_R12, "GetMembers", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(MEMBERS_NEAR),
            std::ptr::addr_of_mut!(HOOK_MEMBERS),
        ));
        // T9: 自动捕获源 (B9 动态证据: 房内游戏持续轮询, 注入后无需任何 UI 操作即可抓到 handle)
        // 序言家族同 GetLobbyId (B22), len=6; capstone 边界待注入验证 — 若游戏异常立即禁用该源
        results.push(record(
            try_install(FN_GET_OWNER, 6, &SDK_PROLOGUE_RBP_R14, "GetOwner", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(OWNER_NEAR),
            std::ptr::addr_of_mut!(HOOK_OWNER),
        ));
        results.push(record(
            try_install(FN_GET_MEMBER_PROPERTY, 7, &SDK_PROLOGUE_RBX_R12, "GetMemberProperty", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(GETMP_NEAR),
            std::ptr::addr_of_mut!(HOOK_GETMP),
        ));
        results.push(record(
            try_install(FN_GET_LOBBY_PROPERTY, 7, &SDK_PROLOGUE_RBX_R12, "GetLobbyProperty", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(GETLP_NEAR),
            std::ptr::addr_of_mut!(HOOK_GETLP),
        ));
        results.push(record(
            try_install(FN_GET_CONN_STRING, 6, &SDK_PROLOGUE_RBP_R14, "GetConnectionString", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(CONN_NEAR),
            std::ptr::addr_of_mut!(HOOK_CONN),
        ));
        results.push(record(
            try_install(FN_GET_MEMBER_CONN_STATUS, 7, &SDK_PROLOGUE_RBX_R12, "GetMemberConnectionStatus", "PlayFabMultiplayerWin.dll", sdk_range, false, 0, std::ptr::null_mut()),
            std::ptr::addr_of_mut!(MEMCONN_NEAR),
            std::ptr::addr_of_mut!(HOOK_MEMCONN),
        ));
        // B29: 踢人 config 构建点改写 rdi (far stub) — 0x3B4CD8D: mov [rbp-0x48],rdi(4B) + vxorps(4B) = 8 字节完整
        match try_install(
            GAME_KICK_CONFIG,
            8,
            &KICKCFG_PROLOGUE,
            "KICKCFG",
            "granblue_fantasy_relink.exe",
            game_range,
            true,
            gbfr_kick_stub as *const () as usize,
            std::ptr::addr_of_mut!(gbfr_kick_tramp),
        ) {
            Some(h) => {
                KICKCFG_NEAR = h.near_addr();
                HOOK_KICKCFG = Box::into_raw(Box::new(h));
                results.push(true);
            }
            None => results.push(false),
        }
        // T10: 官方异步入房入口 (far stub, out-param 槽捕获) — 序言均以
        // 40 53|55|56|57|41 54 开始，最小完整覆盖是 7 字节。
        // T5 诊断: no_join → 不安装这两个 far stub (结果向量少两项, all-or-nothing 只看存在的项)
        if !no_join {
            match try_install(
                FN_JOIN_LOBBY,
                7,
                &SDK_PROLOGUE_RBX_R12,
                "JoinLobby",
                "PlayFabMultiplayerWin.dll",
                sdk_range,
                true,
                gbfr_join_stub as *const () as usize,
                std::ptr::addr_of_mut!(gbfr_join_tramp),
            ) {
                Some(h) => {
                    JOIN_NEAR = h.near_addr();
                    HOOK_JOIN = Box::into_raw(Box::new(h));
                    results.push(true);
                }
                None => results.push(false),
            }
            match try_install(
                FN_CREATE_JOIN,
                7,
                &SDK_PROLOGUE_RBX_R12,
                "CreateAndJoinLobby",
                "PlayFabMultiplayerWin.dll",
                sdk_range,
                true,
                gbfr_createjoin_stub as *const () as usize,
                std::ptr::addr_of_mut!(gbfr_createjoin_tramp),
            ) {
                Some(h) => {
                    CREATEJOIN_NEAR = h.near_addr();
                    HOOK_CREATEJOIN = Box::into_raw(Box::new(h));
                    results.push(true);
                }
                None => results.push(false),
            }
        } else {
            log("[kick] JOIN/CREATEJOIN skipped (diag no_join)");
        }
        if !decide_all_or_nothing(&results) {
            // T2: 全量回滚 — 本次调用已装的 hook 全部还原, 静态清零 (clear_hook = T5 幂等清理)
            let rollback_ok = clear_hook(std::ptr::addr_of_mut!(HOOK_POST))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_GETID))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_MEMBERS))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_OWNER))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_GETMP))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_GETLP))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_CONN))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_MEMCONN))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_KICKCFG))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_JOIN))
                | clear_hook(std::ptr::addr_of_mut!(HOOK_CREATEJOIN));
            let all_clear = std::ptr::read(std::ptr::addr_of!(HOOK_POST)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_GETID)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_MEMBERS)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_OWNER)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_GETMP)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_GETLP)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_CONN)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_MEMCONN)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_KICKCFG)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_JOIN)).is_null()
                && std::ptr::read(std::ptr::addr_of!(HOOK_CREATEJOIN)).is_null();
            if all_clear {
                POST_NEAR = 0; GETID_NEAR = 0; MEMBERS_NEAR = 0;
                OWNER_NEAR = 0; GETMP_NEAR = 0; GETLP_NEAR = 0; CONN_NEAR = 0; MEMCONN_NEAR = 0;
                KICKCFG_NEAR = 0; JOIN_NEAR = 0; CREATEJOIN_NEAR = 0;
                gbfr_kick_tramp = 0;
                gbfr_join_tramp = 0; gbfr_createjoin_tramp = 0;
                gbfr_join_out = 0; gbfr_createjoin_out = 0;
                LOBBY_JOIN = 0;
                log("[kick] PARTIAL INSTALL ROLLED BACK");
            } else {
                let _ = rollback_ok;
                log("[kick] PARTIAL INSTALL rollback FAILED — hook ownership retained");
            }
            return false;
        }
        log(&format!("[kick] hooks installed ({}: PostUpdate/GetLobbyId/GetMembers/GetOwner/GetMemberProperty/GetLobbyProperty/GetConnectionString/GetMemberConnectionStatus/KICKCFG-rdi-swap/JoinLobby/CreateAndJoinLobby)", results.len()));
        true
    }
}

// B29: 恢复全部 hook (unload 命令调用, 之后 FreeLibrary 才安全)
// T5: 幂等 — 二次调用全空槽 → no-op, 仅记 already unhooked; 与 T2 回滚路径共用 clear_hook
pub fn unhook() {
    unsafe {
        let any = clear_hook(std::ptr::addr_of_mut!(HOOK_POST))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_GETID))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_MEMBERS))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_OWNER))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_GETMP))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_GETLP))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_CONN))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_MEMCONN))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_KICKCFG))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_JOIN))
            | clear_hook(std::ptr::addr_of_mut!(HOOK_CREATEJOIN));
        POST_NEAR = 0; GETID_NEAR = 0; MEMBERS_NEAR = 0;
        OWNER_NEAR = 0; GETMP_NEAR = 0; GETLP_NEAR = 0; CONN_NEAR = 0; MEMCONN_NEAR = 0;
        KICKCFG_NEAR = 0; JOIN_NEAR = 0; CREATEJOIN_NEAR = 0;
        gbfr_kick_pending = 0;
        // T5: 与 T2 回滚路径一致 — 清零跳板指针, 防止重装前 stub 残留引用旧 tramp
        gbfr_kick_tramp = 0;
        // T10: 清零 join 槽/跳板/捕获值 — 重装前残留引用旧 tramp 或旧槽地址均不安全
        gbfr_join_tramp = 0; gbfr_createjoin_tramp = 0;
        gbfr_join_out = 0; gbfr_createjoin_out = 0;
        LOBBY_JOIN = 0;
        if any {
            log("[kick] hooks restored");
        } else {
            log("[kick] already unhooked");
        }
    }
}

// 纯函数: 按优先级顺序取第一个 (已安装 && 非零) 源的值 (lobby_handle 回退链, 单测注入假源列表)
fn pick_first_nonzero(sources: &[(bool, u64)]) -> u64 {
    for &(installed, v) in sources {
        if installed && v != 0 {
            return v;
        }
    }
    0
}

// ===== T10: 异步 out-param 槽轮询 =====
// 官方异步语义: JoinLobby/CreateAndJoinLobby 在异步完成时才写入 *lobby。stub 保存槽地址,
// 此处每 200ms (cmd_thread) 读槽值; 抓到非零有效句柄 → LOBBY_JOIN (one-shot), 清槽停轮询。
// 槽位于游戏栈/游戏自有缓冲 — 游戏保证 out 变量在异步完成前存活 (官方 API 契约), 读前仍以
// VirtualQuery MEM_COMMIT 守卫 (antikick mem_committed 同模式) 防 freed 槽 AV。

// 纯决策: 异步 handle 是堆指针, 必须 >= 0x10000 (0x10000 以下 = 非法/未写入)
fn slot_valid(v: u64) -> bool {
    v >= 0x10000
}

// 纯决策: Some(值) 当 槽地址非零 且 槽值合法; 否则 None (调用方区分: 值==0 → 继续轮询)
fn poll_decision(slot_addr: u64, slot_value: u64) -> Option<u64> {
    if slot_addr != 0 && slot_valid(slot_value) {
        Some(slot_value)
    } else {
        None
    }
}

// VirtualQuery 提交状态检查（轮询槽只在确认已提交后读取；完整可读性审计见 antikick::mem_readable）
unsafe fn mem_committed(p: usize) -> bool {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEM_COMMIT, MEMORY_BASIC_INFORMATION};
    let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
    VirtualQuery(p as *const core::ffi::c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0
        && mbi.State == MEM_COMMIT
}

// 轮询单个槽; slot 为 stub 的 out 槽静态地址 (addr_of_mut! 裸指针传, 不产生 &mut)
unsafe fn poll_one(slot: *mut u64, name: &str) {
    let addr = std::ptr::read(slot);
    if addr == 0 {
        return;
    }
    if !mem_committed(addr as usize) {
        log(&format!("[kick] {} slot 0x{:X} not committed — cleared", name, addr));
        std::ptr::write(slot, 0);
        return;
    }
    let value = std::ptr::read_unaligned(addr as *const u64);
    match poll_decision(addr, value) {
        Some(v) => {
            LOBBY_JOIN = v;
            std::ptr::write(slot, 0);
            log(&format!("[kick] auto-captured lobby via {}=0x{:X}", name, v));
        }
        None if value != 0 => {
            std::ptr::write(slot, 0);
            log(&format!("[kick] {} slot value 0x{:X} invalid — cleared", name, value));
        }
        None => {} // 值==0: 异步未完成, 保槽继续轮询
    }
}

// cmd_thread 每轮调用 (两次静态检查, 极廉)
pub fn poll_join_out() {
    unsafe {
        poll_one(std::ptr::addr_of_mut!(gbfr_join_out), "JoinLobby");
        poll_one(std::ptr::addr_of_mut!(gbfr_createjoin_out), "CreateAndJoinLobby");
    }
}

// 读取捕获的 rcx (lobby handle)
pub fn lobby_handle() -> u64 {
    unsafe {
        // 优先级: MEMBERS (B29 最高频) > POST (B12 动态验证) > GETID > OWNER > GETMP > GETLP > CONN > MEMCONN (T9)
        // > JOIN (T10: 异步入房 out-param 槽, 最后回退 — 只有用户新建/加入房间时触发)
        // saved 槽偏移以 detour::CAP_SAVED_OFF 为准 (T2/BLOCKER-2 后为 +0x20)
        let read = |near: usize| -> (bool, u64) {
            if near == 0 {
                (false, 0)
            } else {
                (true, std::ptr::read_unaligned((near + detour::CAP_SAVED_OFF) as *const u64))
            }
        };
        pick_first_nonzero(&[
            read(MEMBERS_NEAR),
            read(POST_NEAR),
            read(GETID_NEAR),
            read(OWNER_NEAR),
            read(GETMP_NEAR),
            read(GETLP_NEAR),
            read(CONN_NEAR),
            read(MEMCONN_NEAR),
            // LOBBY_JOIN 直接拷贝值 (不取引用, static_mut_refs 零新增)
            (true, std::ptr::read_unaligned(std::ptr::addr_of!(LOBBY_JOIN))),
        ])
    }
}

// T9: 各捕获源调用计数 (state 命令观察 live 触发情况; 未安装的 hook = 0)
pub fn lobby_sources() -> String {
    unsafe {
        let c = |h: *mut detour::Hook| -> u64 {
            if h.is_null() { 0 } else { (*h).counts() }
        };
        let joined = std::ptr::read_unaligned(std::ptr::addr_of!(LOBBY_JOIN));
        format!(
            "members={} post={} getid={} owner={} getmp={} getlp={} conn={} memconn={} join={} createjoin={}",
            c(HOOK_MEMBERS), c(HOOK_POST), c(HOOK_GETID),
            c(HOOK_OWNER), c(HOOK_GETMP), c(HOOK_GETLP), c(HOOK_CONN), c(HOOK_MEMCONN),
            joined, joined
        )
    }
}

// ===== T4: 安全踢人闸门 =====
// 官方正向实现路径 (B21/BLOCKER-1): PFLobbyForceRemoveMember(handle, PFEntityKey*, r8b, ctx)
// 闸门顺序 (a)-(d) 全部通过才允许任何 mutation (调用 SDK / 改写 UI 踢人)
#[derive(Debug, PartialEq, Eq)]
enum KickGateResult {
    Ok,
    BadId,
    ForceUnavailable,
    NoHandle,
    HandleInvalid,
}

// 纯函数闸门 (a) id 16 字符 (b) ForceRemoveMember 已解析 (c) lobby handle 非零 (d) handle 已通过 GetLobbyId 自检
fn kick_gate(id: &str, force_available: bool, handle: u64, handle_valid: bool) -> KickGateResult {
    if id.len() != 16 { return KickGateResult::BadId; }
    if !force_available { return KickGateResult::ForceUnavailable; }
    if handle == 0 { return KickGateResult::NoHandle; }
    if !handle_valid { return KickGateResult::HandleInvalid; }
    KickGateResult::Ok
}

// (d) GetLobbyId 动态自检: 调真实 SDK 导出 (transmute 同 scan.rs 模式), 失败即拒绝 — 绝不静默跳过
fn getid_self_check(handle: u64) -> bool {
    unsafe {
        let getid = FN_GET_LOBBY_ID;
        if getid == 0 {
            log("[kick] GetLobbyId not resolved — handle UNVERIFIED, refusing");
            return false;
        }
        let f: unsafe extern "system" fn(u64, *mut u64) -> i32 = std::mem::transmute(getid);
        let mut out_id: u64 = 0;
        let ret = f(handle, &mut out_id);
        if ret != 0 {
            log(&format!("[kick] lobby handle INVALID (GetLobbyId ret=0x{:X})", ret));
            return false;
        }
        log("[kick] lobby handle validated (GetLobbyId ok)");
        true
    }
}

// (e) PFEntityKey 构建: ACTIVE 路径布局 {char* id, char* type} (B12/B14/MINOR-3, wrapper 0x3B4BB70 读 [rdx]/[rdx+8])
// 有效: buf = [id 堆分配指针, KICK_TYPE 指针]; 无效 (含 NUL / 长度非 16) → false
fn build_entity(id: &str, id_out: &mut CString, buf: &mut [u64; 2]) -> bool {
    if id.len() != 16 {
        return false;
    }
    match CString::new(id) {
        Ok(c) => {
            *id_out = c;
            buf[0] = id_out.as_ptr() as u64;
            buf[1] = KICK_TYPE.as_ptr() as u64;
            true
        }
        Err(_) => false,
    }
}

pub fn do_kick(target_id: &str) {
    unsafe {
        let id = target_id.trim();
        // 闸门 (a)-(d); GetLobbyId 自检仅对非零 handle 执行 (只读校验, 无 mutation)
        let handle = lobby_handle();
        let handle_valid = if handle != 0 { getid_self_check(handle) } else { false };
        match kick_gate(id, FN_FORCE_REMOVE != 0, handle, handle_valid) {
            KickGateResult::Ok => {}
            KickGateResult::BadId => { log(&format!("[kick] invalid id: {}", id)); return; }
            KickGateResult::ForceUnavailable => { log("[kick] ForceRemoveMember not resolved"); return; }
            KickGateResult::NoHandle => { log("[kick] lobby handle not captured (open member list / enter room first)"); return; }
            KickGateResult::HandleInvalid => { return; }
        }

        // 主路径: 官方 PFLobbyForceRemoveMember (B21/BLOCKER-1) — 闸门通过后唯一允许的 mutation 入口
        let mut id_out = CString::new("").unwrap_or_default();
        let mut buf: [u64; 2] = [0; 2];
        if !build_entity(id, &mut id_out, &mut buf) {
            log(&format!("[kick] invalid id: {}", id));
            return;
        }
        let force: unsafe extern "system" fn(u64, *const u64, u8, u64) -> i32 =
            std::mem::transmute(FN_FORCE_REMOVE);
        let ret = force(handle, buf.as_ptr(), 0u8, 0u64);
        log(&format!(
            "[kick] ForceRemoveMember ret=0x{:X} handle=0x{:X} target={} (0=accepted, async result via lobby state change)",
            ret, handle, id
        ));

        // 隔离的 KICKCFG-rdi-swap 实验路径: 默认拒绝; 仅 kickcfg_exp on 且 handle 已验证时设置 pending
        if KICKCFG_EXPERIMENTAL.load(Ordering::Relaxed) {
            set_pending_kick(id);
            log(&format!(
                "[kick] KICKCFG-rdi-swap pending set: {} (EXPERIMENTAL) — next UI kick will be redirected",
                id
            ));
        } else {
            log("[kick] KICKCFG-rdi-swap is EXPERIMENTAL and DISABLED by default (use kickcfg_exp on to enable)");
        }
        log("[kick] single-variable: do NOT also enable kickcfg_exp or antikick for this experiment");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_or_nothing_all_true() {
        assert!(decide_all_or_nothing(&[true, true, true, true]));
        assert!(decide_all_or_nothing(&[true; 9]));
        assert!(decide_all_or_nothing(&[true; 11]));
        assert!(decide_all_or_nothing(&[]));
    }

    #[test]
    fn all_or_nothing_any_false() {
        assert!(!decide_all_or_nothing(&[false]));
        assert!(!decide_all_or_nothing(&[true, false, true]));
        assert!(!decide_all_or_nothing(&[true, true, false, true]));
        // T9: 9 元素 — 任一位置为 false 必须整体失败
        for i in 0..9 {
            let mut v = [true; 9];
            v[i] = false;
            assert!(!decide_all_or_nothing(&v), "index {} must fail", i);
        }
        // T10: 11 元素 (9 捕获 + KICKCFG + JOIN + CREATEJOIN) — 任一位置为 false 必须整体失败
        for i in 0..11 {
            let mut v = [true; 11];
            v[i] = false;
            assert!(!decide_all_or_nothing(&v), "index {} must fail", i);
        }
    }

    // ===== T10: 异步 out-param 槽决策 =====
    #[test]
    fn slot_valid_rejects_low_values() {
        // 异步 handle 是堆指针: < 0x10000 视为非法 (未写入/NULL/伪句柄)
        assert!(!slot_valid(0));
        assert!(!slot_valid(0xFFFF));
        assert!(slot_valid(0x10000));
        assert!(slot_valid(0x7FFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn poll_decision_all_combos() {
        // 槽地址为 0 (未捕获) → None, 无论值
        assert_eq!(poll_decision(0, 0), None);
        assert_eq!(poll_decision(0, 0x10000), None);
        // 槽地址非零但值非法 (0 / <0x10000) → None
        assert_eq!(poll_decision(0x1234, 0), None);
        assert_eq!(poll_decision(0x1234, 0x8000), None);
        assert_eq!(poll_decision(0x1234, 0xFFFF), None);
        // 槽地址非零且值合法 → Some(值)
        assert_eq!(poll_decision(0x1234, 0x10000), Some(0x10000));
        assert_eq!(
            poll_decision(0x1234, 0xABCD_EF00_1234_5678),
            Some(0xABCD_EF00_1234_5678)
        );
    }

    // ===== T9: lobby_handle 回退优先级 =====
    #[test]
    fn pick_first_nonzero_priority_order() {
        // 空列表 / 全部未安装 → 0
        assert_eq!(pick_first_nonzero(&[]), 0);
        assert_eq!(pick_first_nonzero(&[(false, 0x100)]), 0);
        // 已安装但 saved=0 → 继续回退
        assert_eq!(pick_first_nonzero(&[(true, 0), (true, 0xABC)]), 0xABC);
        // 优先级 = 列表顺序: 第一个非零胜出
        assert_eq!(pick_first_nonzero(&[(true, 0x111), (true, 0x222)]), 0x111);
        // 未安装的更高优先源 (false) 不遮蔽后面的已安装源
        assert_eq!(pick_first_nonzero(&[(false, 0x222), (true, 0x333)]), 0x333);
        // 全部已安装且 saved=0 → 0
        assert_eq!(pick_first_nonzero(&[(true, 0), (true, 0)]), 0);
    }

    // ===== T4: 安全踢人闸门测试 =====
    const GOOD_ID: &str = "0123456789abcdef";

    #[test]
    fn gate_all_branches() {
        assert_eq!(kick_gate(GOOD_ID, true, 0x1234, true), KickGateResult::Ok);
        assert_eq!(kick_gate("short", true, 0x1234, true), KickGateResult::BadId);
        assert_eq!(kick_gate("0123456789abcdefg", true, 0x1234, true), KickGateResult::BadId);
        assert_eq!(kick_gate(GOOD_ID, false, 0x1234, true), KickGateResult::ForceUnavailable);
        assert_eq!(kick_gate(GOOD_ID, true, 0, true), KickGateResult::NoHandle);
        assert_eq!(kick_gate(GOOD_ID, true, 0x1234, false), KickGateResult::HandleInvalid);
        // 分支优先级: BadId > ForceUnavailable > NoHandle > HandleInvalid
        assert_eq!(kick_gate("bad", false, 0, false), KickGateResult::BadId);
        assert_eq!(kick_gate(GOOD_ID, false, 0, false), KickGateResult::ForceUnavailable);
        assert_eq!(kick_gate(GOOD_ID, true, 0, false), KickGateResult::NoHandle);
    }

    #[test]
    fn pending_allowed_flag_gate() {
        assert!(!pending_allowed(false, 0x1234));
        assert!(!pending_allowed(true, 0));
        assert!(pending_allowed(true, 0x1234));
    }

    #[test]
    fn build_entity_valid_16hex() {
        let mut id_out = CString::new("").unwrap();
        let mut buf = [0u64; 2];
        assert!(build_entity(GOOD_ID, &mut id_out, &mut buf));
        // ACTIVE 路径布局: buf = [id*, type*]
        assert_eq!(buf[0], id_out.as_ptr() as u64);
        assert_eq!(buf[1], KICK_TYPE.as_ptr() as u64);
        let s = unsafe { std::ffi::CStr::from_ptr(buf[0] as *const i8) };
        assert_eq!(s.to_str().unwrap(), GOOD_ID);
    }

    #[test]
    fn build_entity_rejects_invalid() {
        let mut id_out = CString::new("").unwrap();
        let mut buf = [0u64; 2];
        assert!(!build_entity("short", &mut id_out, &mut buf));
        assert!(!build_entity("0123456789abcdefg", &mut id_out, &mut buf));
        assert!(!build_entity("0123456789ab\0cde", &mut id_out, &mut buf));
    }

    // ===== T5: 幂等 unhook =====
    #[test]
    fn slot_held_null_is_noop_decision() {
        // 纯决策: null → false (不执行恢复); 非空哨兵 → true (不触碰内存, 仅判空)
        assert!(!slot_held(std::ptr::null()));
        assert!(slot_held(0x1234_5678_9ABC_DEF0 as *const detour::Hook));
    }

    #[test]
    fn clear_hook_null_slot_is_noop() {
        // 空槽清理: 返回 false 且槽保持 null (二次 unhook 的安全路径)
        let mut h: *mut detour::Hook = std::ptr::null_mut();
        unsafe {
            assert!(!clear_hook(&mut h));
            assert!(h.is_null());
        }
    }}
