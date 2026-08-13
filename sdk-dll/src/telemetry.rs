// T1: 被动原生踢人时间线记录器 (pure telemetry, 零行为变更)
// 目标 (plan Todo 1): 一次运行关联 state-change 类型时序、本地 PFLobbyLeave、断连事件 —
// 为 T2 的原生 vs 官方踢人路径分类器提供被动证据。
//
// 被动性契约 (B22/MAJOR-1):
// - 只在 PFMultiplayerFinishProcessingLobbyStateChanges 入口窥探 (count, stateChanges):
//   每项仅读 stateChangeType@+0 (与 MemberRemoved 的 lobby@+8), 全部 VirtualQuery 守卫
// - 不额外调用 Start/Finish, 不改数组/计数, 不增删 change；原 Finish 调用仍 exact-once
// - 官方签名: FinishProcessing(handle, uint32_t count, const PFLobbyStateChange* const* changes)
//   → 参数经寄存器: rcx=handle, edx=count, r8=changes；资源在该调用前仍保证有效
// - PFLobbyStateChange 首字段 uint32 stateChangeType (+0); PFLobbyMemberRemovedStateChange 的
//   PFLobbyHandle lobby 位于 +8 (PFLobby.h:1278-1288, 1442-1447, 均为 2026-08-11 静态确认)
//
// 安装协调 (learnings/issues):
// - telemetry 仍等 MP_HANDLE!=0 后安装，避免注入初始化阶段触碰 SDK 热路径
// - 日志预算 64 条/run (TEL_BUDGET_CAP), 防每帧日志刷屏; 预算耗尽即静默
// - Finish 仅在游戏已处理完 state changes 后触发；format!/Vec 分配仅发生在目标类型存在时
use crate::antikick::{mem_readable, ptr_safe};
use crate::detour;
use crate::sdk::{FN_FINISH_PROCESSING, FN_LEAVE};
use crate::{log, MP_HANDLE};
use std::sync::atomic::{AtomicU64, Ordering};

const TEL_BUDGET_CAP: u64 = 64;
const TEL_CHANGE_COUNT_MAX: u32 = 1024;
static TEL_BUDGET_USED: AtomicU64 = AtomicU64::new(0);
static TEL_FINISH_PROBE_USED: AtomicU64 = AtomicU64::new(0);
const TEL_FINISH_PROBE_CAP: u64 = 16;

// 关注的 state change 类型 (官方 PFLobbyStateChangeType, PFLobby.h:160-216)
#[derive(PartialEq, Clone, Copy, Debug)]
enum TelKind {
    Ignore,
    MemberRemoved,
    Updated,
    Disconnecting,
    Disconnected,
}

impl TelKind {
    fn name(&self) -> &'static str {
        match self {
            TelKind::Ignore => "Ignore",
            TelKind::MemberRemoved => "MemberRemoved",
            TelKind::Updated => "Updated",
            TelKind::Disconnecting => "Disconnecting",
            TelKind::Disconnected => "Disconnected",
        }
    }
}

// 类型分类 (纯函数): 4=MemberRemoved, 7=Updated, 9=Disconnecting, 10=Disconnected, 其余 Ignore
fn classify_type(t: u32) -> TelKind {
    match t {
        4 => TelKind::MemberRemoved,
        7 => TelKind::Updated,
        9 => TelKind::Disconnecting,
        10 => TelKind::Disconnected,
        _ => TelKind::Ignore,
    }
}

// 窥探第 i 个 change 的类型: stateChanges 是 `const PFLobbyStateChange* const*` (8 字节指针数组);
// 读指针 → ptr_safe+mem_readable 守卫 → 读 u32@+0 (stateChangeType 首字段)。任一守卫失败 → None。
fn entry_type_guarded(changes: u64, i: usize) -> Option<u32> {
    unsafe {
        let slot = changes.checked_add((i as u64).checked_mul(8)?)?;
        if !ptr_safe(slot, mem_readable(slot as usize, 8)) {
            return None;
        }
        let p = std::ptr::read_unaligned(slot as *const u64);
        if !ptr_safe(p, mem_readable(p as usize, 4)) {
            return None;
        }
        Some(std::ptr::read_unaligned(p as *const u32))
    }
}

// count 范围守卫 (纯函数): (0, 1024]
fn count_in_range(n: u32) -> bool {
    0 < n && n <= TEL_CHANGE_COUNT_MAX
}

// 预算决策 (纯函数): 未达上限才允许记录
fn budget_allowed(used: u64, cap: u64) -> bool {
    used < cap
}

// 取一条日志预算 (CAS, 无锁): 成功返回 true 且 used+1, 耗尽返回 false
fn budget_take() -> bool {
    let mut used = TEL_BUDGET_USED.load(Ordering::Relaxed);
    loop {
        if !budget_allowed(used, TEL_BUDGET_CAP) {
            return false;
        }
        match TEL_BUDGET_USED.compare_exchange_weak(used, used + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(cur) => used = cur,
        }
    }
}

// 安装许可 (纯函数, 单测): handle 已抓 + Finish/Leave 均已解析 + 未安装
fn tel_install_allowed(handle: u64, finish_resolved: bool, leave_resolved: bool, installed: bool) -> bool {
    handle != 0 && finish_resolved && leave_resolved && !installed
}

// Phase 2C S2: leave-only 安装许可 (纯函数, 单测) — 只要 handle 已抓 + Leave 已解析 + 未装
fn tel_leave_install_allowed(handle: u64, leave_resolved: bool, installed: bool) -> bool {
    handle != 0 && leave_resolved && !installed
}

// ===== far stubs (detour::install_far 从近块跳到这里, 风格镜像 antikick.rs/kick.rs) =====
// Finish/Leave 都是 SDK 导出入口：任何原始参数都必须原样传给 trampoline。
// 入口 rsp%16=8; 7×push(0x38) → 0; sub 0x20 → call 前 0；保存并恢复全部 volatile
// (rax,rcx,rdx,r8,r9,r10,r11)，避免 telemetry call 破坏原 API 的 rdx/r8/r9 参数。
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_tel_finish_stub
gbfr_tel_finish_stub:
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rcx, rcx
    // Finish signature is (handle, count, changes); helper receives (count, changes).
    mov ecx, edx
    mov rdx, r8
    mov rax, qword ptr [rip + gbfr_tel_finish_fn]
    test rax, rax
    je gbfr_tel_finish_skip
    sub rsp, 0x20
    call rax
    add rsp, 0x20
gbfr_tel_finish_skip:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    jmp qword ptr [rip + gbfr_tel_finish_tramp]
    .data
    .global gbfr_tel_finish_fn
gbfr_tel_finish_fn:
    .quad 0
    .global gbfr_tel_finish_tramp
gbfr_tel_finish_tramp:
    .quad 0
    "#
);
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_tel_leave_stub
gbfr_tel_leave_stub:
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rax, qword ptr [rip + gbfr_tel_leave_fn]
    test rax, rax
    je gbfr_tel_leave_skip
    sub rsp, 0x20
    call rax
    add rsp, 0x20
gbfr_tel_leave_skip:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    jmp qword ptr [rip + gbfr_tel_leave_tramp]
    .data
    .global gbfr_tel_leave_fn
gbfr_tel_leave_fn:
    .quad 0
    .global gbfr_tel_leave_tramp
gbfr_tel_leave_tramp:
    .quad 0
    "#
);
unsafe extern "C" {
    fn gbfr_tel_finish_stub();
    static mut gbfr_tel_finish_fn: u64;
    static mut gbfr_tel_finish_tramp: u64;
    fn gbfr_tel_leave_stub();
    static mut gbfr_tel_leave_fn: u64;
    static mut gbfr_tel_leave_tramp: u64;
}

static mut TEL_FINISH_NEAR: usize = 0;
static mut TEL_LEAVE_NEAR: usize = 0;
static mut HOOK_TEL_FINISH: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_TEL_LEAVE: *mut detour::Hook = std::ptr::null_mut();

// FinishProcessing 入口窥探 (stub 以 rcx=count, rdx=changes 调用):
// count 范围检查 → changes 守卫 → 逐项窥探类型 (只读) → 有目标类型才记 1 条 batch 行 +
// 每条 MemberRemoved 附 lobby@+8 行; 全部受预算约束。绝不消费/改写任何 change。
unsafe extern "system" fn tel_finish_poll(count: u64, changes: u64) {
    let probe = TEL_FINISH_PROBE_USED.fetch_add(1, Ordering::Relaxed);
    if probe < TEL_FINISH_PROBE_CAP {
        log(&format!("[tel] finish_probe count={} changes=0x{:X}", count, changes));
    }
    if !count_in_range(count as u32) || !ptr_safe(changes, mem_readable(changes as usize, 8)) {
        return;
    }
    let mut kinds: Vec<TelKind> = Vec::new();
    let mut mr_lobbies: Vec<u64> = Vec::new();
    for i in 0..count as usize {
        let Some(t) = entry_type_guarded(changes, i) else { continue };
        let k = classify_type(t);
        if k == TelKind::Ignore {
            continue;
        }
        if !kinds.contains(&k) {
            kinds.push(k);
        }
        if k == TelKind::MemberRemoved {
            // lobby handle 位于 change+8 (PFLobbyMemberRemovedStateChange 首字段)
            let Some(slot) = changes.checked_add((i as u64).saturating_mul(8)) else { continue };
            let p = std::ptr::read_unaligned(slot as *const u64);
            let Some(lobby_addr) = p.checked_add(8) else { continue };
            if ptr_safe(lobby_addr, mem_readable(lobby_addr as usize, 8)) {
                mr_lobbies.push(std::ptr::read_unaligned(lobby_addr as *const u64));
            }
        }
    }
    if kinds.is_empty() {
        return;
    }
    if !budget_take() {
        return;
    }
    let names: Vec<&str> = kinds.iter().map(|k| k.name()).collect();
    log(&format!("[tel] statechanges n={} types=[{}]", count, names.join(",")));
    for &l in &mr_lobbies {
        if budget_take() {
            log(&format!("[tel] memberremoved lobby=0x{:X}", l));
        } else {
            break;
        }
    }
}

// PFLobbyLeave 调用记录 (rcx=lobby handle; 仅日志, 零解引用 — handle 可能为 0)
unsafe extern "system" fn tel_leave(handle: u64) {
    if budget_take() {
        log(&format!("[tel] PFLobbyLeave handle=0x{:X}", handle));
    }
}

// 预检 + 安装单个 far stub (kick.rs try_install 同款模式)
unsafe fn tel_try_install(
    target: usize,
    len: usize,
    expected: &[u8],
    name: &str,
    module: &str,
    range: Option<(u64, usize)>,
    stub: usize,
    trampoline_slot: *mut u64,
) -> Option<detour::Hook> {
    if target == 0 {
        log(&format!("[tel] {} addr unavailable", name));
        return None;
    }
    if !detour::preflight(target, module, range) {
        return None;
    }
    let actual = std::slice::from_raw_parts(target as *const u8, expected.len());
    if actual != expected {
        log(&format!(
            "[tel] {} signature mismatch want={} got={}",
            name,
            detour::hex16(expected),
            detour::hex16(actual)
        ));
        return None;
    }
    let h = detour::install_far(target, len, stub, trampoline_slot);
    if h.is_some() {
        log(&format!("[tel] {} installed (module={})", name, module));
    }
    h
}

// 安装两个 telemetry far stub (幂等: 已装 / 门控不过 → 静默 false; all-or-nothing 回滚)
pub fn install() -> bool {
    // T5 诊断: no_telemetry → 永不安装 (unhook 幂等, 空槽 no-op 安全)
    if crate::DIAG_NO_TELEMETRY.load(Ordering::Relaxed) {
        log("[tel] SKIPPED (diag no_telemetry)");
        return false;
    }
    unsafe {
        let handle = MP_HANDLE.load(Ordering::Relaxed);
        let finish = std::ptr::read_unaligned(std::ptr::addr_of!(FN_FINISH_PROCESSING));
        let leave = std::ptr::read_unaligned(std::ptr::addr_of!(FN_LEAVE));
        let finish_slot = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_FINISH));
        let leave_slot = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_LEAVE));
        if !tel_install_allowed(handle, finish != 0, leave != 0, !finish_slot.is_null() || !leave_slot.is_null()) {
            return false;
        }
        // fn 槽必须先于 patch 生效 (patch 后 stub 可能即刻被执行)
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_finish_fn), tel_finish_poll as *const () as usize as u64);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_fn), tel_leave as *const () as usize as u64);
        let range = detour::module_range("PlayFabMultiplayerWin.dll");
        let mut finish_h = tel_try_install(
            finish,
            6,
            &[0x40, 0x55, 0x56, 0x57, 0x41, 0x54],
            "FinishProcessing",
            "PlayFabMultiplayerWin.dll",
            range,
            gbfr_tel_finish_stub as *const () as usize,
            std::ptr::addr_of_mut!(gbfr_tel_finish_tramp),
        );
        if let Some(h) = &finish_h {
            std::ptr::write(std::ptr::addr_of_mut!(TEL_FINISH_NEAR), h.near_addr());
        }
        let mut leave_h = tel_try_install(
            leave,
            7,
            &[0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54],
            "Leave",
            "PlayFabMultiplayerWin.dll",
            range,
            gbfr_tel_leave_stub as *const () as usize,
            std::ptr::addr_of_mut!(gbfr_tel_leave_tramp),
        );
        if let Some(h) = &leave_h {
            std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), h.near_addr());
        }
        match (&mut finish_h, &mut leave_h) {
            (Some(_), Some(_)) => {
                let fh = finish_h.take().unwrap();
                let lh = leave_h.take().unwrap();
                std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_FINISH), Box::into_raw(Box::new(fh)));
                std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_LEAVE), Box::into_raw(Box::new(lh)));
                log("[tel] hooks installed (FinishProcessing/Leave)");
                true
            }
            _ => {
                let mut rollback_ok = true;
                if let Some(h) = finish_h.as_mut() {
                    rollback_ok &= h.restore();
                }
                if let Some(h) = leave_h.as_mut() {
                    rollback_ok &= h.restore();
                }
                if !rollback_ok {
                    log("[tel] install rollback FAILED — refusing to discard hook ownership");
                    if let Some(h) = finish_h.take() {
                        std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_FINISH), Box::into_raw(Box::new(h)));
                    }
                    if let Some(h) = leave_h.take() {
                        std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_LEAVE), Box::into_raw(Box::new(h)));
                    }
                    return false;
                }
                std::ptr::write(std::ptr::addr_of_mut!(TEL_FINISH_NEAR), 0);
                std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), 0);
                std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_finish_tramp), 0);
                std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_tramp), 0);
                log("[tel] install FAILED (FinishProcessing/Leave) — all hooks rolled back");
                false
            }
        }
    }
}

// Phase 2C S2: leave-only 选择器安装 — 只装 PFLobbyLeave 被动记录 far stub,
// 不装 FinishProcessing probe (隔离 H2 嫌疑组, 见 phase2c plan §6 S2 细化)。
// 幂等: handle 未抓 / Leave 未解析 / 已装 → 静默 false; no_telemetry → 永不安装。
// 与 install() 共享 gbfr_tel_leave_stub / gbfr_tel_leave_tramp / HOOK_TEL_LEAVE / TEL_LEAVE_NEAR,
// 因此 unhook() 已覆盖 (finish 槽为空 → 跳过, 幂等)。
pub fn install_leave_only() -> bool {
    if crate::DIAG_NO_TELEMETRY.load(Ordering::Relaxed) {
        log("[tel] leave-only SKIPPED (diag no_telemetry)");
        return false;
    }
    unsafe {
        let handle = MP_HANDLE.load(Ordering::Relaxed);
        let leave = std::ptr::read_unaligned(std::ptr::addr_of!(FN_LEAVE));
        let leave_slot = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_LEAVE));
        if !tel_leave_install_allowed(handle, leave != 0, !leave_slot.is_null()) {
            return false;
        }
        // fn 槽必须先于 patch 生效 (patch 后 stub 可能即刻被执行)
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_fn), tel_leave as *const () as usize as u64);
        match tel_try_install(
            leave,
            7,
            &[0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54],
            "Leave",
            "PlayFabMultiplayerWin.dll",
            detour::module_range("PlayFabMultiplayerWin.dll"),
            gbfr_tel_leave_stub as *const () as usize,
            std::ptr::addr_of_mut!(gbfr_tel_leave_tramp),
        ) {
            Some(h) => {
                std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), h.near_addr());
                std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_LEAVE), Box::into_raw(Box::new(h)));
                log("[tel] leave-only hook installed (PFLobbyLeave)");
                true
            }
            None => {
                std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_tramp), 0);
                log("[tel] leave-only install FAILED (rolled back)");
                false
            }
        }
    }
}

// 恢复两个 hook (幂等: 双槽皆空 → no-op 早退; Box::from_raw 恰好一次)
pub fn unhook() {
    unsafe {
        let finish = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_FINISH));
        let leave = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_LEAVE));
        if finish.is_null() && leave.is_null() {
            log("[tel] already unhooked");
            return;
        }
        if !finish.is_null() {
            if !(*finish).restore() {
                log("[tel] FinishProcessing restore FAILED — slot retained");
                return;
            }
            let _ = Box::from_raw(finish);
            std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_FINISH), std::ptr::null_mut());
        }
        if !leave.is_null() {
            if !(*leave).restore() {
                log("[tel] Leave restore FAILED — slot retained");
                return;
            }
            let _ = Box::from_raw(leave);
            std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_LEAVE), std::ptr::null_mut());
        }
        std::ptr::write(std::ptr::addr_of_mut!(TEL_FINISH_NEAR), 0);
        std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), 0);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_finish_tramp), 0);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_tramp), 0);
        log("[tel] hooks restored");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_and_unknown_types() {
        assert_eq!(classify_type(4), TelKind::MemberRemoved);
        assert_eq!(classify_type(7), TelKind::Updated);
        assert_eq!(classify_type(9), TelKind::Disconnecting);
        assert_eq!(classify_type(10), TelKind::Disconnected);
        for t in [0u32, 1, 2, 3, 5, 6, 8, 11, 0xFFFF_FFFF] {
            assert_eq!(classify_type(t), TelKind::Ignore);
        }
        assert_eq!(TelKind::MemberRemoved.name(), "MemberRemoved");
        assert_eq!(TelKind::Disconnected.name(), "Disconnected");
    }

    #[test]
    fn entry_type_rejects_null_low_uncommitted_and_accepts_valid() {
        unsafe {
            // null / 低地址 changes → slot 守卫失败
            assert_eq!(entry_type_guarded(0, 0), None);
            assert_eq!(entry_type_guarded(0x8000, 0), None);
            // 已提交数组但槽值为 0 / 未提交 → 值守卫失败
            let zero_arr = Box::new([0u64; 1]);
            assert_eq!(entry_type_guarded(zero_arr.as_ptr() as u64, 0), None);
            use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS};
            let reserved = VirtualAlloc(std::ptr::null_mut(), 0x1000, MEM_RESERVE, PAGE_NOACCESS);
            assert!(!reserved.is_null());
            let bad_arr = Box::new([reserved as u64; 1]);
            assert_eq!(entry_type_guarded(bad_arr.as_ptr() as u64, 0), None);
            VirtualFree(reserved, 0, MEM_RELEASE);
            // 有效合成 change: stateChangeType=4@+0
            let sc = Box::new(4u32);
            let arr = Box::new([&*sc as *const u32 as u64; 1]);
            assert_eq!(entry_type_guarded(arr.as_ptr() as u64, 0), Some(4));
        }
    }

    #[test]
    fn count_range_bounds() {
        assert!(!count_in_range(0));
        assert!(count_in_range(1));
        assert!(count_in_range(1024));
        assert!(!count_in_range(1025));
    }

    #[test]
    fn budget_cap_boundary() {
        assert!(budget_allowed(0, 64));
        assert!(budget_allowed(63, 64));
        assert!(!budget_allowed(64, 64));
        assert!(!budget_allowed(64, 0));
    }

    #[test]
    fn install_gate_combinations() {
        assert!(!tel_install_allowed(0, true, true, false));
        assert!(!tel_install_allowed(0x100, false, true, false));
        assert!(!tel_install_allowed(0x100, true, false, false));
        assert!(!tel_install_allowed(0x100, true, true, true));
        assert!(tel_install_allowed(0x100, true, true, false));
    }

    #[test]
    fn leave_only_install_gate_combinations() {
        // Phase 2C S2: handle 未抓 / Leave 未解析 / 已装 → 拒绝; 仅全过允许
        assert!(!tel_leave_install_allowed(0, true, false));
        assert!(!tel_leave_install_allowed(0x100, false, false));
        assert!(!tel_leave_install_allowed(0x100, true, true));
        assert!(tel_leave_install_allowed(0x100, true, false));
    }

    #[test]
    fn leave_handler_logs_and_consumes_budget() {
        TEL_BUDGET_USED.store(0, Ordering::Relaxed);
        unsafe { tel_leave(0); }
        assert_eq!(TEL_BUDGET_USED.load(Ordering::Relaxed), 1);
        unsafe { tel_leave(0x1234); }
        assert_eq!(TEL_BUDGET_USED.load(Ordering::Relaxed), 2);
        TEL_BUDGET_USED.store(TEL_BUDGET_CAP, Ordering::Relaxed);
        unsafe { tel_leave(0x5678); }
        assert_eq!(TEL_BUDGET_USED.load(Ordering::Relaxed), TEL_BUDGET_CAP);
    }
}
