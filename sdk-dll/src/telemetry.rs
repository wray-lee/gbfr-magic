// T1: 被动原生踢人时间线记录器 (pure telemetry, 零行为变更)
// 目标 (plan Todo 1): 一次运行关联 state-change 类型时序、本地 PFLobbyLeave、断连事件 —
// 为 T2 的原生 vs 官方踢人路径分类器提供被动证据。
//
// 被动性契约 (B22/MAJOR-1):
// - 只窥探 PFMultiplayerStartProcessingLobbyStateChanges 的 (count, stateChanges) 输出:
//   每项仅读 stateChangeType@+0 (与 MemberRemoved 的 lobby@+8), 全部 VirtualQuery 守卫
// - 绝不调 FinishProcessing, 绝不改数组/计数, 绝不消费任何 change
// - 官方签名 (PFLobby.h:3020-3024): StartProcessing(handle, uint32_t* count, const PFLobbyStateChange* const** changes)
//   → 参数经寄存器: rcx=handle, rdx=count ptr, r8=changes ptr
// - PFLobbyStateChange 首字段 uint32 stateChangeType (+0); PFLobbyMemberRemovedStateChange 的
//   PFLobbyHandle lobby 位于 +8 (PFLobby.h:1278-1288, 1442-1447, 均为 2026-08-11 静态确认)
//
// 安装协调 (learnings/issues):
// - StartProcessing 同一导出已被 sdk.rs GRAB_HOOK (install_capture) 占用 —
//   telemetry 的 far stub 必须等 MP_HANDLE!=0 (grab 已恢复) 后才装 (tel_install_allowed 闸门)
// - 日志预算 64 条/run (TEL_BUDGET_CAP), 防每帧日志刷屏; 预算耗尽即静默
// - 热路径极简: 仅守卫窥探 + 条件单行日志; format!/Vec 分配仅发生在实际记录时
use crate::antikick::{mem_committed, ptr_safe};
use crate::detour;
use crate::sdk::{FN_LEAVE, FN_START_PROCESSING};
use crate::{log, MP_HANDLE};
use std::sync::atomic::{AtomicU64, Ordering};

const TEL_BUDGET_CAP: u64 = 64;
const TEL_CHANGE_COUNT_MAX: u32 = 1024;
static TEL_BUDGET_USED: AtomicU64 = AtomicU64::new(0);

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
// 读指针 → ptr_safe+mem_committed 守卫 → 读 u32@+0 (stateChangeType 首字段)。任一守卫失败 → None。
fn entry_type_guarded(changes: u64, i: usize) -> Option<u32> {
    unsafe {
        let slot = changes + (i as u64) * 8;
        if !ptr_safe(slot, mem_committed(slot as usize)) {
            return None;
        }
        let p = std::ptr::read_unaligned(slot as *const u64);
        if !ptr_safe(p, mem_committed(p as usize)) {
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

// 安装许可 (纯函数, 单测): handle 已抓 (grab 已恢复 → 同一导出可安全接管)
// + StartProcessing/Leave 均已解析 + 未安装
fn tel_install_allowed(handle: u64, start_resolved: bool, leave_resolved: bool, installed: bool) -> bool {
    handle != 0 && start_resolved && leave_resolved && !installed
}

// ===== far stubs (detour::install_far 从近块跳到这里, 风格镜像 antikick.rs/kick.rs) =====
// tel_start_stub: hook StartProcessing 入口
// 入口 rsp%16=8; 7×push(0x38) → 0; sub 0x20 → call 前 0 (shadow space 覆盖 2 参调用); add/pop 后恢复
// 寄存器: 全部 volatile (rax,rcx,rdx,r8,r9,r10,r11) 压栈保存 — 原值经栈恢复, rcx/rdx 覆写为
//   原 rdx(count ptr)/r8(changes ptr) 调 Rust 处理; flags 跨 call 被破坏无碍 (x64 ABI: call 破坏 flags)
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_tel_start_stub
gbfr_tel_start_stub:
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    mov rcx, rdx
    mov rdx, r8
    mov rax, qword ptr [rip + gbfr_tel_start_fn]
    test rax, rax
    je gbfr_tel_start_skip
    sub rsp, 0x20
    call rax
    add rsp, 0x20
gbfr_tel_start_skip:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    jmp qword ptr [rip + gbfr_tel_start_tramp]
    .data
    .global gbfr_tel_start_fn
gbfr_tel_start_fn:
    .quad 0
    .global gbfr_tel_start_tramp
gbfr_tel_start_tramp:
    .quad 0
    "#
);
// tel_leave_stub: hook PFLobbyLeave 入口 (rcx=lobby handle, 原样透传给 Rust)
// 入口 rsp%16=8; 2×push(0x10) → 0; sub 0x20 → call 前 0; add/pop 后恢复
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_tel_leave_stub
gbfr_tel_leave_stub:
    push rax
    push rcx
    mov rax, qword ptr [rip + gbfr_tel_leave_fn]
    test rax, rax
    je gbfr_tel_leave_skip
    sub rsp, 0x20
    call rax
    add rsp, 0x20
gbfr_tel_leave_skip:
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
    fn gbfr_tel_start_stub();
    static mut gbfr_tel_start_fn: u64;
    static mut gbfr_tel_start_tramp: u64;
    fn gbfr_tel_leave_stub();
    static mut gbfr_tel_leave_fn: u64;
    static mut gbfr_tel_leave_tramp: u64;
}

static mut TEL_START_NEAR: usize = 0;
static mut TEL_LEAVE_NEAR: usize = 0;
static mut HOOK_TEL_START: *mut detour::Hook = std::ptr::null_mut();
static mut HOOK_TEL_LEAVE: *mut detour::Hook = std::ptr::null_mut();

// StartProcessing 输出窥探 (stub 以 rcx=count ptr, rdx=changes ptr 调用):
// 守卫两指针 → count 范围检查 → 逐项窥探类型 (只读) → 有目标类型才记 1 条 batch 行 +
// 每条 MemberRemoved 附 lobby@+8 行; 全部受预算约束。绝不消费/改写任何 change。
unsafe extern "system" fn tel_start_poll(count_ptr: u64, changes_ptr: u64) {
    if !ptr_safe(count_ptr, mem_committed(count_ptr as usize)) {
        return;
    }
    if !ptr_safe(changes_ptr, mem_committed(changes_ptr as usize)) {
        return;
    }
    let count = std::ptr::read_unaligned(count_ptr as *const u32) as u64;
    if !count_in_range(count as u32) {
        return;
    }
    let mut kinds: Vec<TelKind> = Vec::new();
    let mut mr_lobbies: Vec<u64> = Vec::new();
    for i in 0..count as usize {
        let Some(t) = entry_type_guarded(changes_ptr, i) else { continue };
        let k = classify_type(t);
        if k == TelKind::Ignore {
            continue;
        }
        if !kinds.contains(&k) {
            kinds.push(k);
        }
        if k == TelKind::MemberRemoved {
            // lobby handle 位于 change+8 (PFLobbyMemberRemovedStateChange 首字段)
            let p = std::ptr::read_unaligned((changes_ptr + (i as u64) * 8) as *const u64);
            if ptr_safe(p + 8, mem_committed((p + 8) as usize)) {
                mr_lobbies.push(std::ptr::read_unaligned((p + 8) as *const u64));
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
    name: &str,
    module: &str,
    range: Option<(u64, usize)>,
    stub: usize,
) -> Option<detour::Hook> {
    if target == 0 {
        log(&format!("[tel] {} addr unavailable", name));
        return None;
    }
    if !detour::preflight(target, module, range) {
        return None;
    }
    let h = detour::install_far(target, 6, stub);
    if h.is_some() {
        log(&format!("[tel] {} installed (module={})", name, module));
    }
    h
}

// 安装两个 telemetry far stub (幂等: 已装 / 门控不过 → 静默 false; all-or-nothing 回滚)
pub fn install() -> bool {
    unsafe {
        let handle = MP_HANDLE.load(Ordering::Relaxed);
        let sp = std::ptr::read_unaligned(std::ptr::addr_of!(FN_START_PROCESSING));
        let leave = std::ptr::read_unaligned(std::ptr::addr_of!(FN_LEAVE));
        let start_slot = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_START));
        let leave_slot = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_LEAVE));
        if !tel_install_allowed(handle, sp != 0, leave != 0, !start_slot.is_null() || !leave_slot.is_null()) {
            return false;
        }
        // fn 槽必须先于 patch 生效 (patch 后 stub 可能即刻被执行)
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_start_fn), tel_start_poll as *const () as usize as u64);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_fn), tel_leave as *const () as usize as u64);
        let range = detour::module_range("PlayFabMultiplayerWin.dll");
        let mut start_h = tel_try_install(sp, "StartProcessing", "PlayFabMultiplayerWin.dll", range, gbfr_tel_start_stub as *const () as usize);
        // tramp 槽紧跟各自 install_far 生效 — 最小化 patch 生效与 tramp 写入间的窗口 (kick.rs B22/MINOR-6 同款权衡)
        if let Some(h) = &start_h {
            std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_start_tramp), h.trampoline() as u64);
            std::ptr::write(std::ptr::addr_of_mut!(TEL_START_NEAR), h.near_addr());
        }
        let mut leave_h = tel_try_install(leave, "Leave", "PlayFabMultiplayerWin.dll", range, gbfr_tel_leave_stub as *const () as usize);
        if let Some(h) = &leave_h {
            std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_tramp), h.trampoline() as u64);
            std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), h.near_addr());
        }
        match (&mut start_h, &mut leave_h) {
            (Some(_), Some(_)) => {
                let sh = start_h.take().unwrap();
                let lh = leave_h.take().unwrap();
                std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_START), Box::into_raw(Box::new(sh)));
                std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_LEAVE), Box::into_raw(Box::new(lh)));
                log("[tel] hooks installed (StartProcessing/Leave)");
                true
            }
            _ => {
                if let Some(h) = start_h.as_mut() {
                    h.restore();
                }
                if let Some(h) = leave_h.as_mut() {
                    h.restore();
                }
                std::ptr::write(std::ptr::addr_of_mut!(TEL_START_NEAR), 0);
                std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), 0);
                std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_start_tramp), 0);
                std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_leave_tramp), 0);
                log("[tel] install FAILED (StartProcessing/Leave) — all hooks rolled back");
                false
            }
        }
    }
}

// 恢复两个 hook (幂等: 双槽皆空 → no-op 早退; Box::from_raw 恰好一次)
pub fn unhook() {
    unsafe {
        let start = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_START));
        let leave = std::ptr::read(std::ptr::addr_of!(HOOK_TEL_LEAVE));
        if start.is_null() && leave.is_null() {
            log("[tel] already unhooked");
            return;
        }
        if !start.is_null() {
            (*start).restore();
            let _ = Box::from_raw(start);
            std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_START), std::ptr::null_mut());
        }
        if !leave.is_null() {
            (*leave).restore();
            let _ = Box::from_raw(leave);
            std::ptr::write(std::ptr::addr_of_mut!(HOOK_TEL_LEAVE), std::ptr::null_mut());
        }
        std::ptr::write(std::ptr::addr_of_mut!(TEL_START_NEAR), 0);
        std::ptr::write(std::ptr::addr_of_mut!(TEL_LEAVE_NEAR), 0);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_tel_start_tramp), 0);
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
