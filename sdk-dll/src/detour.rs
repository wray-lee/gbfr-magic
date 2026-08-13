// 统一 x64 inline hook 工具 (K5): 5-8 字节 E9 patch + 近距跳板
//
// 背景 (B21/B22 审计修正):
// - E9 rel32 只能跳 ±2GB: 跳板必须分配在 target 附近 (近距分配), 否则 hook 失效
//   (游戏 exe 基址 ~0x140000000, DLL ~0x7FF..., 直接跳 DLL 内 stub 会溢出 rel32)
// - 被 hook 区域必须是完整指令边界; 各 hook 点指令边界 2026-08-11 capstone 实测 (B22):
//     PFLobbyPostUpdate 0x39F60: 40 53|55|56|57|41 54|41 55|41 56|41 57 → 边界 {2,3,4,5,7,9,11,13}, len=7
//     PFLobbyGetLobbyId 0x38050: 40 55|56|57|41 56|41 57          → 边界 {2,3,4,6,8},   len=6
//     PFLobbyGetMembers/MemberProperty/LobbyProperty/MemberConnectionStatus 与 Join/CreateJoin:
//       40 53|55|56|57|41 54... → 边界 {2,3,4,5,7,...}, len=7
//     StartProcessing 0x3FA90 / 0x63C90: 40 55|56|57|41 54|41 55|41 56|41 57 → 边界 {2,3,4,6,8,10,12} (7×push, B25/MINOR-4 完整集), len=6
//   (B20/B21 曾用 len=6/5 — 在 push r12/push r14 (2 字节 41 5X) 中间断开: 悬空 REX 吞 E9、
//    被 hook 函数丢一次 callee-saved push, 尾块 pop 恢复垃圾值 → 调用方寄存器破坏。B22 修正)
// - 写代码页后必须 FlushInstructionCache (K6)
//
// 两种近块布局 (T2: capture 增加调用计数):
//   install_capture: 近块内联 "inc [rip+counter]; mov [rip+saved],rcx; jmp [rip+tramp]"
//     代码区 0x00..0x14 (20B): inc@0x00(7B) → counter; mov@0x07(7B) → saved; jmp@0x0E(6B) → tramp 槽
//     数据槽全部在代码区之后: counter@+0x18, saved@+0x20, tramp 槽@+0x28, 跳板@+0x30
//     (BLOCKER-2 教训: 数据槽若与代码重叠 → mov 首调即覆盖 jmp 的 disp32 → 二次调用跳垃圾地址;
//     数据槽必须 >= 0x14 = 代码区大小, capture_layout_no_overlap 测试把关)
//     inc 修改 flags — 被 hook 函数的序言 (push 系列, 边界见上) 不读取调用方 flags,
//     函数体后续运算也会重写 flags, 故对游戏无行为影响 (B24/MAJOR-1 同源推理:
//     只审查被 hook 序言实际消费的状态, 序言只消费寄存器, 不消费 flags)
//   install_far:     近块内联 "jmp [rip+slot]" → 外部 far_stub (复杂逻辑场景, antikick)
//     slot@+0x08 (far_stub), 跳板@+0x10；调用方的 trampoline 槽在 target patch 前发布，
//     避免高频入口命中已生效 patch、但外部 stub 仍看到空返回槽的竞态窗口。
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use crate::log;

const ALLOC_SIZE: usize = 0x100;
const MAX_LEN: usize = 16; // B29: 原 8 — KICK_EXEC 序言 12 字节 (7×push) 超限导致 hook 失败
const CAP_COUNT_OFF: usize = 0x18;            // capture: 调用计数槽
pub(crate) const CAP_SAVED_OFF: usize = 0x20; // capture: saved rcx 槽 (kick.rs lobby_handle 也读)
const CAP_SLOT_OFF: usize = 0x28;             // capture: tramp 地址槽
const CAP_TRAMP_OFF: usize = 0x30;            // capture: 跳板
const FAR_SLOT_OFF: usize = 0x08;  // far: far_stub 地址槽
const FAR_TRAMP_OFF: usize = 0x10; // far: 跳板

pub struct Hook {
    target: usize,
    len: usize,
    near: usize,
    is_capture: bool,
    orig: [u8; MAX_LEN],
}

fn flush(p: usize, n: usize) {
    unsafe { FlushInstructionCache(GetCurrentProcess(), p as *const c_void, n); }
}

// 在 target 附近 (先向上, 后向下, 各 1GB 逐步探测) 分配可执行页
// B29: 原实现仅向上 512MB — KICK_EXEC (游戏 exe 0x7FF63F79C8B0) 上方无空闲页导致 hook 失败
// 失败返回 0 (不做 NULL 回退: 远距 hook 会因 rel32 溢出而损坏代码, 宁缺毋滥)
// 成功即登记 (T5): 单点记录所有成功分配, 供 unload 报告
fn near_alloc(target: usize) -> usize {
    unsafe {
        let page = target & !0xFFF;
        // 向上 1GB, 每 1MB 试探
        for i in 1..1024 {
            let hint = page + i * 0x100000;
            let p = VirtualAlloc(
                hint as *const c_void,
                ALLOC_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if !p.is_null() {
                record_alloc(p as usize);
                return p as usize;
            }
        }
        // 向下 1GB
        for i in 1..1024 {
            let hint = page.saturating_sub(i * 0x100000);
            if hint < 0x10000 { break; }
            let p = VirtualAlloc(
                hint as *const c_void,
                ALLOC_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if !p.is_null() {
                record_alloc(p as usize);
                return p as usize;
            }
        }
        0
    }
}

// ===== T5: 近分配登记表 =====
// 记录每次成功 near_alloc 的地址, 供 unload 报告 outstanding 数量
// ponytail: 刻意不释放 — 释放仅当全局静止 (无任何 hook/trampoline 可能执行) 时才安全;
//   unload 已恢复全部 hook 字节, 但若有线程正卡在被 hook 点仍可能走跳板, 故保留登记 + 报告, 不释放。
//   升级路径: 证明 quiescence 后 (如 hook 全部恢复 + 暂停游戏线程) 再按表逐项 VirtualFree
static ALLOC_REGISTRY: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<usize>> {
    ALLOC_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn record_alloc(p: usize) {
    if let Ok(mut v) = registry().lock() {
        v.push(p);
    }
}

/// T5: 全部未释放的近分配地址 (锁内克隆, 附加型 — 从不移除)
pub fn near_allocs() -> Vec<usize> {
    registry().lock().map(|v| v.clone()).unwrap_or_default()
}

/// T5: 未释放近分配数量 (unload 报告用)
pub fn near_alloc_count() -> usize {
    near_allocs().len()
}

// T2: 预检 — target 必须在模块 [base, base+size) 范围内 (纯函数, 无副作用)
pub fn validate_target(target: usize, expected_base: u64, expected_size: usize) -> bool {
    (target as u64) >= expected_base && (target as u64) < expected_base + expected_size as u64
}

// T2: 已加载模块的 (基址, SizeOfImage); 空名 → GetModuleHandleW(null) = 测试进程 exe
// PE 头: e_lfanew@+0x3C → "PE\0\0" → optional header (magic@+0x18, SizeOfImage@+0x38, PE32/PE32+ 同偏移)
pub fn module_range(name: &str) -> Option<(u64, usize)> {
    unsafe {
        let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let h = if name.is_empty() {
            GetModuleHandleW(ptr::null())
        } else {
            GetModuleHandleW(name_wide.as_ptr())
        };
        if h.is_null() {
            return None;
        }
        let base = h as u64;
        let e_lfanew = ptr::read_unaligned((base as usize + 0x3C) as *const u32);
        if e_lfanew == 0 || e_lfanew > 0x1000 {
            return None;
        }
        let pe = base as usize + e_lfanew as usize;
        if ptr::read_unaligned(pe as *const u32) != 0x0000_4550 {
            return None;
        }
        let opt = pe + 0x18;
        let magic = ptr::read_unaligned(opt as *const u16);
        if magic != 0x10B && magic != 0x20B {
            return None;
        }
        let size = ptr::read_unaligned((opt + 0x38) as *const u32) as usize;
        if size == 0 {
            return None;
        }
        Some((base, size))
    }
}

// T2: 预检 + 失败日志 (PREFLIGHT FAIL → 调用方不得安装)
pub fn preflight(target: usize, module: &str, range: Option<(u64, usize)>) -> bool {
    match range {
        Some((base, size)) if validate_target(target, base, size) => true,
        r => {
            let where_ = match r {
                Some((base, size)) => format!("range=0x{:X}-0x{:X}", base, base + size as u64),
                None => "module not loaded".to_string(),
            };
            log(&format!(
                "[detour] PREFLIGHT FAIL target=0x{:X} module={} {}",
                target, module, where_
            ));
            false
        }
    }
}

// T2: 字节 → 小写 hex (证据日志)
pub(crate) fn hex16(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn install_common(
    target: usize,
    len: usize,
    capture: bool,
    far_stub: usize,
    far_trampoline_slot: *mut u64,
) -> Option<Hook> {
    unsafe {
        if !(5..=MAX_LEN).contains(&len) {
            return None;
        }
        let near = near_alloc(target);
        if near == 0 {
            return None;
        }
        let mut orig = [0u8; MAX_LEN];
        ptr::copy_nonoverlapping(target as *const u8, orig.as_mut_ptr(), len);
        let buf = std::slice::from_raw_parts_mut(near as *mut u8, ALLOC_SIZE);
        let tramp_off = if capture { CAP_TRAMP_OFF } else { FAR_TRAMP_OFF };
        if capture {
            // 数据槽全部位于代码区 (0x00..0x14) 之后; saved 槽若与 jmp 指令重叠,
            // 首次调用即破坏 jmp disp32 (见 capture_layout_no_overlap 测试)
            // inc qword ptr [rip+0x11] → counter@near+0x18 (7B, next-RIP=0x07, 0x18-0x07=0x11);
            // mov [rip+0x12],rcx → saved@near+0x20 (7B, next-RIP=0x0E, 0x20-0x0E=0x12);
            // jmp [rip+0x14] → tramp 槽@near+0x28 (6B, next-RIP=0x14, 0x28-0x14=0x14)
            buf[0..7].copy_from_slice(&[0x48, 0xFF, 0x05, 0x11, 0, 0, 0]);
            buf[7..14].copy_from_slice(&[0x48, 0x89, 0x0D, 0x12, 0, 0, 0]);
            buf[14..20].copy_from_slice(&[0xFF, 0x25, 0x14, 0, 0, 0]);
            ptr::write_unaligned((near + CAP_COUNT_OFF) as *mut u64, 0);
            ptr::write_unaligned((near + CAP_SLOT_OFF) as *mut u64, (near + CAP_TRAMP_OFF) as u64);
        } else {
            // jmp qword ptr [rip+2] → slot@near+0x08 = far_stub
            buf[0..6].copy_from_slice(&[0xFF, 0x25, 2, 0, 0, 0]);
            ptr::write_unaligned((near + FAR_SLOT_OFF) as *mut u64, far_stub as u64);
        }
        // 跳板: 原 len 字节 + E9 回跳 target+len
        let tramp = near + tramp_off;
        ptr::copy_nonoverlapping(orig.as_ptr(), tramp as *mut u8, len);
        let rel = (target + len) as i64 - (tramp + len + 5) as i64;
        let p = tramp + len;
        *(p as *mut u8) = 0xE9;
        ptr::copy_nonoverlapping((rel as i32).to_le_bytes().as_ptr(), (p + 1) as *mut u8, 4);
        flush(near, ALLOC_SIZE);
        if !capture && !far_trampoline_slot.is_null() {
            ptr::write(far_trampoline_slot, tramp as u64);
        }
        // 写 hook: E9 rel32 → near + (len-5) 个 NOP (覆盖完整指令区域)
        let mut patch = [0x90u8; MAX_LEN];
        let rel = near as i64 - (target + 5) as i64;
        patch[0] = 0xE9;
        patch[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
        let mut old = 0u32;
        if VirtualProtect(target as *mut c_void, len, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            if !capture && !far_trampoline_slot.is_null() {
                ptr::write(far_trampoline_slot, 0);
            }
            log(&format!("[detour] VirtualProtect RWX FAILED target=0x{:X}", target));
            return None;
        }
        ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, len);
        let original_protect = old;
        let mut ignored = 0u32;
        if VirtualProtect(target as *mut c_void, len, original_protect, &mut ignored) == 0 {
            log(&format!("[detour] VirtualProtect RESTORE FAILED target=0x{:X}", target));
        }
        flush(target, len);
        // T2: 字节校验 — 读回 target 前 len 字节与预期 patch 比较; 不一致立即回滚
        let mut check = [0u8; MAX_LEN];
        ptr::copy_nonoverlapping(target as *const u8, check.as_mut_ptr(), len);
        if check[..len] != patch[..len] {
            log(&format!(
                "[detour] PATCH VERIFY FAILED target=0x{:X} want={} got={}",
                target,
                hex16(&patch[..len]),
                hex16(&check[..len])
            ));
            let mut rollback_old = 0u32;
            if VirtualProtect(target as *mut c_void, len, PAGE_EXECUTE_READWRITE, &mut rollback_old) != 0 {
                ptr::copy_nonoverlapping(orig.as_ptr(), target as *mut u8, len);
                let mut ignored = 0u32;
                if VirtualProtect(target as *mut c_void, len, rollback_old, &mut ignored) == 0 {
                    log(&format!("[detour] ROLLBACK PROTECT RESTORE FAILED target=0x{:X}", target));
                }
                flush(target, len);
            } else {
                log(&format!("[detour] ROLLBACK VirtualProtect FAILED target=0x{:X}", target));
            }
            if !capture && !far_trampoline_slot.is_null() {
                ptr::write(far_trampoline_slot, 0);
            }
            return None;
        }
        log(&format!(
            "[detour] installed target=0x{:X} len={} near=0x{:X} orig={} patch={} tramp=0x{:X}",
            target,
            len,
            near,
            hex16(&orig[..len]),
            hex16(&patch[..len]),
            tramp
        ));
        Some(Hook { target, len, near, is_capture: capture, orig })
    }
}

/// 抓寄存器 hook: 近块内联保存 rcx, 调用方用 saved() 读取
pub fn install_capture(target: usize, len: usize) -> Option<Hook> {
    install_common(target, len, true, 0, ptr::null_mut())
}

pub fn install_capture_checked(
    target: usize,
    expected: &[u8],
    name: &str,
    module: &str,
    range: Option<(u64, usize)>,
) -> Option<Hook> {
    if target == 0 || !preflight(target, module, range) {
        return None;
    }
    unsafe {
        let actual = std::slice::from_raw_parts(target as *const u8, expected.len());
        if actual != expected {
            log(&format!(
                "[detour] {} signature mismatch want={} got={}",
                name,
                hex16(expected),
                hex16(actual)
            ));
            return None;
        }
    }
    install_capture(target, expected.len())
}

/// 跳转到外部 stub。若 stub 最后读取外部 trampoline 槽，传入该槽地址；安装器会在
/// target patch 生效前写入 trampoline，失败回滚时清零。无需外部槽的 stub 可传 null。
pub unsafe fn install_far(
    target: usize,
    len: usize,
    far_stub: usize,
    trampoline_slot: *mut u64,
) -> Option<Hook> {
    install_common(target, len, false, far_stub, trampoline_slot)
}

impl Hook {
    pub fn near_addr(&self) -> usize {
        self.near
    }
    /// 读取 capture 近块保存的 rcx 值 (install_capture 布局: saved@+0x10)
    pub fn saved(&self) -> u64 {
        unsafe { ptr::read_unaligned((self.near + CAP_SAVED_OFF) as *const u64) }
    }
    /// T2: 调用计数 (capture 布局: counter@+0x18, install 时清零); far hook 无计数槽, 返回 0
    pub fn counts(&self) -> u64 {
        if !self.is_capture {
            return 0;
        }
        unsafe { ptr::read_unaligned((self.near + CAP_COUNT_OFF) as *const u64) }
    }
    /// 还原被 hook 的原指令 (仅适用于 capture/far 均可, 需保存 Hook 本体)
    pub fn restore(&mut self) -> bool {
        unsafe {
            let mut old = 0u32;
            if VirtualProtect(self.target as *mut c_void, self.len, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                log(&format!("[detour] restore VirtualProtect FAILED target=0x{:X}", self.target));
                return false;
            }
            ptr::copy_nonoverlapping(self.orig.as_ptr(), self.target as *mut u8, self.len);
            let original_protect = old;
            let mut ignored = 0u32;
            if VirtualProtect(self.target as *mut c_void, self.len, original_protect, &mut ignored) == 0 {
                log(&format!("[detour] restore protection FAILED target=0x{:X}", self.target));
            }
            flush(self.target, self.len);
            // T2: 还原字节校验 — 读回 target 前 len 字节与 orig 比较
            let mut check = [0u8; MAX_LEN];
            ptr::copy_nonoverlapping(self.target as *const u8, check.as_mut_ptr(), self.len);
            if check[..self.len] == self.orig[..self.len] {
                log(&format!("[detour] RESTORE VERIFY OK target=0x{:X}", self.target));
                log(&format!("[detour] restored target=0x{:X}", self.target));
                true
            } else {
                log(&format!(
                    "[detour] RESTORE VERIFY FAIL target=0x{:X} want={} got={}",
                    self.target,
                    hex16(&self.orig[..self.len]),
                    hex16(&check[..self.len])
                ));
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_target_boundaries() {
        let base: u64 = 0x140_0000_0000;
        let size: usize = 0x1000;
        assert!(validate_target(base as usize, base, size));
        assert!(validate_target((base + size as u64 - 1) as usize, base, size));
        assert!(!validate_target((base - 1) as usize, base, size));
        assert!(!validate_target((base + size as u64) as usize, base, size));
    }

    #[test]
    fn hex16_formats_lowercase() {
        assert_eq!(hex16(&[0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54]), "40535556574154");
        assert_eq!(hex16(&[0xE9, 0x00, 0x00, 0x00, 0x00, 0x90]), "e90000000090");
        assert_eq!(hex16(b""), "");
    }

    #[test]
    fn capture_layout_no_overlap() {
        // 数据槽必须位于代码区 (0x00..0x14, inc+mov+jmp = 20B) 之后:
        // 任一槽与代码重叠 → mov 首调即覆盖 jmp disp32 → 二次调用跳垃圾地址 (BLOCKER-2)
        assert!(CAP_TRAMP_OFF > CAP_SLOT_OFF);
        assert!(CAP_SLOT_OFF > CAP_SAVED_OFF);
        assert!(CAP_SAVED_OFF > CAP_COUNT_OFF);
        assert!(CAP_COUNT_OFF >= 0x14);
    }

    #[test]
    fn module_range_of_test_exe() {
        // 测试进程: PlayFabMultiplayerWin.dll 未加载; GetModuleHandleW(null) = 测试 exe 本体
        let (base, size) = module_range("").expect("test exe should be loadable");
        assert!(base > 0x10000);
        assert!(size > 0x1000, "SizeOfImage too small: 0x{:X}", size);
    }

    #[test]
    fn near_alloc_registry_tracks_and_cleans() {
        // T5: 登记表 — 对测试进程自身图像地址做 near_alloc (VirtualAlloc 在测试进程内真实分配),
        // 校验登记后 VirtualFree 清理。测试内释放安全: 无任何 hook 安装, trampoline 不会执行
        // (生产路径不释放 — 见 ALLOC_REGISTRY ponytail 注释)
        use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let (base, _) = module_range("").expect("test exe");
            let p = near_alloc(base as usize);
            assert_ne!(p, 0, "near_alloc should succeed near test exe");
            assert!(near_allocs().contains(&p), "registry must track the alloc");
            assert!(near_alloc_count() >= 1);
            assert_eq!(VirtualFree(p as *mut c_void, 0, MEM_RELEASE), 1, "test cleanup");
        }
    }

    #[test]
    fn near_alloc_registry_append_only_two() {
        // T5: 两次分配 → 两者都登记 (附加型登记表)
        use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let (base, _) = module_range("").expect("test exe");
            let a = near_alloc(base as usize);
            let b = near_alloc(base as usize);
            assert_ne!(a, 0);
            assert_ne!(b, 0);
            assert_ne!(a, b, "two allocs must be distinct pages");
            let all = near_allocs();
            assert!(all.contains(&a) && all.contains(&b));
            VirtualFree(a as *mut c_void, 0, MEM_RELEASE);
            VirtualFree(b as *mut c_void, 0, MEM_RELEASE);
        }
    }
}
