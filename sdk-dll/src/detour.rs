// 统一 x64 inline hook 工具 (K5): 5-8 字节 E9 patch + 近距跳板
//
// 背景 (B21/B22 审计修正):
// - E9 rel32 只能跳 ±2GB: 跳板必须分配在 target 附近 (近距分配), 否则 hook 失效
//   (游戏 exe 基址 ~0x140000000, DLL ~0x7FF..., 直接跳 DLL 内 stub 会溢出 rel32)
// - 被 hook 区域必须是完整指令边界; 各 hook 点指令边界 2026-08-11 capstone 实测 (B22):
//     PFLobbyPostUpdate 0x39F60: 40 53|55|56|57|41 54|41 55|41 56|41 57 → 边界 {2,3,4,5,7,9,11,13}, len=7
//     PFLobbyGetLobbyId 0x38050: 40 55|56|57|41 56|41 57          → 边界 {2,3,4,6,8},   len=6
//     StartProcessing 0x3FA90 / 0x63C90: 40 55|56|57|41 54|41 55|41 56|41 57 → 边界 {2,3,4,6,8,10,12} (7×push, B25/MINOR-4 完整集), len=6
//   (B20/B21 曾用 len=6/5 — 在 push r12/push r14 (2 字节 41 5X) 中间断开: 悬空 REX 吞 E9、
//    被 hook 函数丢一次 callee-saved push, 尾块 pop 恢复垃圾值 → 调用方寄存器破坏。B22 修正)
// - 写代码页后必须 FlushInstructionCache (K6)
//
// 两种近块布局:
//   install_capture: 近块内联 "mov [rip+saved],rcx; jmp [rip+tramp]" (抓寄存器场景, 无需外部 stub)
//   install_far:     近块内联 "jmp [rip+slot]" → 外部 far_stub (复杂逻辑场景, antikick)
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use std::ffi::c_void;
use std::ptr;

const ALLOC_SIZE: usize = 0x100;
const MAX_LEN: usize = 8;
const CAP_TRAMP_OFF: usize = 0x20; // capture 布局: saved@0x10, tramp@0x18, 跳板@0x20
const FAR_TRAMP_OFF: usize = 0x10; // far 布局: slot@0x08, 跳板@0x10

pub struct Hook {
    target: usize,
    len: usize,
    near: usize,
    tramp_off: usize,
    orig: [u8; MAX_LEN],
}

fn flush(p: usize, n: usize) {
    unsafe { FlushInstructionCache(GetCurrentProcess(), p as *const c_void, n); }
}

// 在 target 附近 (逐步 1MB 向上试探, 最多 512MB) 分配可执行页
// 失败返回 0 (不做 NULL 回退: 远距 hook 会因 rel32 溢出而损坏代码, 宁缺毋滥)
fn near_alloc(target: usize) -> usize {
    unsafe {
        let page = target & !0xFFF;
        for i in 1..512 {
            let hint = page + i * 0x100000;
            let p = VirtualAlloc(
                hint as *const c_void,
                ALLOC_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if !p.is_null() {
                return p as usize;
            }
        }
        0
    }
}

fn install_common(target: usize, len: usize, capture: bool, far_stub: usize) -> Option<Hook> {
    unsafe {
        if !(5..=8).contains(&len) {
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
            // mov qword ptr [rip+9], rcx  (saved@near+0x10); jmp [rip+11] (tramp@near+0x18)
            buf[0..7].copy_from_slice(&[0x48, 0x89, 0x0D, 9, 0, 0, 0]);
            buf[7..13].copy_from_slice(&[0xFF, 0x25, 11, 0, 0, 0]);
            ptr::write_unaligned((near + 0x18) as *mut u64, (near + CAP_TRAMP_OFF) as u64);
        } else {
            // jmp qword ptr [rip+2] → slot@near+0x08 = far_stub
            buf[0..6].copy_from_slice(&[0xFF, 0x25, 2, 0, 0, 0]);
            ptr::write_unaligned((near + 0x08) as *mut u64, far_stub as u64);
        }
        // 跳板: 原 len 字节 + E9 回跳 target+len
        let tramp = near + tramp_off;
        ptr::copy_nonoverlapping(orig.as_ptr(), tramp as *mut u8, len);
        let rel = (target + len) as i64 - (tramp + len + 5) as i64;
        let p = tramp + len;
        *(p as *mut u8) = 0xE9;
        ptr::copy_nonoverlapping((rel as i32).to_le_bytes().as_ptr(), (p + 1) as *mut u8, 4);
        flush(near, ALLOC_SIZE);
        // 写 hook: E9 rel32 → near + (len-5) 个 NOP (覆盖完整指令区域)
        let mut patch = [0x90u8; MAX_LEN];
        let rel = near as i64 - (target + 5) as i64;
        patch[0] = 0xE9;
        patch[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
        let mut old = 0u32;
        VirtualProtect(target as *mut c_void, len, PAGE_EXECUTE_READWRITE, &mut old);
        ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, len);
        VirtualProtect(target as *mut c_void, len, old, &mut old);
        flush(target, len);
        Some(Hook { target, len, near, tramp_off, orig })
    }
}

/// 抓寄存器 hook: 近块内联保存 rcx, 调用方用 saved() 读取
pub fn install_capture(target: usize, len: usize) -> Option<Hook> {
    install_common(target, len, true, 0)
}

/// 跳转到外部 stub (stub 负责逻辑, 最后 jmp [rip+tramp_slot]; tramp_slot 由调用方设为 trampoline())
pub fn install_far(target: usize, len: usize, far_stub: usize) -> Option<Hook> {
    install_common(target, len, false, far_stub)
}

impl Hook {
    pub fn trampoline(&self) -> usize {
        self.near + self.tramp_off
    }
    pub fn near_addr(&self) -> usize {
        self.near
    }
    /// 读取 capture 近块保存的 rcx 值 (install_capture 布局: saved@+0x10)
    pub fn saved(&self) -> u64 {
        unsafe { ptr::read_unaligned((self.near + 0x10) as *const u64) }
    }
    /// 还原被 hook 的原指令 (仅适用于 capture/far 均可, 需保存 Hook 本体)
    pub fn restore(&mut self) {
        unsafe {
            let mut old = 0u32;
            VirtualProtect(self.target as *mut c_void, self.len, PAGE_EXECUTE_READWRITE, &mut old);
            ptr::copy_nonoverlapping(self.orig.as_ptr(), self.target as *mut u8, self.len);
            VirtualProtect(self.target as *mut c_void, self.len, old, &mut old);
            flush(self.target, self.len);
        }
    }
}
