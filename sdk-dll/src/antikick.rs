// 防踢: hook SDK 内部 MemberRemoved change 工厂 (0x63C90) — B18.4 方案
// 基于 B17 静态逆向:
// - 被踢链路: 服务器移除 → SDK 网络层 → 游戏 FinishProcessing 处理成员移除 changes →
//   内部成员列表更新 → LobbyPlayFab[34] (0x3B3F2F0) "自己在不在列表" 检查失败 → 游戏调
//   PFLobbyLeave → SDK 0x734E0 → 0x63C90 生成 change (顺序以 B11 动态为准, B20/L5)
// - 0x63C90 签名 (B24/B26 细化, B27 统一表述): rdx=成员实体 SSO (+0x00 id, +0x08 type);
//   r8 的值被写入 change+0x18 (mov r12,r8 @0x63CCF → mov [r9+0x18],r12 @0x63DEE; B17.4 内部布局标该字段
//   为 lobby handle — r8 的语义为"写入 change+0x18 的值", 具体身份未完全定论, 以观测事实为准);
//   r9d 的值被写入 change+0x30 (mov r15d,r9d @0x63CCC → mov [r9+0x30],r15d @0x63DF2, reason 字段);
//   rcx 角色未直接观测
// - 拦截: 当成员 id == 自己 → 直接返回 0 (不生成 change)
//
// 证据等级 (L6/B20 审计修正):
// - B15 (动态, 唯一动态证据): 改 KICK_EXEC rdx.id 连 change 值都改, 但 LEAVE 照常触发
//   → 被踢判定在 SDK 内部, 不依赖 change 的 id 值
// - B18.4 (静态设计, 未经动态验证): 拦截 0x63C90 让游戏收不到 MemberRemoved(自己) 即防踢
//   → 与 B15 张力: 若判定走 SDK 内部状态 (而非游戏侧按 change 更新), 本方案无效
// - 风险: 0x63C90 返回 0 (null change) 对调用方 0x734E0 的处理未验证; 服务器端移除是既成事实
//   真正留在房间需配合自动重进 (B15/B18.5)
use crate::detour;
use crate::sdk::sdk_base;
use crate::{log, MY_ID};
use std::sync::atomic::Ordering;

const SDK_MEMBER_REMOVED_FACTORY: u64 = 0x63C90;

// 防踢 stub (汇编, 位于本 DLL 内; detour::install_far 从近块跳到这里):
// 参数: rcx=lobby对象, rdx=成员实体, r8=成员实体?, r9d=reason
// 逻辑: 若 [rdx] 字符串 == 自己 id → 返回 0; 否则跳回原函数
// 栈对齐 (K2/B20, 7×push 核算 B24): 入口 rsp%16=8; 7×push(0x38) 后 rsp%16=8-0x38≡0;
//   sub rsp,0x20 → call 前 rsp%16=0, shadow space 0x20 覆盖 1 参数调用; add/pop 后恢复入口 rsp%16=8
// 寄存器保存 (B24/MAJOR-1): 必须保存 r8/r9 — 被 hook 函数 0x63C90 序言后立即
//   mov r15d,r9d / mov r12,r8 消费入口参数 (0x63CCC/0x63CCF), 随后写 change+0x18(lobby)/+0x30(reason)
//   (0x63DEE/0x63DF2)。ak_check 是 Rust 编译产物, 按 ABI 自由破坏 volatile r8/r9
//   (实测: movzx r9d,[rcx+r8] / cmp r9b,[rdx+r8], r8=索引 r9=暂存) — 不保存则每次
//   非自己成员移除都产出 lobby/reason 全错的 change 对象。旧 stub 仅保存 5 个 (B22 未发现,
//   因 ak_check 的寄存器使用需反汇编编译产物才能确认)
// 竞态防护 (B22/MINOR-6): pass 路径先测 gbfr_ak_tramp — install 的 patch 生效与 tramp 写入之间
//   存在微窗口 (enabled=0 时也走 pass), tramp=0 直接 jmp 会跳地址 0 崩溃; 现改为返回 0 (不崩)
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_antikick_stub
gbfr_antikick_stub:
    cmp qword ptr [rip + gbfr_ak_enabled], 0
    je gbfr_ak_pass
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    mov rcx, rdx
    mov rax, qword ptr [rip + gbfr_ak_check_fn]
    test rax, rax
    je gbfr_ak_restore
    sub rsp, 0x20
    call rax
    add rsp, 0x20
    test eax, eax
    jne gbfr_ak_block
gbfr_ak_restore:
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
gbfr_ak_pass:
    mov rax, qword ptr [rip + gbfr_ak_tramp]
    test rax, rax
    je gbfr_ak_not_ready
    jmp rax
gbfr_ak_not_ready:
    xor eax, eax
    ret
gbfr_ak_block:
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    xor eax, eax
    ret
    .data
    .global gbfr_ak_enabled
gbfr_ak_enabled:
    .quad 0
    .global gbfr_ak_check_fn
gbfr_ak_check_fn:
    .quad 0
    .global gbfr_ak_tramp
gbfr_ak_tramp:
    .quad 0
    "#
);
unsafe extern "C" {
    fn gbfr_antikick_stub();
    static mut gbfr_ak_enabled: u64;
    static mut gbfr_ak_check_fn: u64;
    static mut gbfr_ak_tramp: u64;
}

// 判断成员实体是否是自己 (rdx 指向 PFEntityKey 风格 {id*, type*})
// extern "system" 在 x64 Windows 即标准 ABI (与 C 一致), stub 以 rcx=rdx 调用, eax 收返回值
unsafe extern "system" fn ak_check(entity: usize) -> i32 {
    let my = MY_ID.load(Ordering::Relaxed);
    if my == 0 || entity == 0 { return 0; }
    let id_ptr = *(entity as *const u64);
    if id_ptr == 0 { return 0; }
    // 比较字符串
    let mut i = 0usize;
    loop {
        let a = *(id_ptr as *const u8).add(i);
        let b = *(my as *const u8).add(i);
        if a != b { return 0; }
        if a == 0 { return 1; }
        i += 1;
        if i > 64 { return 0; }
    }
}

static mut AK_NEAR: usize = 0;

// 防踢开关 (MAJOR-1/B21 修正: 原 antikick_off 只改 ANTIKICK 原子量, stub 读的 gbfr_ak_enabled 从未清 0)
pub fn set_enabled(on: bool) {
    unsafe {
        gbfr_ak_enabled = on as u64;
    }
    log(if on { "[ak] enabled" } else { "[ak] disabled" });
}

// 安装防踢 hook (幂等: 已安装则只开开关)
pub fn install() {
    unsafe {
        if AK_NEAR != 0 {
            gbfr_ak_enabled = 1;
            return;
        }
        let b = sdk_base();
        if b == 0 { log("[ak] sdk not loaded"); return; }
        let target = (b + SDK_MEMBER_REMOVED_FACTORY) as usize;
        // B20: hook 区域 = 6 字节 (0x63C90 序言 40 55|56|57|41 54, 边界 {2,3,4,6,8,10,12} 7×push 完整集, len=6 在边界上, B25/MINOR-4)
        match detour::install_far(target, 6, gbfr_antikick_stub as *const () as usize) {
            Some(h) => {
                AK_NEAR = h.near_addr();
                gbfr_ak_tramp = h.trampoline() as u64;
                gbfr_ak_check_fn = ak_check as *const () as usize as u64;
                gbfr_ak_enabled = 1;
                log(&format!("[ak] hook installed at 0x{:X} (证据等级: B18.4 静态设计, B15 动态有张力, 见 B20/L6)", target));
            }
            None => {
                log("[ak] hook install FAILED (near alloc)");
            }
        }
    }
}
