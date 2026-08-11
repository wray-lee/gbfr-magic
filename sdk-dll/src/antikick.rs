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
//
// T6 隔离 (quarantine, 见 learnings.md):
// (a) 服务器端移除是最终结果 (leader PostUpdate 已提交) — 本地抑制只掩盖 UI 表现,
//     不会让你留在房间
// (b) 唯一被接受的未来路径: 检测 (收到自己的 MemberRemoved change) + 自动重进
//     (保存 lobbyId+password 后重新加入) — 未来工作, 未实现
// (c) 证据等级: B18.4 静态设计未动态验证; B15 动态矛盾 (被踢判定在 SDK 内部);
//     B29 动态崩溃 (启用防踢 + 被踢 → 闪退) — 故默认禁用, 需显式 antikick_exp on
//
// T2 (two-path model, 见 plan T2/T4 与 learnings.md):
// - 原生 UI 踢人路径: 游戏侧 PostUpdate/memberToDelete 决策 (native_instr)
//   → 本机 PFLobbyLeave (local_leave) — 唯一可考虑抑制的路径
// - 官方路径: PFLobbyForceRemoveMember → MemberRemoved change (official_member_removed)
//   — 服务器权威, 不可预防, 不做任何抑制
// - 旧 SDK_MEMBER_REMOVED_FACTORY (0x63C90) null-return 实验永远隔离 (B29 崩溃),
//   仅作为历史保留: 不启用、不扩展、不解除 (install surface 原样留存)
use crate::detour;
use crate::sdk::sdk_base;
use crate::{log, MY_ID};
use std::sync::atomic::{AtomicBool, Ordering};

const SDK_MEMBER_REMOVED_FACTORY: u64 = 0x63C90;

// ===== T2: 踢人路径分类 (纯函数, 无副作用; T3 将由 telemetry 实时证据喂入) =====
// 两条独立路径 (native_instr/local_leave/official_member_removed 三信号):
// - 原生: 游戏侧 PostUpdate/memberToDelete 决策 → 本机 PFLobbyLeave — 唯一可抑制路径
// - 官方: PFLobbyForceRemoveMember → MemberRemoved change — 服务器权威, 不可预防
// 规则 (plan T2, 编码进表): 官方信号优先且绝不标原生成功 (混合 → Inconclusive);
// 有原生指令即原生路径 (Leave 可能已被抑制或尚未发生); 缺席 Leave 单独 ≠ 成功
// cdylib 不导出 pub 项 → 非测试构建视为 dead; T3 将由 telemetry 消费, 显式豁免
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KickPath {
    None,
    NativeInstructionObserved,
    LocalLeaveObserved,
    OfficialMemberRemovedObserved,
    Inconclusive,
}

#[allow(dead_code)]
pub fn classify_kick_path(native_instr: bool, local_leave: bool, official_member_removed: bool) -> KickPath {
    if official_member_removed {
        if native_instr {
            KickPath::Inconclusive
        } else {
            KickPath::OfficialMemberRemovedObserved
        }
    } else if native_instr {
        KickPath::NativeInstructionObserved
    } else if local_leave {
        KickPath::LocalLeaveObserved
    } else {
        KickPath::Inconclusive
    }
}

// T2: 抑制许可 — 仅原生指令路径可抑制; 官方/本地 Leave/None/Inconclusive 一律 false
// (官方 ForceRemoveMember 不可预防; 混合信号绝不当作原生成功)
#[allow(dead_code)]
pub fn may_suppress(path: KickPath) -> bool {
    path == KickPath::NativeInstructionObserved
}

// T6: 实验开关 — 默认 false (硬性默认关闭, B29 崩溃隔离);
// 仅控制 install() 的安装许可 + set_enabled 的 0 强制 (stub 内运行时闸门仍是 gbfr_ak_enabled)
pub static ANTIKICK_EXPERIMENTAL: AtomicBool = AtomicBool::new(false);

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

// T6: 指针可读性决策 (纯函数, 单测) — 镜像 VirtualQuery 决策: p==0 / p<0x10000 / 未提交 → false
// T1: pub(crate) — telemetry.rs 复用 (不重复实现)
pub(crate) fn ptr_safe(p: u64, committed: bool) -> bool {
    p != 0 && p >= 0x10000 && committed
}

// T6: VirtualQuery 提交状态检查 (返回 0 或 State!=MEM_COMMIT → 不可读)
// T1: pub(crate) — telemetry.rs 复用 (不重复实现)
pub(crate) unsafe fn mem_committed(p: usize) -> bool {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEM_COMMIT, MEMORY_BASIC_INFORMATION};
    let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
    VirtualQuery(p as *const core::ffi::c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) != 0
        && mbi.State == MEM_COMMIT
}

// 判断成员实体是否是自己 (rdx 指向 PFEntityKey 风格 {id*, type*})
// extern "system" 在 x64 Windows 即标准 ABI (与 C 一致), stub 以 rcx=rdx 调用, eax 收返回值
// B29: 加 VirtualQuery 可读性校验 — 动态实测被踢时游戏闪退, 根因疑似 0x63C90 的 rdx
// 并非总是有效 PFEntityKey (B15 有张力: 被踢判定在 SDK 内部); 读非法指针 → AV → 闪退
// T6: MY_ID (my) 同样加守卫 — B29 崩溃向量之一: my 是 stale/freed 指针 (setid 释放后
// 未清 MY_ID); 守卫失败 → 日志 + pass-through (不抑制)
unsafe extern "system" fn ak_check(entity: usize) -> i32 {
    let my = MY_ID.load(Ordering::Relaxed);
    if my == 0 || entity == 0 { return 0; }
    if !ptr_safe(my, mem_committed(my as usize)) {
        log("[ak] MY_ID invalid, pass-through");
        return 0;
    }
    if !ptr_safe(entity as u64, mem_committed(entity)) { return 0; }
    let id_ptr = *(entity as *const u64);
    if !ptr_safe(id_ptr, mem_committed(id_ptr as usize)) { return 0; }
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
static mut HOOK_AK: *mut detour::Hook = std::ptr::null_mut(); // B29: 供 unload 恢复

// T6: 目标开关值 (纯函数, 单测) — 实验模式关时恒 0 ("off 永远赢", 无论请求值)
fn next_enabled(experimental: bool, current: u64) -> u64 {
    if experimental { current } else { 0 }
}

// T6: 实验模式开关 — on: 允许 install() 且日志明示崩溃风险;
// off: 强制 gbfr_ak_enabled=0 (set_enabled(false)), 已装 hook 保留但禁用 (不自动卸载)
pub fn set_experimental(on: bool) {
    ANTIKICK_EXPERIMENTAL.store(on, Ordering::Relaxed);
    if on {
        log("[ak] EXPERIMENTAL MODE ON — known crash risk (B29), server-side removal is final, this only suppresses local change generation");
    } else {
        set_enabled(false);
        log("[ak] EXPERIMENTAL MODE OFF — hook stays installed but disabled");
    }
}

// 防踢开关 (MAJOR-1/B21 修正: 原 antikick_off 只改 ANTIKICK 原子量, stub 读的 gbfr_ak_enabled 从未清 0)
// T6: 写入值经 next_enabled — 实验模式关 → 恒 0 (set_enabled(false) 无条件赢)
pub fn set_enabled(on: bool) {
    let val = next_enabled(ANTIKICK_EXPERIMENTAL.load(Ordering::Relaxed), on as u64);
    unsafe {
        gbfr_ak_enabled = val;
    }
    log(if val != 0 { "[ak] enabled" } else { "[ak] disabled" });
}

// T5: 幂等决策 (纯函数, 单测): 槽为空 → 无需恢复
fn ak_slot_held(h: *const detour::Hook) -> bool {
    !h.is_null()
}

// B29: 恢复 hook (unload 命令调用)
// T5: 幂等 — 二次调用 (HOOK_AK 已空) → no-op 日志; Box::from_raw 恰好一次
// (T6 协调注意: 此处仅加了空槽早退 + 决策辅助函数, 未动 install/set_enabled/ak_check)
pub fn unhook() {
    unsafe {
        if !ak_slot_held(HOOK_AK) {
            log("[ak] already unhooked");
            return;
        }
        (*HOOK_AK).restore();
        let _ = Box::from_raw(HOOK_AK);
        HOOK_AK = std::ptr::null_mut();
        AK_NEAR = 0;
        gbfr_ak_tramp = 0;
        gbfr_ak_enabled = 0;
        log("[ak] hook restored");
    }
}

// T6: 安装许可 (纯函数, 单测) — 仅 实验模式开 + SDK 已加载 才允许
fn install_allowed(flag: bool, sdk_loaded: bool) -> bool {
    flag && sdk_loaded
}

// 安装防踢 hook (幂等: 已安装则只开开关)
// T6: 顶部闸门 — ANTIKICK_EXPERIMENTAL 默认 false → 直接拒绝, 零内存写入
//     (不装 hook, 不写 gbfr_ak_enabled; B29 崩溃隔离)
pub fn install() {
    unsafe {
        let b = sdk_base();
        if !install_allowed(ANTIKICK_EXPERIMENTAL.load(Ordering::Relaxed), b != 0) {
            log("[ak] REFUSED: antikick is EXPERIMENTAL and DISABLED by default (crashed in B29 test; server-side removal is final) — use antikick_exp on to enable");
            return;
        }
        if AK_NEAR != 0 {
            gbfr_ak_enabled = 1;
            return;
        }
        let target = (b + SDK_MEMBER_REMOVED_FACTORY) as usize;
        // B20: hook 区域 = 6 字节 (0x63C90 序言 40 55|56|57|41 54, 边界 {2,3,4,6,8,10,12} 7×push 完整集, len=6 在边界上, B25/MINOR-4)
        match detour::install_far(target, 6, gbfr_antikick_stub as *const () as usize) {
            Some(h) => {
                AK_NEAR = h.near_addr();
                gbfr_ak_tramp = h.trampoline() as u64;
                gbfr_ak_check_fn = ak_check as *const () as usize as u64;
                gbfr_ak_enabled = 1;
                HOOK_AK = Box::into_raw(Box::new(h)); // B29
                log(&format!("[ak] hook installed at 0x{:X} (证据等级: B18.4 静态设计, B15 动态有张力, 见 B20/L6)", target));
            }
            None => {
                log("[ak] hook install FAILED (near alloc)");
            }
        }
    }
}

// ===== NATIVE GUARD (T4) — game-side decision override, independent of the SDK-side
// 0x63C90 experiment above; plan gbfr-kick-message-interception T4 =====
// 决策边界 (T3 静态证据 task-3-static-localization.md, orchestrator byte-verified):
// observer[6] 0x143B48030 (PostUpdateCompleted) 内 call selfcheck @ 0x143B488A3
//   (E8 48 6A FF FF = call 0x143B3F2F0), 仅在 memcmp("id_container") 门
//   @ 0x143B48887 (E8 D4 2A E6 00) 通过后可达; 调用后 test al,al @ 0x143B488A8,
//   jne 0x143B488B1 (0F 85 51 FF FF FF): al=1 → 自己仍在成员列表 → 未被踢 (继续 change 循环);
//   al=0 (fall-through) → 被踢反应 (按 id_container 值重建成员列表 + 通知) → 后续触发 Leave。
// selfcheck (vtable[34], 序言 56 57 53 48 83 EC 20) 返回 al=1 iff 容器成员列表
//   [container+0x180..0x188] 仍含全局 self id。
// 机制: 5 字节 E9 far-stub @ game_base+0x3B488A3 — stub 调 REAL selfcheck (绝对地址
//   game_base+0x3B3F2F0, 存 DLL 全局槽), enabled && al==0 → 改 al=1 (假装仍在列表),
//   直接 jmp 回 game_base+0x3B488A8 (back 槽); trampoline 不使用。
// 版本绑定 (多点多签名, ALL 必须匹配否则 REFUSED 零补丁): target/jne/memcmp/selfcheck 四处。
// 默认关闭, off/unload 幂等且逐字节恢复 (detour Hook::restore 自带字节校验)。
const AK2_CALL_RVA: u64 = 0x3B488A3;   // call selfcheck 指令
const AK2_SELFCHECK_RVA: u64 = 0x3B3F2F0; // selfcheck 函数 (vtable[34])
const AK2_JNE_RVA: u64 = 0x3B488B1;   // test al,al 后的 jne (self 在列表 → 未踢)
const AK2_MEMCMP_RVA: u64 = 0x3B48887; // memcmp("id_container", key) 门
const AK2_SIG_TARGET: [u8; 5] = [0xE8, 0x48, 0x6A, 0xFF, 0xFF];
const AK2_SIG_JNE: [u8; 6] = [0x0F, 0x85, 0x51, 0xFF, 0xFF, 0xFF];
const AK2_SIG_MEMCMP: [u8; 5] = [0xE8, 0xD4, 0x2A, 0xE6, 0x00];
const AK2_SIG_SELFCHECK: [u8; 7] = [0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x20];
const AK2_SIGS: [(u64, &[u8]); 4] = [
    (AK2_CALL_RVA, &AK2_SIG_TARGET),
    (AK2_JNE_RVA, &AK2_SIG_JNE),
    (AK2_MEMCMP_RVA, &AK2_SIG_MEMCMP),
    (AK2_SELFCHECK_RVA, &AK2_SIG_SELFCHECK),
];

// 纯决策 (单测): E9 hook (len=5) 的返回地址 = target + 5 (完整指令后的下一指令)
const fn back_addr(target: u64) -> u64 {
    target + 5
}

const AK2_BACK_RVA: u64 = back_addr(AK2_CALL_RVA); // 0x3B488A8 (test al,al)

// T4 stub (汇编, 位于本 DLL 内; detour::install_far 近块 → 跳到这里):
// 入口 rsp%16=8 (caller call 压栈); push rcx (→0) 保存容器; sub rsp,0x20 (→0) shadow space;
//   [rsp+0x20] 取回原 rcx; xor edx,edx (与 caller 原参数一致: selfcheck(container, 0));
//   call [gbfr_ak2_real]; 然后 enabled && al==0 → mov al,1; restore: add/pop 恢复入口
//   rsp%16=8 后 jmp [gbfr_ak2_back] 直回 0x143B488A8 (tramp 不用)。
// 寄存器破坏集 = 仅 volatile (rax,rcx,rdx,flags) — 与原始 call 一致; caller 只重测 al,
//   后续仅用非 volatile 寄存器 (r12/r13/r15/rbx/rbp/rsi/rdi 均未触碰)。
// fail-closed: gbfr_ak2_real==0 (理论不可达 — 槽先于 patch 写入, unload 后才清) → al=0
//   原流程 (不覆盖); 预清 eax 保证该路径 al 确定性。
core::arch::global_asm!(
    r#"
    .text
    .global gbfr_ak2_stub
gbfr_ak2_stub:
    push rcx
    sub rsp, 0x20
    mov rcx, qword ptr [rsp + 0x20]
    xor edx, edx
    xor eax, eax
    mov rax, qword ptr [rip + gbfr_ak2_real]
    test rax, rax
    je gbfr_ak2_restore
    call rax
    cmp qword ptr [rip + gbfr_ak2_enabled], 0
    je gbfr_ak2_restore
    test al, al
    jne gbfr_ak2_restore
    mov al, 1
gbfr_ak2_restore:
    add rsp, 0x20
    pop rcx
    jmp qword ptr [rip + gbfr_ak2_back]
    .data
    .global gbfr_ak2_real
gbfr_ak2_real:
    .quad 0
    .global gbfr_ak2_back
gbfr_ak2_back:
    .quad 0
    .global gbfr_ak2_enabled
gbfr_ak2_enabled:
    .quad 0
    "#
);
unsafe extern "C" {
    fn gbfr_ak2_stub();
    static mut gbfr_ak2_real: u64;
    static mut gbfr_ak2_back: u64;
    static mut gbfr_ak2_enabled: u64;
}

static mut AK2_NEAR: usize = 0;
static mut HOOK_AK2: *mut detour::Hook = std::ptr::null_mut();

// 纯决策 (单测): 版本绑定全过 + 游戏已加载 + 未安装 → 允许安装 (fail-closed)
fn guard_install_allowed(game_base: u64, sigs_ok: bool, installed: bool) -> bool {
    game_base != 0 && sigs_ok && !installed
}

// 纯决策 (单测): stub 内覆盖规则的 Rust 镜像 (asm 实现同一逻辑; 供测试+文档)
#[allow(dead_code)]
fn override_result(enabled: bool, selfcheck_al: u8) -> u8 {
    if enabled && selfcheck_al == 0 { 1 } else { selfcheck_al }
}

// 纯决策 (单测): 逐字节签名比较 (长度不等 → false)
fn sig_match(expected: &[u8], actual: &[u8]) -> bool {
    expected.len() == actual.len() && expected.iter().zip(actual).all(|(e, a)| e == a)
}

// 版本绑定: 读 game 内存 4 处签名, 全匹配 → None; 否则 Some(首个不匹配 RVA)
fn verify_sigs(game_base: u64) -> Option<u64> {
    if game_base == 0 {
        return Some(0);
    }
    unsafe {
        for &(rva, expected) in &AK2_SIGS {
            let p = (game_base + rva) as usize;
            let mut actual = [0u8; 7];
            std::ptr::copy_nonoverlapping(p as *const u8, actual.as_mut_ptr(), expected.len());
            if !sig_match(expected, &actual[..expected.len()]) {
                return Some(rva);
            }
        }
        None
    }
}

// native_antikick_exp on: 幂等 — 已装则仅 ensure enabled=1; 否则签名门 → 三全局槽
// 先写 (patch 后 stub 可能即刻被执行, telemetry.rs:283-285 同款) → install_far
pub fn native_guard_on() {
    unsafe {
        let b = crate::sdk::game_base();
        if b == 0 {
            log("[ak2] REFUSED: granblue_fantasy_relink.exe not loaded");
            return;
        }
        let installed = std::ptr::read(std::ptr::addr_of!(AK2_NEAR)) != 0;
        if installed {
            std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_enabled), 1);
            log("[ak2] already installed (enabled=1)");
            return;
        }
        let target = (b + AK2_CALL_RVA) as usize;
        if !detour::preflight(target, "granblue_fantasy_relink.exe", detour::module_range("granblue_fantasy_relink.exe")) {
            return;
        }
        let mismatch = verify_sigs(b);
        if !guard_install_allowed(b, mismatch.is_none(), installed) {
            if let Some(rva) = mismatch {
                log(&format!("[ak2] REFUSED: signature mismatch at game_base+0x{:X}", rva));
            }
            return;
        }
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_real), b + AK2_SELFCHECK_RVA);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_back), b + AK2_BACK_RVA);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_enabled), 1);
        match detour::install_far(target, 5, gbfr_ak2_stub as *const () as usize) {
            Some(h) => {
                std::ptr::write(std::ptr::addr_of_mut!(AK2_NEAR), h.near_addr());
                std::ptr::write(std::ptr::addr_of_mut!(HOOK_AK2), Box::into_raw(Box::new(h)));
                log(&format!("[ak2] native guard installed at 0x{:X}", target));
            }
            None => {
                std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_enabled), 0);
                log("[ak2] install FAILED (near alloc)");
            }
        }
    }
}

// native_antikick_exp off + unload: 幂等恢复 — enabled=0 → restore (字节校验) → 清槽;
// 无 tramp 全局槽 (trampoline 不使用, 无需清)
pub fn native_guard_uninstall() {
    unsafe {
        let hook = std::ptr::read(std::ptr::addr_of!(HOOK_AK2));
        if hook.is_null() {
            log("[ak2] already removed");
            return;
        }
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_enabled), 0);
        (*hook).restore();
        let _ = Box::from_raw(hook);
        std::ptr::write(std::ptr::addr_of_mut!(HOOK_AK2), std::ptr::null_mut());
        std::ptr::write(std::ptr::addr_of_mut!(AK2_NEAR), 0);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_real), 0);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_back), 0);
        std::ptr::write(std::ptr::addr_of_mut!(gbfr_ak2_enabled), 0);
        log("[ak2] native guard removed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== T5: 幂等 unhook =====
    #[test]
    fn unhook_null_slot_is_noop() {
        // 纯决策: 空槽 → false (不执行任何恢复动作)
        assert!(!ak_slot_held(std::ptr::null()));
        assert!(ak_slot_held(0x1 as *const detour::Hook));
        // 直接连调两次: 测试进程内 HOOK_AK 恒为 null, 走 no-op 日志路径, 不触碰任何游戏内存
        unhook();
        unhook();
    }

    // ===== T6: 隔离闸门 =====
    #[test]
    fn install_refused_when_flag_off() {
        // 全 4 组合: 仅 flag on + sdk loaded 允许
        assert!(!install_allowed(false, true));
        assert!(!install_allowed(false, false));
        assert!(!install_allowed(true, false));
        assert!(install_allowed(true, true));
    }

    #[test]
    fn set_experimental_off_forces_disabled() {
        // 实验模式关 → 恒 0 (无论请求值); 开 → 透传
        assert_eq!(next_enabled(false, 0), 0);
        assert_eq!(next_enabled(false, 1), 0);
        assert_eq!(next_enabled(true, 0), 0);
        assert_eq!(next_enabled(true, 1), 1);
    }

    #[test]
    fn my_id_guard() {
        // ptr_safe 决策: p==0 / p<0x10000 / 未提交 → false
        assert!(!ptr_safe(0, true));
        assert!(!ptr_safe(0, false));
        assert!(!ptr_safe(0x8000, true));
        assert!(!ptr_safe(0x10000, false));
        assert!(ptr_safe(0x10000, true));
        assert!(ptr_safe(0x7FFF_FFFF_FFFF, true));
    }

    // ===== T2: 路径分类 =====
    #[test]
    fn classify_exhaustive_table() {
        // 全 8 组合: 规则表每行 + all-false + 全部 2-of-3 组合
        assert_eq!(classify_kick_path(false, false, false), KickPath::Inconclusive);
        assert_eq!(classify_kick_path(true, false, false), KickPath::NativeInstructionObserved);
        assert_eq!(classify_kick_path(false, true, false), KickPath::LocalLeaveObserved);
        assert_eq!(classify_kick_path(true, true, false), KickPath::NativeInstructionObserved);
        assert_eq!(classify_kick_path(false, false, true), KickPath::OfficialMemberRemovedObserved);
        assert_eq!(classify_kick_path(true, false, true), KickPath::Inconclusive);
        assert_eq!(classify_kick_path(false, true, true), KickPath::OfficialMemberRemovedObserved);
        assert_eq!(classify_kick_path(true, true, true), KickPath::Inconclusive);
    }

    #[test]
    fn may_suppress_only_native() {
        // 仅 NativeInstructionObserved 可抑制; None/本地 Leave/官方/不确定 全部 false
        assert!(may_suppress(KickPath::NativeInstructionObserved));
        assert!(!may_suppress(KickPath::None));
        assert!(!may_suppress(KickPath::LocalLeaveObserved));
        assert!(!may_suppress(KickPath::OfficialMemberRemovedObserved));
        assert!(!may_suppress(KickPath::Inconclusive));
    }

    #[test]
    fn official_signal_never_suppressible() {
        // 文档规则: 官方信号存在 → 无论其他信号如何, 绝不产生可抑制结论 (不可预防)
        for n in [false, true] {
            for l in [false, true] {
                assert!(!may_suppress(classify_kick_path(n, l, true)));
            }
        }
    }

    #[test]
    fn absence_of_leave_alone_is_not_success() {
        // 文档规则: 只有 "没走 Leave" 而无其他信号 → Inconclusive, 不可抑制
        assert!(!may_suppress(classify_kick_path(false, false, false)));
        // 部分/混合信号 (2-of-3) 不得标原生成功
        assert!(!may_suppress(classify_kick_path(false, true, true)));
        assert!(!may_suppress(classify_kick_path(true, false, true)));
        assert!(!may_suppress(classify_kick_path(true, true, true)));
    }

    // ===== T4: 原生防踢守卫 (fail-closed 纯决策) =====
    #[test]
    fn sig_match_accepts_exact_bytes() {
        // 全部 4 组版本绑定签名: 自身恒匹配
        assert!(sig_match(&AK2_SIG_TARGET, &AK2_SIG_TARGET));
        assert!(sig_match(&AK2_SIG_JNE, &AK2_SIG_JNE));
        assert!(sig_match(&AK2_SIG_MEMCMP, &AK2_SIG_MEMCMP));
        assert!(sig_match(&AK2_SIG_SELFCHECK, &AK2_SIG_SELFCHECK));
    }

    #[test]
    fn sig_match_rejects_length_mismatch() {
        assert!(!sig_match(&AK2_SIG_TARGET, &AK2_SIG_TARGET[..4]));
        let longer = [0xE8, 0x48, 0x6A, 0xFF, 0xFF, 0x00];
        assert!(!sig_match(&AK2_SIG_TARGET, &longer));
        assert!(!sig_match(&[], &[1]));
        assert!(!sig_match(&[1], &[]));
    }

    #[test]
    fn sig_match_rejects_each_byte_flip() {
        // 每个字节翻转都必须拒收 (多字节签名任一不符 → REFUSED)
        for i in 0..AK2_SIG_TARGET.len() {
            let mut bad = AK2_SIG_TARGET.clone();
            bad[i] ^= 0xFF;
            assert!(!sig_match(&AK2_SIG_TARGET, &bad), "target byte {} must matter", i);
        }
        for i in 0..AK2_SIG_SELFCHECK.len() {
            let mut bad = AK2_SIG_SELFCHECK.clone();
            bad[i] ^= 0x01;
            assert!(!sig_match(&AK2_SIG_SELFCHECK, &bad), "selfcheck byte {} must matter", i);
        }
    }

    #[test]
    fn sig_match_empty_arrays() {
        assert!(sig_match(&[], &[]));
    }

    #[test]
    fn guard_install_allowed_table() {
        // 全 8 组合: 仅 game_base!=0 && 签名全过 && 未安装 允许
        for &gb in &[0u64, 0x140_0000_00] {
            for &sigs in &[false, true] {
                for &installed in &[false, true] {
                    assert_eq!(
                        guard_install_allowed(gb, sigs, installed),
                        gb != 0 && sigs && !installed,
                        "gb={} sigs={} installed={}",
                        gb,
                        sigs,
                        installed
                    );
                }
            }
        }
    }

    #[test]
    fn double_install_guard() {
        // 已安装 → 拒绝再装 (幂等: on 只 ensure enabled=1)
        assert!(!guard_install_allowed(0x140_0000_00, true, true));
        assert!(!guard_install_allowed(0x140_0000_00, false, true));
    }

    #[test]
    fn override_result_table() {
        // enabled && al==0 → 1 (假装仍在列表); disabled 或 al==1 → 原样
        assert_eq!(override_result(false, 0), 0);
        assert_eq!(override_result(false, 1), 1);
        assert_eq!(override_result(true, 1), 1);
        assert_eq!(override_result(true, 0), 1);
    }

    #[test]
    fn back_addr_adds_hook_len() {
        assert_eq!(back_addr(0x1234_5678), 0x1234_567D);
        // 版本绑定常量一致性: call 后下一指令 = back (test al,al)
        assert_eq!(back_addr(AK2_CALL_RVA), AK2_BACK_RVA);
        assert_eq!(AK2_BACK_RVA, 0x3B488A8);
    }
}
