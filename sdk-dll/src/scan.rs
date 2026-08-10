// 房间扫描: 正向调 PFMultiplayerFindLobbies + StartProcessing 轮询
// 基于 B17 静态逆向 + B21/B24 (pefile/capstone 复核):
// - PFMultiplayerFindLobbies @ 0x03D030 (pefile 确认): 官方 4 参数
//   (rcx=handle, rdx=config, r8=asyncContext, r9=out-array, 0x3D030 实测保存 r9/r8/rdx/rcx)
//   代码传 r8=0/r9=0 恰为官方参数 (null asyncContext + null out 数组 → 结果变化走 StartProcessing 队列, 设计正确)
// - PFLobbySearchConfiguration (PlayFab 官方结构, 0x30 字节):
//   +0x00 searchFilter: *const c_char
//   +0x08 searchKeys: *const *const c_char
//   +0x10 searchKeyCount: u32
//   +0x18 targetEntityKeys: *const PFEntityKey
//   +0x20 targetEntityKeyCount: u32
//   +0x28 pageSize: u32
//   (searchFilter 全空 + pageSize=50 的合法性: 待运行时验证, B20/B21 待办 2)
// - FindLobbiesCompleted change: type=12, 后续字段含结果数组
//   (游戏侧 change 结构 [B14 动态 dump, L1/B20]: +0x00 type u32, +0x08 lobby/async, +0x10 起子类字段)
use crate::sdk::{FN_FIND_LOBBIES, FN_START_PROCESSING, FN_FINISH_PROCESSING};
use crate::{log, MP_HANDLE};
use std::sync::atomic::Ordering;

// PFLobbySearchResult (官方现行布局, B28 静态确认 — 游戏 exe 0x3B53770 实测逐字段吻合 + 官方头文件
// PlayFabMultiplayerUnreal/Platforms/Windows/Include/PFLobby.h 交叉验证):
// +0x00 lobbyId: *const c_char             (直接字符串指针, 非 PFEntityKey!)
// +0x08 connectionString: *const c_char    (可空)
// +0x10 ownerEntity: *const PFEntityKey    (指向实体的指针, 可空)
// +0x18 maxMemberCount u32, +0x1C currentMemberCount u32
// +0x20 searchPropertyCount u32, +0x28 searchPropertyKeys*, +0x30 searchPropertyValues*
// +0x38 friendCount u32, +0x40 friends*, +0x48 membershipLock u32
// → 元素 stride = 0x50 (游戏 0x3B538B2 lea rcx,[rcx+rcx*4]; shl rcx,4 = ×20 实测)
//   (B22/B27 的 {lobbyId PFEntityKey@0, conn@0x28, stride 0x40} 布局完全错误, B28 勘误)
// FindLobbiesCompleted change 布局 (官方现行版, B28 静态确认 — DLL 工厂 0x61C76 + 游戏 0x3B53770 +
// 官方头文件三方一致):
// 基结构仅 {u32 stateChangeType @+0x00} (无 asyncContext 成员; asyncContext 在派生结构内)
// +0x00 type=12 u32, +0x04 result u32, +0x08 searchingEntity PFEntityKey(16B),
// +0x18 asyncContext, +0x20 searchResultCount u32, +0x28 searchResults*
// (内部对象 = 本布局 + 0x10 头部: 工厂 0x61C76 写 [obj+0x10]=0xc type / [obj+0x14]=result /
//   [obj+0x28]=asyncContext / [obj+0x30]=count / [obj+0x38]=results;
//   B27 曾按官方旧版 result@+0x04/count@+0x08/results@+0x10 — 错误, 本 SDK 为现行版)

pub(crate) fn read_cstr(p: usize) -> String {
    unsafe {
        // B22/B26: 边界保护 — 垃圾小整数值指针 (错位读取时可能出现) 直接判空, 防 AV
        // (p==0 已被 p<0x10000 覆盖, 无需单独分支)
        if p < 0x10000 { return String::new(); }
        let mut out = Vec::new();
        let mut i = 0usize;
        loop {
            let b = *(p as *const u8).add(i);
            if b == 0 { break; }
            out.push(b);
            i += 1;
            if i > 512 { break; }
        }
        String::from_utf8_lossy(&out).to_string()
    }
}

// 执行一次房间搜索, 返回房间列表 (leader 信息从 lobbyId/connectionString 提取)
//
// ⚠️ B22/MAJOR-1 并发风险: SDK state change 队列是**单消费者**。本函数轮询 StartProcessing
// 并 finish() 掉拿到的全部变化 (MemberAdded/MemberRemoved/Updated 等), 期间游戏 UI/逻辑
// 将**永久丢失**这些变化 (API 契约要求 finish 全部, 无法选择性消费)。
// 建议: 在非联机操作窗口使用; 若必须联机中使用, 接受房间状态同步延迟/成员列表异常的风险。
pub fn do_scan() {
    unsafe {
        let handle = MP_HANDLE.load(Ordering::Relaxed);
        if handle == 0 { log("[scan] handle not ready"); return; }
        if FN_FIND_LOBBIES == 0 { log("[scan] FindLobbies not resolved"); return; }

        // 构造 PFLobbySearchConfiguration: 空过滤 + 大页
        // 游戏搜索条件未知, 先空搜索 (服务器返回全部/按默认)
        let mut config = [0u8; 0x30];
        // +0x28 pageSize = 50
        std::ptr::write_unaligned((config.as_mut_ptr() as *mut u32).add(0x28 / 4), 50u32);

        let find: unsafe extern "system" fn(u64, *const u8, u64, u64) -> i32 =
            std::mem::transmute(FN_FIND_LOBBIES);
        let ret = find(handle, config.as_ptr(), 0, 0);
        log(&format!("[scan] FindLobbies ret=0x{:X} (0=成功, 负=错误)", ret));
        if ret < 0 { return; }

        // 轮询 StartProcessing 直到拿到 FindLobbiesCompleted (type=12)
        let start: unsafe extern "system" fn(u64, *mut u32, *mut u64) -> i32 =
            std::mem::transmute(FN_START_PROCESSING);
        // B22/BLOCKER-2 修正: 官方 ABI 为 (handle, count, changes) — 0x3D320 实测 mov r12d,edx (count=arg2)
        // / mov r14,r8 (array=arg3)。B17.9.3 已记录正确顺序。旧代码 (handle, changes, count) 会
        // 把指针当 count / count 当指针 → SDK 校验失败或 AV。
        let finish: unsafe extern "system" fn(u64, u32, *const u64) -> i32 =
            std::mem::transmute(FN_FINISH_PROCESSING);

        for _round in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut count: u32 = 0;
            let mut changes: u64 = 0;
            if start(handle, &mut count, &mut changes) < 0 { continue; }
            if count == 0 { continue; }
            let mut found = false;
            for i in 0..count {
                let ch = *(changes as *const u64).add(i as usize);
                if ch == 0 { continue; }
                let ty = *(ch as *const u32);
                if ty == 12 {
                    // FindLobbiesCompleted (B28: 官方现行版 result@+0x04/count@+0x20/results@+0x28,
                    // 静态确认 — 工厂 0x61C76/游戏 0x3B53770/官方头文件三方一致)
                    let result = *(ch as *const u32).add(0x04 / 4);      // +0x04 result (HRESULT)
                    let mut n = *(ch as *const u32).add(0x20 / 4);       // +0x20 searchResultCount
                    let arr = *(ch as *const u64).add(0x28 / 8);         // +0x28 searchResults*
                    // B27 防御保留: count 超合理上限截断告警, results==0 跳过 (防 NULL 解引用 AV)
                    if n > 1000 {
                        log(&format!("[scan] count={} 超上限截断 (结果异常, 见 B27/B28)", n));
                        n = 0;
                    }
                    log(&format!("[scan] FindLobbiesCompleted result={} count={}", result, n));
                    if arr != 0 {
                        // B28: stride=0x50 (官方现行布局, 游戏 0x3B538B2 实测);
                        // lobbyId@0, connectionString@8, ownerEntity*@0x10, max@0x18, current@0x1C
                        for j in 0..n.min(100) {
                            let r = (arr as *const u8).add(j as usize * 0x50);
                            let lobby_id = read_cstr(*(r as *const u64) as usize);
                            let conn = read_cstr(*((r as *const u64).add(0x08 / 8)) as usize);
                            let owner = *(r as *const u64).add(0x10 / 8) as usize;
                            let owner_id = read_cstr(if owner != 0 { *(owner as *const u64) as usize } else { 0 });
                            let max_m = *(r as *const u32).add(0x18 / 4);
                            let cur_m = *(r as *const u32).add(0x1C / 4);
                            log(&format!(
                                "[scan]   room[{}] lobbyId={} owner={} members={}/{} conn={}",
                                j, lobby_id, owner_id, cur_m, max_m, conn
                            ));
                        }
                    } else {
                        log("[scan]   searchResults==0 (无结果或异常, 见 B27/B28)");
                    }
                    found = true;
                }
            }
            finish(handle, count, changes as *const u64);
            if found { return; }
        }
        log("[scan] timeout waiting FindLobbiesCompleted");
    }
}
