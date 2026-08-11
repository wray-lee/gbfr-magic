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
use std::sync::atomic::{AtomicBool, Ordering};

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

// 房间信息 (FindLobbiesCompleted 解析结果, 纯数据)
pub(crate) struct RoomInfo {
    pub lobby_id: String,
    pub conn: String,
    pub owner_id: String,
    pub max_members: u32,
    pub cur_members: u32,
}

// FindLobbiesCompleted 解析结果分类
pub(crate) enum ScanStatus {
    Completed { result: u32, count: u32 },
    // 结果集整体拒绝 (searchResults==0 或 count>1000), reason 记录拒绝原因
    Rejected { reason: String },
    // ch==0 或 type != 12: 不属于本扫描
    NotOurs,
}

// 解析 FindLobbiesCompleted change (type=12), 纯函数 — 可单测, 不做任何日志。
// 布局 (B28 官方现行版, 勿改): 基结构 type@+0x00 / result@+0x04 / count@+0x20 / results@+0x28;
// 元素 stride=0x50: lobbyId@0, connectionString@8, ownerEntity*@0x10, max@0x18, current@0x1C
// 安全策略 (B27/B28 防御): ch==0 → NotOurs; count>1000 或 results==0 → 整体 Rejected;
// 所有字符串读取经 read_cstr (p<0x10000 判空, 长度上限 512) — 任何指针都不会裸解引用。
pub(crate) fn parse_findlobbies_completed(ch: *const u8, out: &mut Vec<RoomInfo>) -> ScanStatus {
    unsafe {
        if ch.is_null() { return ScanStatus::NotOurs; }
        let ty = *(ch as *const u32);
        if ty != 12 { return ScanStatus::NotOurs; }
        let result = *(ch as *const u32).add(0x04 / 4);      // +0x04 result (HRESULT)
        let n = *(ch as *const u32).add(0x20 / 4);           // +0x20 searchResultCount
        let arr = *(ch as *const u64).add(0x28 / 8);         // +0x28 searchResults*
        if n > 1000 {
            return ScanStatus::Rejected { reason: format!("count={} exceeds 1000 (state anomaly, see B27/B28)", n) };
        }
        if arr == 0 {
            return ScanStatus::Rejected { reason: "searchResults==0 (null results, see B27/B28)".to_string() };
        }
        out.clear();
        // B28: stride=0x50; 解析上限 100 条 (显示用)
        for j in 0..n.min(100) {
            let r = (arr as *const u8).add(j as usize * 0x50);
            let lobby_id = read_cstr(*(r as *const u64) as usize);
            let conn = read_cstr(*((r as *const u64).add(0x08 / 8)) as usize);
            let owner = *(r as *const u64).add(0x10 / 8) as usize;
            let owner_id = read_cstr(if owner != 0 { *(owner as *const u64) as usize } else { 0 });
            let max_m = *(r as *const u32).add(0x18 / 4);
            let cur_m = *(r as *const u32).add(0x1C / 4);
            out.push(RoomInfo {
                lobby_id, conn, owner_id,
                max_members: max_m, cur_members: cur_m,
            });
        }
        ScanStatus::Completed { result, count: n }
    }
}

// 扫描重入保护 (AtomicBool 而非 static mut: 同行为且不新增 static_mut_refs 警告)
static SCAN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

// 执行一次房间搜索, 返回房间列表 (leader 信息从 lobbyId/connectionString 提取)
//
// ⚠️ B22/MAJOR-1 并发风险: SDK state change 队列是**单消费者**。本函数轮询 StartProcessing
// 并 finish() 掉拿到的全部变化 (MemberAdded/MemberRemoved/Updated 等), 期间游戏 UI/逻辑
// 将**永久丢失**这些变化 (API 契约要求 finish 全部, 无法选择性消费)。
// 建议: 在非联机操作窗口使用; 若必须联机中使用, 接受房间状态同步延迟/成员列表异常的风险。
pub fn do_scan() {
    unsafe {
        // B22/MAJOR-1: 单消费者队列 — 扫描期间游戏永久丢失全部 pending state changes
        // (MemberAdded/MemberRemoved/Updated), API 契约要求 finish 全部, 无法选择性消费。
        // 仅在非联机操作窗口使用; 此警告显式记录, 保持风险可见。
        log("[scan] CONSUMPTION WARNING: this scan consumes ALL pending lobby state changes (single-consumer queue)");
        let handle = MP_HANDLE.load(Ordering::Relaxed);
        if handle == 0 { log("[scan] handle not ready"); return; }
        if FN_FIND_LOBBIES == 0 { log("[scan] FindLobbies not resolved"); return; }
        // 重入保护: 已有扫描在跑时拒绝再次进入 (防止并发 poll/finish 交错)
        if SCAN_IN_PROGRESS.swap(true, Ordering::Relaxed) {
            log("[scan] already in progress");
            return;
        }
        struct ScanGuard;
        impl Drop for ScanGuard {
            fn drop(&mut self) { SCAN_IN_PROGRESS.store(false, Ordering::Relaxed); }
        }
        let _guard = ScanGuard;

        // 构造 PFLobbySearchConfiguration
        // 0x224B0 校验 (静态确认): +0 (searchFilter) 与 +8 (searchKeys) 必须为非空字符串/数组,
        // 全零 config 会返回 0x89236404。官方布局: 
        // +0x00 searchFilter: *const c_char
        // +0x08 searchKeys: *const *const c_char
        // +0x10 searchKeyCount: u32
        // +0x18 targetEntityKeys: *const PFEntityKey
        // +0x20 targetEntityKeyCount: u32
        // +0x28 pageSize: u32
        let mut config = [0u8; 0x30];
        // searchFilter: 非空 (空字符串也不行, 0x224B0 检查首字节非 0)
        let filter = b"lobby/maxMembers gt 0\0";
        let filter_ptr = filter.as_ptr() as u64;
        std::ptr::write_unaligned((config.as_mut_ptr() as *mut u64).add(0x00 / 8), filter_ptr);
        // searchKeys: 非空数组, 至少 1 个 key (0x224B0 检查数组首指针非 0)
        let key = b"lobby/maxMembers\0";
        let key_arr = [key.as_ptr() as u64];
        let keys_ptr = key_arr.as_ptr() as u64;
        std::ptr::write_unaligned((config.as_mut_ptr() as *mut u64).add(0x08 / 8), keys_ptr);
        std::ptr::write_unaligned((config.as_mut_ptr() as *mut u32).add(0x10 / 4), 1u32);
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
            let mut done = false;
            for i in 0..count {
                let ch = *(changes as *const u64).add(i as usize);
                // 指针守卫全部在 parse_findlobbies_completed 内 (ch==0 / arr==0 / read_cstr)
                let mut rooms: Vec<RoomInfo> = Vec::new();
                match parse_findlobbies_completed(ch as *const u8, &mut rooms) {
                    ScanStatus::Completed { result, count: n } => {
                        log(&format!("[scan] FindLobbiesCompleted result={} count={}", result, n));
                        for (j, r) in rooms.iter().enumerate() {
                            log(&format!(
                                "[scan]   room[{}] lobbyId={} owner={} members={}/{} conn={}",
                                j, r.lobby_id, r.owner_id, r.cur_members, r.max_members, r.conn
                            ));
                        }
                        done = true;
                    }
                    // 结果集被整体拒绝 (null results / count>1000): 本查询的 completion 已被消费,
                    // 继续轮询不会有新 completion → 记录原因后结束本轮扫描
                    ScanStatus::Rejected { reason } => {
                        log(&format!("[scan] FindLobbiesCompleted rejected: {}", reason));
                        done = true;
                    }
                    ScanStatus::NotOurs => {}
                }
            }
            finish(handle, count, changes as *const u64);
            if done { return; }
        }
        log("[scan] timeout waiting FindLobbiesCompleted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 手工按 B28 布局构建 FindLobbiesCompleted change 缓冲 (type=12 固定)
    unsafe fn completion_buf(result: u32, count: u32, arr: u64) -> [u8; 0x30] {
        let mut b: [u8; 0x30] = std::mem::zeroed();
        std::ptr::write_unaligned(b.as_mut_ptr() as *mut u32, 12u32);
        std::ptr::write_unaligned((b.as_mut_ptr() as *mut u32).add(0x04 / 4), result);
        std::ptr::write_unaligned((b.as_mut_ptr() as *mut u32).add(0x20 / 4), count);
        std::ptr::write_unaligned((b.as_mut_ptr() as *mut u64).add(0x28 / 8), arr);
        b
    }

    // (a) 现行布局合法 completion → 1 个房间, 字段全对
    #[test]
    fn valid_completion_yields_one_room() {
        unsafe {
            let lobby = std::ffi::CString::new("lobby-abc").unwrap();
            let conn = std::ffi::CString::new("conn-xyz").unwrap();
            let owner = std::ffi::CString::new("owner-42").unwrap();
            let mut owner_slot: [u8; 8] = std::mem::zeroed(); // PFEntityKey 首成员 = entityKey cstr 指针
            std::ptr::write_unaligned(owner_slot.as_mut_ptr() as *mut u64, owner.as_ptr() as u64);
            let mut room: [u8; 0x50] = std::mem::zeroed();
            std::ptr::write_unaligned(room.as_mut_ptr() as *mut u64, lobby.as_ptr() as u64);
            std::ptr::write_unaligned((room.as_mut_ptr() as *mut u64).add(0x08 / 8), conn.as_ptr() as u64);
            std::ptr::write_unaligned((room.as_mut_ptr() as *mut u64).add(0x10 / 8), owner_slot.as_ptr() as u64);
            std::ptr::write_unaligned((room.as_mut_ptr() as *mut u32).add(0x18 / 4), 4u32);
            std::ptr::write_unaligned((room.as_mut_ptr() as *mut u32).add(0x1C / 4), 2u32);
            let ch = completion_buf(0, 1, room.as_ptr() as u64);
            let mut out = Vec::new();
            match parse_findlobbies_completed(ch.as_ptr(), &mut out) {
                ScanStatus::Completed { result, count } => {
                    assert_eq!(result, 0);
                    assert_eq!(count, 1);
                }
                _ => panic!("expected Completed"),
            }
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].lobby_id, "lobby-abc");
            assert_eq!(out[0].conn, "conn-xyz");
            assert_eq!(out[0].owner_id, "owner-42");
            assert_eq!(out[0].max_members, 4);
            assert_eq!(out[0].cur_members, 2);
        }
    }

    // (b) results==0 (null 结果指针) → Rejected
    #[test]
    fn null_results_rejected() {
        unsafe {
            let ch = completion_buf(0, 3, 0);
            let mut out = Vec::new();
            match parse_findlobbies_completed(ch.as_ptr(), &mut out) {
                ScanStatus::Rejected { reason } => assert!(reason.contains("searchResults")),
                _ => panic!("expected Rejected"),
            }
            assert!(out.is_empty());
        }
    }

    // (c) count>1000 → 确定性策略: 整体 Rejected (即使 results 指针非空, 也不解引用)
    #[test]
    fn oversized_count_rejected() {
        unsafe {
            let ch = completion_buf(0, 1001, 0x1000);
            let mut out = Vec::new();
            match parse_findlobbies_completed(ch.as_ptr(), &mut out) {
                ScanStatus::Rejected { reason } => assert!(reason.contains("1000")),
                _ => panic!("expected Rejected"),
            }
            assert!(out.is_empty());
        }
    }

    // (d) ch==0 → NotOurs; type!=12 (MemberAdded=5) → NotOurs
    #[test]
    fn null_change_or_other_type_is_not_ours() {
        unsafe {
            let mut out = Vec::new();
            assert!(matches!(parse_findlobbies_completed(std::ptr::null(), &mut out), ScanStatus::NotOurs));
            let mut b: [u8; 0x30] = std::mem::zeroed();
            std::ptr::write_unaligned(b.as_mut_ptr() as *mut u32, 5u32);
            assert!(matches!(parse_findlobbies_completed(b.as_ptr(), &mut out), ScanStatus::NotOurs));
        }
    }

    // (e) read_cstr 对 0 和小指针 → 空串, 不崩溃
    #[test]
    fn read_cstr_guards_bad_pointers() {
        assert_eq!(read_cstr(0), "");
        assert_eq!(read_cstr(0x1000), "");
    }
}
