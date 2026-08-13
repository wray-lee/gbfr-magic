// GBFR SDK 正向实现 DLL
// 基于 B17/B18 静态逆向: 直接调 PlayFabMultiplayerWin.dll 导出实现
// 1) 房间扫描: PFMultiplayerFindLobbies + StartProcessing 轮询 (scan.rs)
// 2) 踢人: PFLobbyForceRemoveMember (kick.rs)
// 3) 防踢: hook SDK 内部 0x63C90 (antikick.rs)
//
// 注入方式: 主程序 CreateRemoteThread + LoadLibraryW 加载本 DLL
// 通信: 命令文件 (scan/kick <id>/antikick_on/antikick_off/setid <hex>/state/unload) + 结果文件
// 命令行可带唯一 run ID 前缀 `#<runid>` (如 `#001 state`): 精确整行去重,
// 相同命令不同 run ID 均执行; CMD/RESULT 日志带同一 run ID 便于关联证据

mod antikick;
mod detour;
mod kick;
mod scan;
mod sdk;
mod telemetry;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::Threading::CreateThread;

// 全局状态 (注入进程内)
pub static SDK_BASE: AtomicU64 = AtomicU64::new(0); // PlayFabMultiplayerWin.dll 基址
pub static MP_HANDLE: AtomicU64 = AtomicU64::new(0); // PFMultiplayerHandle (游戏初始化好的)
pub static MY_ID: AtomicU64 = AtomicU64::new(0); // 自己 entity id (C 字符串指针, setid 命令设置)
pub static ANTIKICK: AtomicBool = AtomicBool::new(false); // 防踢开关

const CMD_FILE: &str = r"C:\Users\Wray\AppData\Local\Temp\opencode\gbfr_sdk_cmd.txt";
const OUT_FILE: &str = r"C:\Users\Wray\AppData\Local\Temp\opencode\gbfr_sdk_out.txt";
// T5 诊断开关文件 (DLL 加载时读一次; inject.exe 无法改已运行进程的环境变量)
// 每行一个选项, 空行忽略, 大小写不敏感。主选择器 hooks / grab / leave 至多一个；
// no_telemetry / no_join 仅修饰 legacy hooks；未知或冲突输入 fail-closed 到 S0。
const DIAG_FILE: &str = r"C:\Users\Wray\AppData\Local\Temp\opencode\gbfr_diag.txt";

// T5 诊断开关 (DllMain 从 DIAG_FILE 解析后写入; 默认 = S0 load-only, 零游戏/PlayFab hook)
// 主选择器 hooks/grab/leave 至多一个；未知行或多个主选择器 fail-closed 到 S0。
// no_telemetry/no_join 仅是 legacy hooks 的修饰符，不会自行启用 hook。
pub static DIAG_HOOKS: AtomicBool = AtomicBool::new(false);
pub static DIAG_GRAB: AtomicBool = AtomicBool::new(false);
pub static DIAG_LEAVE: AtomicBool = AtomicBool::new(false);
pub static DIAG_NO_TELEMETRY: AtomicBool = AtomicBool::new(false);
pub static DIAG_NO_JOIN: AtomicBool = AtomicBool::new(false);

// 纯函数: 解析诊断开关文件内容 (单测覆盖; 文件读取在 DllMain)
// 返回 (hooks, grab, leave, no_telemetry, no_join); 无文件/空文件/未知/冲突 → 主选择器全 false = S0 load-only
pub fn parse_diag_flags(content: &str) -> (bool, bool, bool, bool, bool) {
    let mut hooks = false;
    let mut grab = false;
    let mut leave = false;
    let mut no_telemetry = false;
    let mut no_join = false;
    let mut invalid = false;
    for raw in content.lines() {
        let flag = raw.trim().to_ascii_lowercase();
        if flag.is_empty() {
            continue;
        }
        match flag.as_str() {
            "hooks" => hooks = true,
            "grab" => grab = true,
            "leave" => leave = true,
            "no_telemetry" => no_telemetry = true,
            "no_join" => no_join = true,
            _ => invalid = true,
        }
    }
    if invalid
        || [hooks, grab, leave]
            .into_iter()
            .filter(|selected| *selected)
            .count()
            > 1
    {
        hooks = false;
        grab = false;
        leave = false;
    }
    (hooks, grab, leave, no_telemetry, no_join)
}

// UTC 时间戳 e.g. "2026-08-11T12:34:56Z", 每个 log 行前缀
fn ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ts_from_secs(secs)
}

// 纯函数: Unix secs → "YYYY-MM-DDTHH:MM:SSZ" (Howard Hinnant days↔civil 算法, 零依赖)
fn ts_from_secs(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

pub fn log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUT_FILE)
    {
        let _ = writeln!(f, "[{}] {}", ts(), msg);
    }
}

// run ID 日志标记: Some(id) → "#001"; None → "no-runid" (警告标记)
fn marker(runid: Option<u64>) -> String {
    match runid {
        Some(id) => format!("#{:03}", id),
        None => "no-runid".to_string(),
    }
}

// 解析单行命令: `#<runid> <cmd> [args]` 或 `<cmd> [args]`
// 返回 (runid, tokens); 空白行 / 非法 `#` 前缀 → None (忽略)
fn parse_cmd_line(line: &str) -> Option<(Option<u64>, Vec<&str>)> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if let Some(rest) = parts[0].strip_prefix('#') {
        Some((Some(rest.parse::<u64>().ok()?), parts[1..].to_vec()))
    } else {
        Some((None, parts))
    }
}

// 消费决策: 该行是否应执行 (精确按整行去重, 含 run ID)
// ponytail: seen 集合随不同行数增长 — 命令工具进程级, 可接受; 若出现海量 run ID 再换有界缓存
fn line_is_new(line: &str, seen: &mut HashSet<String>) -> bool {
    let line = line.trim();
    !line.is_empty() && seen.insert(line.to_string())
}

// 分发命令; 返回 true 表示 unload (线程应退出)
unsafe fn dispatch(line: &str, runid: Option<u64>, parts: &[&str]) -> bool {
    let m = marker(runid);
    log(&format!("[{}] CMD: {}", m, line));
    let result = match parts.first() {
        Some(&"scan") => {
            scan::do_scan();
            "done"
        }
        Some(&"kick") => {
            if parts.len() >= 2 {
                kick::do_kick(parts[1]);
                "done"
            } else {
                log(&format!("[{}] kick <id>", m));
                "usage"
            }
        }
        Some(&"kickcfg_exp") => {
            if parts.len() >= 2 && (parts[1] == "on" || parts[1] == "off") {
                let on = parts[1] == "on";
                kick::set_kickcfg_experimental(on);
                log(&format!("[{}] kickcfg_exp {}", m, parts[1]));
                "done"
            } else {
                log(&format!("[{}] kickcfg_exp on|off", m));
                "usage"
            }
        }
        Some(&"antikick_exp") => {
            if parts.len() >= 2 && (parts[1] == "on" || parts[1] == "off") {
                let on = parts[1] == "on";
                antikick::set_experimental(on);
                log(&format!("[{}] antikick_exp {}", m, parts[1]));
                "done"
            } else {
                log(&format!("[{}] antikick_exp on|off", m));
                "usage"
            }
        }
        Some(&"native_antikick_exp") => {
            // T4: 游戏侧原生自踢决策守卫 (默认关闭, 版本绑定 fail-closed)
            if parts.len() >= 2 && (parts[1] == "on" || parts[1] == "off") {
                let on = parts[1] == "on";
                if on {
                    antikick::native_guard_on();
                } else {
                    antikick::native_guard_uninstall();
                }
                log(&format!("[{}] native_antikick_exp {}", m, parts[1]));
                "done"
            } else {
                log(&format!("[{}] native_antikick_exp on|off", m));
                "usage"
            }
        }
        Some(&"setid") => {
            if parts.len() >= 2 {
                let id = std::ffi::CString::new(parts[1]).unwrap_or_default();
                // ponytail: into_raw 泄漏 — 每次 setid 泄漏一份字符串 (进程级工具, 可接受);
                // 需释放时: 保存旧 ptr, CString::from_raw 重建后 drop
                let ptr = id.into_raw();
                MY_ID.store(ptr as u64, Ordering::Relaxed);
                log(&format!("[{}] MY_ID set: {}", m, parts[1]));
                "done"
            } else {
                log(&format!("[{}] setid <hex>", m));
                "usage"
            }
        }
        Some(&"antikick_on") => {
            ANTIKICK.store(true, Ordering::Relaxed);
            antikick::install();
            antikick::set_enabled(true);
            log(&format!("[{}] antikick ON", m));
            "done"
        }
        Some(&"antikick_off") => {
            ANTIKICK.store(false, Ordering::Relaxed);
            antikick::set_enabled(false);
            log(&format!("[{}] antikick OFF", m));
            "done"
        }
        Some(&"state") => {
            sdk::check_handle();
            log(&format!(
                "[{}] STATE sdk=0x{:X} handle=0x{:X} lobby=0x{:X} myid=0x{:X} antikick={}",
                m,
                SDK_BASE.load(Ordering::Relaxed),
                MP_HANDLE.load(Ordering::Relaxed),
                kick::lobby_handle(),
                MY_ID.load(Ordering::Relaxed),
                ANTIKICK.load(Ordering::Relaxed)
            ));
            log(&format!("[{}] LOBBY_SOURCES: {}", m, kick::lobby_sources()));
            "done"
        }
        Some(&"unload") => {
            // B29: 恢复全部 hook 后自卸载 (游戏无需重启, 下次注入即新代码)
            // T5: 分阶段日志 — 每步恢复可独立关联证据; 全部恢复后报告 outstanding 近分配
            log(&format!("[{}] unloading...", m));
            log(&format!("[{}] unload: kicking hooks...", m));
            kick::unhook();
            log(&format!("[{}] unload: antikick hooks...", m));
            antikick::unhook();
            log(&format!("[{}] unload: grab hook...", m));
            sdk::unhook_grab();
            log(&format!("[{}] unload: telemetry hooks...", m));
            telemetry::unhook();
            log(&format!("[{}] unload: native guard...", m));
            antikick::native_guard_uninstall();
            log(&format!("[{}] unload: hooks restored (all)", m));
            let n = detour::near_alloc_count();
            if n > 0 {
                log(&format!(
                    "[{}] unload: near allocs outstanding: {} (not freed — see detour.rs ponytail note)",
                    m, n
                ));
            }
            log(&format!("[{}] unload: cmd thread exiting", m));
            log(&format!("[{}] RESULT: done", m));
            let h = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(
                windows_sys::core::w!("gbfr_sdk_dll.dll"),
            );
            if !h.is_null() {
                windows_sys::Win32::System::LibraryLoader::FreeLibraryAndExitThread(h, 0);
            }
            return true;
        }
        Some(&_) => {
            log(&format!("[{}] unknown cmd", m));
            "unknown"
        }
        None => {
            log(&format!("[{}] no command", m));
            "usage"
        }
    };
    log(&format!("[{}] RESULT: {}", m, result));
    false
}

// 命令处理线程
unsafe extern "system" fn cmd_thread(_p: *mut core::ffi::c_void) -> u32 {
    use std::io::Read;
    log("[dll] cmd thread started");
    let mut seen = HashSet::new();
    // The command file is an append-only shared history. A freshly injected DLL
    // must not replay commands emitted before this process existed (especially
    // `unload`, which would immediately tear down the new injection). Only lines
    // appended after this baseline are eligible for dispatch.
    if let Ok(existing) = std::fs::read_to_string(CMD_FILE) {
        for raw in existing.lines() {
            let line = raw.trim();
            if !line.is_empty() {
                seen.insert(line.to_string());
            }
        }
        log(&format!(
            "[dll] command history baselined ({} lines)",
            seen.len()
        ));
    }
    // Phase 2C S1: `grab` 选择器推迟到首个 update 安装 — DllMain 已在 loader lock 内返回,
    // 此处抓取 hook 与游戏线程并发 (capture 幂等安装, 不触碰 lobby 状态机)
    let mut first_update = true;
    loop {
        if first_update {
            first_update = false;
            if DIAG_GRAB.load(Ordering::Relaxed) {
                sdk::install_grab_handle();
            }
        }
        telemetry::drain();
        // T10: 轮询异步入房 out-param 槽 (两次静态检查, 极廉) — 抓到 lobby handle 即 one-shot 存 LOBBY_JOIN
        kick::poll_join_out();
        // T1: 被动 telemetry (幂等, 门控不过/已装即静默早退) — MP_HANDLE 抓到 (grab 已恢复) 后才装
        // S0/load-only: 未显式 opt-in `hooks` 时永不安装任何 PlayFab hook
        if DIAG_HOOKS.load(Ordering::Relaxed) {
            telemetry::install();
        } else if DIAG_LEAVE.load(Ordering::Relaxed) {
            // Phase 2C S2: `leave` 选择器 — 只装 PFLobbyLeave 被动记录 far stub
            // (不装 grab/FinishProcessing; 幂等安装在 cmd worker, 避开 DllMain loader lock)
            telemetry::install_leave_only();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut s = String::new();
        if let Ok(mut f) = std::fs::File::open(CMD_FILE) {
            if f.read_to_string(&mut s).is_ok() {
                for raw in s.lines() {
                    let line = raw.trim();
                    if let Some((runid, parts)) = parse_cmd_line(line) {
                        if line_is_new(line, &mut seen) && dispatch(line, runid, &parts) {
                            return 0;
                        }
                    }
                }
            }
        }
    }
}

// DLL 入口: 注入后自动开命令线程
// B23/MINOR-5: PROCESS_ATTACH (loader lock 内) 执行文件 I/O log — 注入工具常见实践, 已实测可行;
//   严格性限制已知 (loader lock 内 I/O 可能阻塞/死锁于极端情况, 且 log 失败静默), 不重构仅记录。
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h: *mut core::ffi::c_void,
    reason: u32,
    _r: *mut core::ffi::c_void,
) -> i32 {
    if reason == 1 {
        // DLL_PROCESS_ATTACH
        log("[dll] attached");
        sdk::init();
        // T5: 诊断开关 (读失败/无文件 = 默认 S0 load-only, 零 hook)
        let (hooks, grab, leave, no_telemetry, no_join) = std::fs::read_to_string(DIAG_FILE)
            .map(|s| parse_diag_flags(&s))
            .unwrap_or((false, false, false, false, false));
        DIAG_HOOKS.store(hooks, Ordering::Relaxed);
        DIAG_GRAB.store(grab, Ordering::Relaxed);
        DIAG_LEAVE.store(leave, Ordering::Relaxed);
        DIAG_NO_TELEMETRY.store(no_telemetry, Ordering::Relaxed);
        DIAG_NO_JOIN.store(no_join, Ordering::Relaxed);
        log(&format!(
            "[dll] diag: hooks={} grab={} leave={} no_telemetry={} no_join={}",
            hooks, grab, leave, no_telemetry, no_join
        ));
        // S0/load-only 默认: 不装任何游戏/PlayFab hook, 除非 diag 显式 opt-in `hooks`
        if hooks {
            // 抓 handle: hook SDK StartProcessing
            sdk::install_grab_handle();
            // K1/B21-B22: hook SDK PFLobbyPostUpdate/PFLobbyGetLobbyId 导出抓 lobby handle (B12)
            kick::install_lobby_hooks(no_join);
        } else if grab || leave {
            // Phase 2C S1/S2: 首个 cmd update 安装所选单一 hook (避开 DllMain loader lock)
            log("[dll] deferred install to first cmd update (grab/leave selector)");
        } else {
            log("[dll] S0 load-only: zero game/PlayFab hooks installed");
        }
        let mut tid = 0u32;
        CreateThread(
            std::ptr::null(),
            0,
            Some(cmd_thread),
            std::ptr::null_mut(),
            0,
            &mut tid,
        );
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_and_without_runid() {
        let (id, toks) = parse_cmd_line("#001 state").unwrap();
        assert_eq!(id, Some(1));
        assert_eq!(toks, ["state"]);
        let (id, toks) = parse_cmd_line("kick 3").unwrap();
        assert_eq!(id, None);
        assert_eq!(toks, ["kick", "3"]);
        let (id, toks) = parse_cmd_line("  #7 scan  ").unwrap();
        assert_eq!(id, Some(7));
        assert_eq!(toks, ["scan"]);
    }

    #[test]
    fn empty_and_malformed_lines_are_ignored() {
        assert_eq!(parse_cmd_line(""), None);
        assert_eq!(parse_cmd_line("   "), None);
        assert_eq!(parse_cmd_line("\t"), None);
        assert_eq!(parse_cmd_line("#abc state"), None);
    }

    #[test]
    fn different_runids_both_execute() {
        let mut seen = HashSet::new();
        assert!(line_is_new("#001 state", &mut seen));
        assert!(line_is_new("#002 state", &mut seen));
        assert_eq!(parse_cmd_line("#001 state").unwrap().1, ["state"]);
        assert_eq!(parse_cmd_line("#002 state").unwrap().1, ["state"]);
    }

    #[test]
    fn exact_same_line_never_executes_twice() {
        let mut seen = HashSet::new();
        assert!(line_is_new("#001 state", &mut seen));
        assert!(!line_is_new("#001 state", &mut seen));
        assert!(!line_is_new("#001 state", &mut seen));
    }

    #[test]
    fn no_runid_warns_and_executes_once() {
        assert_eq!(marker(None), "no-runid");
        assert_eq!(marker(Some(1)), "#001");
        let mut seen = HashSet::new();
        assert!(line_is_new("state", &mut seen));
        assert!(!line_is_new("state", &mut seen));
    }

    #[test]
    fn empty_input_does_nothing() {
        assert_eq!(parse_cmd_line(""), None);
        let mut seen = HashSet::new();
        assert!(!line_is_new("", &mut seen));
        assert!(!line_is_new("   ", &mut seen));
        assert!(seen.is_empty());
    }

    #[test]
    fn ts_formats_utc() {
        assert_eq!(ts_from_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(ts_from_secs(1_786_406_400), "2026-08-11T00:00:00Z");
        assert_eq!(marker(Some(123_456)), "#123456");
    }

    #[test]
    fn diag_empty_and_missing_defaults_s0_load_only() {
        assert_eq!(parse_diag_flags(""), (false, false, false, false, false));
        assert_eq!(
            parse_diag_flags("   \n\t\n"),
            (false, false, false, false, false)
        );
    }

    #[test]
    fn diag_flags_parse_with_trim_and_case_insensitive() {
        assert_eq!(
            parse_diag_flags("no_telemetry\nno_join"),
            (false, false, false, true, true)
        );
        assert_eq!(
            parse_diag_flags("  NO_TELEMETRY  \n"),
            (false, false, false, true, false)
        );
        assert_eq!(
            parse_diag_flags("no_join"),
            (false, false, false, false, true)
        );
    }

    #[test]
    fn diag_hooks_is_explicit_optin() {
        assert_eq!(
            parse_diag_flags("hooks"),
            (true, false, false, false, false)
        );
        assert_eq!(
            parse_diag_flags("  HOOKS  \n"),
            (true, false, false, false, false)
        );
        assert_eq!(
            parse_diag_flags("hooks\nno_telemetry\nno_join"),
            (true, false, false, true, true)
        );
    }

    #[test]
    fn diag_grab_is_explicit_selector() {
        assert_eq!(parse_diag_flags("grab"), (false, true, false, false, false));
        assert_eq!(
            parse_diag_flags("  GRAB  \n"),
            (false, true, false, false, false)
        );
        assert_eq!(
            parse_diag_flags("grab\nno_telemetry"),
            (false, true, false, true, false)
        );
        assert_eq!(
            parse_diag_flags("hooks\ngrab"),
            (false, false, false, false, false)
        );
    }

    #[test]
    fn diag_leave_is_explicit_selector() {
        assert_eq!(
            parse_diag_flags("leave"),
            (false, false, true, false, false)
        );
        assert_eq!(
            parse_diag_flags("  LEAVE  \n"),
            (false, false, true, false, false)
        );
        assert_eq!(
            parse_diag_flags("leave\nno_telemetry"),
            (false, false, true, true, false)
        );
        assert_eq!(
            parse_diag_flags("hooks\nleave"),
            (false, false, false, false, false)
        );
    }

    #[test]
    fn diag_unknown_lines_fail_closed() {
        assert_eq!(
            parse_diag_flags("bogus\nno_kick\nNO_TELEMETRY_extra"),
            (false, false, false, false, false)
        );
        assert_eq!(
            parse_diag_flags("leave\n# comment"),
            (false, false, false, false, false)
        );
        assert_eq!(
            parse_diag_flags("no_telemetry\nno_join"),
            (false, false, false, true, true)
        );
    }
}
