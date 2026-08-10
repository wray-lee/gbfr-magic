// 联机功能: 扫描游戏内存中的房间列表 JSON (服务器下发, 含密码明文)
use crate::memory::Process;
use serde::Serialize;

pub const GAME_PROCESS: &str = "granblue_fantasy_relink.exe";

#[derive(Serialize, Clone)]
pub struct RoomInfo {
    pub leader_name: String,
    pub platform: u32,
    pub account_id: String,
    pub password: String,
    pub locked: bool,
}

#[derive(Serialize, Clone)]
pub struct MemberInfo {
    pub name: String,        // 平台名 (member_platform_user_name, 如 Steam 昵称)
    pub game_name: String,   // 游戏内名字 (leader_name, 如 羅順蘭)
    pub platform: String,
    pub account_id: String,
    pub game_id: String,     // title_player_account Id (16 hex)
}

// 扫描当前房间成员
// 权威来源: PlayFab Lobby 状态里的 Members 数组 (MemberData JSON, 无历史缓存)
// 每个成员: MemberEntity.Id = game_id, MemberData.member_platform_* = 平台信息
// 游戏名: 从 "成员对象" 匹配 (game_id + 附近 UTF-8 游戏名, 如 羅順蘭)
pub fn scan_members() -> Result<Vec<MemberInfo>, String> {
    let pid = Process::find_by_name(GAME_PROCESS).ok_or("游戏未运行")?;
    let proc = Process::open(pid).map_err(|e| e.to_string())?;

    // 单次全堆扫描, 收集:
    // 1) MemberData JSON (当前房间 Members 数组, 权威成员列表)
    // 2) leader_name JSON (房主游戏名, 用于匹配成员游戏名)
    let mut all_member_data: Vec<(String, String, String, String)> = Vec::new(); // (name, platform, account_id, game_id)
    let mut leader_names: std::collections::HashMap<String, String> = std::collections::HashMap::new(); // account_id -> 游戏名
    let mut game_names: std::collections::HashMap<String, String> = std::collections::HashMap::new(); // game_id -> 游戏名

    scan_heap_blocks(&proc, &mut |region_addr, data| {
        // 扫描 MemberData (成员数组)
        let mut idx = 0;
        while let Some(rel) = find_sub(data, b"MemberData", idx) {
            if let Some((gid, json)) = parse_member_data_in_chunk(data, rel) {
                let name = json_str_field(&json, "member_platform_user_name").unwrap_or_default();
                let platform = json_str_field(&json, "member_platform").unwrap_or_default();
                let account_id = json_str_field(&json, "member_platform_account_id").unwrap_or_default();
                all_member_data.push((name, platform, account_id, gid));
            }
            idx = rel + 1;
        }
        // 扫描 leader_name (房主游戏名, string_key5 房间 JSON)
        let mut idx = 0;
        while let Some(rel) = find_sub(data, b"leader_name", idx) {
            if let Some((acc, gname)) = parse_leader_in_chunk(data, rel) {
                leader_names.entry(acc).or_insert(gname);
            }
            idx = rel + 1;
        }
        // 扫描游戏名对象 (game_id + 附近 UTF-8 游戏名)
        let mut idx = 0;
        while let Some(rel) = find_sub(data, b"title_player_account", idx) {
            if let Some((gid, gname)) = parse_game_name_near(data, rel) {
                game_names.entry(gid).or_insert(gname);
            }
            idx = rel + 1;
        }
    });

    // 组装成员: MemberData 为主, 游戏名 = leader_names(房主) 或 game_names(成员对象)
    let mut members: Vec<MemberInfo> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (name, platform, account_id, game_id) in &all_member_data {
        let key = format!("{}|{}", platform, account_id);
        if !seen.insert(key) {
            continue;
        }
        // 空条目过滤: 无账号且无 game_id 的不显示
        if account_id.is_empty() && game_id.is_empty() {
            continue;
        }
        // 游戏名: 优先 leader_names (房主), 否则 game_names (成员对象)
        let gname = leader_names.get(account_id)
            .or_else(|| game_names.get(game_id))
            .cloned()
            .unwrap_or_default();
        members.push(MemberInfo {
            name: name.clone(),
            game_name: gname,
            platform: platform.clone(),
            account_id: account_id.clone(),
            game_id: game_id.clone(),
        });
    }
    Ok(members)
}

// 解析 MemberData JSON: 提取 memberEntity Id (game_id) 和 MemberData 内容
// 模式: {"MemberEntity":{"Id":"<16hex>","Type":"title_player_account",...},"MemberData":{...}}
fn parse_member_data_in_chunk(data: &[u8], rel: usize) -> Option<(String, String)> {
    // 向前找 MemberEntity.Id
    let start = rel.saturating_sub(0x200);
    let window = &data[start..data.len().min(rel + 0x300)];
    let m_id = find_in_window(window, b"\"Id\":\"")?;
    let gid_start = m_id + b"\"Id\":\"".len();
    let gid: String = window[gid_start..]
        .iter()
        .take_while(|b| b.is_ascii_hexdigit())
        .map(|b| *b as char)
        .collect();
    if gid.len() != 16 { return None; }
    // MemberData JSON 内容
    let m_data = find_in_window(window, b"\"MemberData\":{")?;
    let js_rel = m_data + b"\"MemberData\":{".len() - 1;
    let content = &window[js_rel..];
    let mut depth = 0i32;
    let mut end = None;
    for (i, &b) in content.iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { end = Some(i + 1); break; } }
            _ => {}
        }
    }
    let json = std::str::from_utf8(&content[..end?]).ok()?.to_string();
    Some((gid, json))
}

// 解析 leader_name JSON: 返回 (account_id, 游戏名)
fn parse_leader_in_chunk(data: &[u8], rel: usize) -> Option<(String, String)> {
    let start = rel.saturating_sub(0x80);
    let window = &data[start..data.len().min(rel + 0x200)];
    let json = parse_json_in_chunk_from(&window, rel - start, 0x80)?;
    let name = json_str_field(&json, "leader_name")?;
    let acc = json_str_field(&json, "leader_platform_account_id").unwrap_or_default();
    if acc.is_empty() { return None; }
    Some((acc, name))
}

// 从窗口内解析 JSON (起点 = 窗口内偏移)
fn parse_json_in_chunk_from(window: &[u8], rel: usize, max_back: usize) -> Option<String> {
    let start = rel.saturating_sub(max_back);
    let w = &window[start..];
    let mut js_rel = None;
    for i in (0..w.len()).rev() {
        if w[i] == b'{' { js_rel = Some(i); break; }
    }
    let js = js_rel?;
    let content = &w[js..];
    let mut depth = 0i32;
    let mut end = None;
    for (i, &b) in content.iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { end = Some(i + 1); break; } }
            _ => {}
        }
    }
    std::str::from_utf8(&content[..end?]).ok().map(|s| s.to_string())
}

// 找窗口内子串
fn find_in_window(window: &[u8], pat: &[u8]) -> Option<usize> {
    find_sub(window, pat, 0)
}

// 从 title_player_account 对象附近找游戏名 (game_id + 0x20..0x60 后 UTF-8 名字)
fn parse_game_name_near(data: &[u8], rel: usize) -> Option<(String, String)> {
    // 向前找 Id
    let start = rel.saturating_sub(0x100);
    let window = &data[start..rel];
    let m = find_in_window(window, b"\"Id\":\"")?;
    let gid_start = m + b"\"Id\":\"".len();
    let gid: String = window[gid_start..]
        .iter()
        .take_while(|b| b.is_ascii_hexdigit())
        .map(|b| *b as char)
        .collect();
    if gid.len() != 16 { return None; }
    // 向后 0x100 找 UTF-8 名字 (中文/日文, 3 字节+)
    let after = &data[rel..data.len().min(rel + 0x200)];
    // 找连续 UTF-8 多字节序列
    let mut best: Option<(usize, String)> = None;
    let mut i = 0;
    while i < after.len() {
        if after[i] >= 0xE0 && i + 2 < after.len() {
            // 尝试解码 UTF-8 序列
            let len = utf8_len(after[i]);
            if len >= 2 && i + len <= after.len() {
                if let Ok(s) = std::str::from_utf8(&after[i..i + len]) {
                    if s.chars().all(|c| c.is_alphanumeric() || c.is_ascii_punctuation() || c == '❤' || c == '❤') && s.chars().count() >= 2 {
                        // 扩展连续名字
                        let mut j = i + len;
                        while j < after.len() {
                            let l2 = utf8_len(after[j]);
                            if l2 >= 2 && j + l2 <= after.len() {
                                if let Ok(s2) = std::str::from_utf8(&after[j..j + l2]) {
                                    if s2.chars().all(|c| c.is_alphanumeric() || c == '❤') {
                                        j += l2;
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                        let full = String::from_utf8_lossy(&after[i..j]).to_string();
                        if best.as_ref().map_or(true, |(d, _)| i < *d) {
                            best = Some((i, full));
                        }
                    }
                }
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    best.map(|(_, s)| (gid, s))
}

// UTF-8 序列长度
fn utf8_len(b: u8) -> usize {
    if b >= 0xF0 { 4 } else if b >= 0xE0 { 3 } else if b >= 0xC0 { 2 } else { 1 }
}

// 从消息上下文提取 ~lobby~LobbyChange~<id>
fn extract_lobby_id(ctx: &[u8]) -> Option<String> {
    let pat = b"~lobby~LobbyChange~";
    let idx = find_sub(ctx, pat, 0)?;
    let rest = &ctx[idx + pat.len()..];
    let mut id = String::new();
    for &b in rest {
        if b.is_ascii_hexdigit() || b == b'-' || b == b'.' {
            id.push(b as char);
            if id.len() > 40 { break; }
        } else {
            break;
        }
    }
    if id.contains('-') && id.len() > 20 { Some(id) } else { None }
}

// 提取上下文中所有 16-hex (成员 ID)
fn extract_hex_ids(ctx: &[u8]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let mut i = 0;
    while i + 16 <= ctx.len() {
        if ctx[i..i + 16].iter().all(|b| b.is_ascii_hexdigit()) {
            let before_ok = i == 0 || !ctx[i - 1].is_ascii_hexdigit();
            let after_ok = i + 16 >= ctx.len() || !ctx[i + 16].is_ascii_hexdigit();
            if before_ok && after_ok {
                out.insert(String::from_utf8_lossy(&ctx[i..i + 16]).to_uppercase());
            }
        }
        i += 1;
    }
    out
}

// 从位置向前找 '{' 并解析完整 JSON
fn parse_json_at(proc: &Process, hit_pos: usize, max_back: usize) -> Option<String> {
    let back = proc.read((hit_pos as u64).saturating_sub(max_back as u64), max_back)?;
    let mut js_rel = None;
    for i in (0..back.len()).rev() {
        if back[i] == b'{' { js_rel = Some(i); break; }
    }
    let js = hit_pos.checked_sub(max_back)?.checked_add(js_rel?)?;
    let content = proc.read(js as u64, 0x400)?;
    let mut depth = 0i32;
    let mut end = None;
    for (i, &b) in content.iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { end = Some(i + 1); break; } }
            _ => {}
        }
    }
    let text = std::str::from_utf8(&content[..end?]).ok()?;
    if text.contains("member_platform") { Some(text.to_string()) } else { None }
}

// 在 pos 前 0x500 范围内找 16-hex 游戏内 ID
fn find_game_id_near(proc: &Process, pos: usize) -> String {
    const BACK: usize = 0x500;
    if let Some(data) = proc.read((pos as u64).saturating_sub(BACK as u64), BACK) {
        // 找所有 16 位大写 hex
        let mut best: Option<(usize, String)> = None;
        let bytes = &data;
        let mut i = 0;
        while i + 16 <= bytes.len() {
            let is_hex = bytes[i..i + 16].iter().all(|b| b.is_ascii_hexdigit());
                    if is_hex {
                        let before_ok = i == 0 || !bytes[i - 1].is_ascii_hexdigit();
                        let after_ok = i + 16 >= bytes.len() || !bytes[i + 16].is_ascii_hexdigit();
                        if before_ok && after_ok {
                            let s = String::from_utf8_lossy(&bytes[i..i + 16]).to_uppercase();
                            let dist = BACK - i;
                            if best.as_ref().map_or(true, |(d, _)| dist < *d) {
                                best = Some((dist, s));
                            }
                        }
                    }
            i += 1;
        }
        return best.map(|(_, s)| s).unwrap_or_default();
    }
    String::new()
}

// 块内 JSON 解析: 命中位置 rel 在 data 块内, 直接切片 (0 次额外读)
// 向前最多 max_back 找 '{', 括号配平提取 JSON 文本
fn parse_json_in_chunk(data: &[u8], rel: usize, max_back: usize) -> Option<String> {
    let start = rel.saturating_sub(max_back);
    let window = &data[start..data.len().min(rel + 0x600)];
    let mut js_rel = None;
    for i in (0..window.len()).rev() {
        if window[i] == b'{' { js_rel = Some(i); break; }
    }
    let js = js_rel?;
    let content = &window[js..];
    let mut depth = 0i32;
    let mut end = None;
    for (i, &b) in content.iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => { depth -= 1; if depth == 0 { end = Some(i + 1); break; } }
            _ => {}
        }
    }
    let text = std::str::from_utf8(&content[..end?]).ok()?;
    Some(text.to_string())
}

// 块内找 16-hex 游戏内 ID (命中位置 rel 向前 BACK 字节)
fn find_hex_in_chunk(data: &[u8], rel: usize, back: usize) -> String {
    let start = rel.saturating_sub(back);
    let window = &data[start..rel];
    let mut best: Option<(usize, String)> = None;
    let mut i = 0;
    while i + 16 <= window.len() {
        let is_hex = window[i..i + 16].iter().all(|b| b.is_ascii_hexdigit());
        if is_hex {
            let before_ok = i == 0 || !window[i - 1].is_ascii_hexdigit();
            let after_ok = i + 16 >= window.len() || !window[i + 16].is_ascii_hexdigit();
            if before_ok && after_ok {
                let s = String::from_utf8_lossy(&window[i..i + 16]).to_uppercase();
                let dist = back - i;
                if best.as_ref().map_or(true, |(d, _)| dist < *d) {
                    best = Some((dist, s));
                }
            }
        }
        i += 1;
    }
    best.map(|(_, s)| s).unwrap_or_default()
}

// 高效全堆扫描: 只扫 MEM_PRIVATE (堆), 4MB 大块, 跳过全零块
// 返回每块 (区域地址, 块内偏移, 数据)
fn scan_heap_blocks<'a>(
    proc: &Process,
    cb: &mut dyn FnMut(u64, &[u8]),
) {
    const CHUNK: usize = 0x400000; // 4MB
    for (region_addr, region_size) in proc.heap_regions() {
        let mut off = 0usize;
        while off < region_size {
            let chunk = std::cmp::min(region_size - off, CHUNK);
            if let Some(data) = proc.read(region_addr + off as u64, chunk) {
                // 跳过全零块 (堆里大量空闲零页)
                if data.iter().any(|&b| b != 0) {
                    cb(region_addr + off as u64, &data);
                }
            }
            off += chunk;
        }
    }
}

// 扫描全部可读内存, 找房间 JSON
// 活跃房间 = SearchData.string_key5 的值 (服务器搜索结果, 含 leader_name/lobby_password)
// 裸 leader_name 可能是历史缓存, 仅作为 fallback
pub fn scan_rooms() -> Result<Vec<RoomInfo>, String> {
    let pid = Process::find_by_name(GAME_PROCESS).ok_or("游戏未运行")?;
    let proc = Process::open(pid).map_err(|e| e.to_string())?;

    let mut rooms: Vec<RoomInfo> = Vec::new();
    let mut seen: std::collections::HashSet<(u32, String)> = std::collections::HashSet::new();

    // 1) 主来源: string_key5 值 (搜索结果项)
    let pat_sk5 = b"string_key5";
    scan_heap_blocks(&proc, &mut |_, data| {
        let mut idx = 0;
        while let Some(rel) = find_sub(data, pat_sk5, idx) {
            // string_key5":"{...} 模式: 找引号后的 JSON
            if let Some(info) = parse_sk5_room_in_chunk(data, rel) {
                let key = (info.platform, info.account_id.clone());
                if seen.insert(key) {
                    rooms.push(info);
                }
            }
            idx = rel + 1;
        }
    });

    // 2) fallback: 裸 leader_name (仅当上面没找到时, 避免历史缓存污染)
    if rooms.is_empty() {
        let pat = b"leader_name";
        scan_heap_blocks(&proc, &mut |region_addr, data| {
            let mut idx = 0;
            while let Some(rel) = find_sub(data, pat, idx) {
                let info = if rel >= 0x300 && rel + 0x800 <= data.len() {
                    parse_room_json_in_chunk(data, rel)
                } else {
                    parse_room_json(&proc, region_addr as usize + rel)
                };
                if let Some(info) = info {
                    let key = (info.platform, info.account_id.clone());
                    if seen.insert(key) {
                        rooms.push(info);
                    }
                }
                idx = rel + 1;
            }
        });
    }
    rooms.sort_by(|a, b| a.leader_name.cmp(&b.leader_name));
    Ok(rooms)
}

// 解析 string_key5 的值 (转义 JSON 字符串内的房间 JSON)
fn parse_sk5_room_in_chunk(data: &[u8], rel: usize) -> Option<RoomInfo> {
    // 模式: "string_key5":"{...}"  命中在 string_key5 开头
    let after = &data[rel + b"string_key5".len()..];
    // 找 :"  (跳过空白)
    let mut i = 0;
    while i < after.len() && after[i] != b'"' {
        if after[i] == b':' { break; }
        i += 1;
    }
    while i < after.len() && after[i] != b'"' { i += 1; }
    if i >= after.len() || after[i] != b'"' { return None; }
    let val_start = i + 1;
    // 收集转义字符串内容, 直到未转义的 " 或 0x600 上限
    let mut val = Vec::new();
    let mut j = val_start;
    let mut escaped = false;
    while j < after.len() && val.len() < 0x600 {
        let b = after[j];
        if escaped {
            if b == b'n' { val.push(b'\n'); }
            else if b == b'r' { val.push(b'\r'); }
            else if b == b't' { val.push(b'\t'); }
            else { val.push(b); }
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            break;
        } else {
            val.push(b);
        }
        j += 1;
    }
    let text = std::str::from_utf8(&val).ok()?;
    if !text.contains("leader_name") || !text.contains("lobby_password") {
        return None;
    }
    let leader_name = json_str_field(text, "leader_name")?;
    let platform = json_num_field(text, "leader_platform").unwrap_or(0);
    let account_id = json_str_field(text, "leader_platform_account_id").unwrap_or_default();
    let password = json_str_field(text, "lobby_password").unwrap_or_default();
    Some(RoomInfo {
        leader_name,
        platform,
        account_id,
        // 5555555555 = 无密码房间的默认占位
        password: if password == "5555555555" { String::new() } else { password.clone() },
        locked: !password.is_empty() && password != "5555555555",
    })
}

// 块内房间 JSON 解析 (0 次额外读)
fn parse_room_json_in_chunk(data: &[u8], rel: usize) -> Option<RoomInfo> {
    let text = parse_json_in_chunk(data, rel, 0x300)?;
    if !text.contains("leader_name") || !text.contains("lobby_password") {
        return None;
    }
    let leader_name = json_str_field(&text, "leader_name")?;
    let platform = json_num_field(&text, "leader_platform").unwrap_or(0);
    let account_id = json_str_field(&text, "leader_platform_account_id").unwrap_or_default();
    let password = json_str_field(&text, "lobby_password").unwrap_or_default();
    Some(RoomInfo {
        leader_name,
        platform,
        account_id,
        // 5555555555 = 无密码房间的默认占位 (已验证: 真实密码如 hentai/mrow/hello123/1111/2222)
        password: if password == "5555555555" { String::new() } else { password.clone() },
        locked: !password.is_empty() && password != "5555555555",
    })
}

// 从命中位置向前找 '{', 然后解析完整 JSON
fn parse_room_json(proc: &Process, hit_pos: usize) -> Option<RoomInfo> {
    // 向前最多 0x300 找 '{'
    let back = proc.read((hit_pos as u64).saturating_sub(0x300), 0x300)?;
    let mut js_rel = None;
    for i in (0..back.len()).rev() {
        if back[i] == b'{' {
            js_rel = Some(i);
            break;
        }
    }
    let js = hit_pos.checked_sub(0x300)?.checked_add(js_rel?)?;
    let content = proc.read(js as u64, 0x800)?;
    // 配平括号找结束
    let mut depth = 0i32;
    let mut end = None;
    for (i, &b) in content.iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let text = std::str::from_utf8(&content[..end?]).ok()?;
    if !text.contains("leader_name") || !text.contains("lobby_password") {
        return None;
    }
    // 简单 JSON 字段提取 (不引入 serde_json 解析转义负担)
    let leader_name = json_str_field(text, "leader_name")?;
    let platform = json_num_field(text, "leader_platform").unwrap_or(0);
    let account_id = json_str_field(text, "leader_platform_account_id").unwrap_or_default();
    let password = json_str_field(text, "lobby_password").unwrap_or_default();
    Some(RoomInfo {
        leader_name,
        platform,
        account_id,
        // 5555555555 = 无密码房间的默认占位 (已验证: 真实密码如 hentai/mrow/hello123/1111/2222)
        password: if password == "5555555555" { String::new() } else { password.clone() },
        locked: !password.is_empty() && password != "5555555555",
    })
}

// 从 JSON 文本提取字符串字段值
fn json_str_field(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let idx = text.find(&pat)? + pat.len();
    let rest = &text[idx..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            out.push(chars.next().unwrap_or(' '));
        } else if c == '"' {
            break;
        } else {
            out.push(c);
        }
    }
    Some(out)
}

// 提取数字字段
fn json_num_field(text: &str, key: &str) -> Option<u32> {
    let pat = format!("\"{}\":", key);
    let idx = text.find(&pat)? + pat.len();
    let rest = &text[idx..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn find_sub(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (start..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}
