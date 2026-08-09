// 游戏逻辑: 队伍编辑 / 露莉亚切换 / 选中角色修改
use crate::memory::Process;
use crate::chars;
use serde::Serialize;
use std::sync::Mutex;

// 全局连接状态
pub static CONNECTED: Mutex<bool> = Mutex::new(false);

pub const GAME_PROCESS: &str = "granblue_fantasy_relink.exe";
pub const PARTY_PTR_RVA: u64 = 0x701C420; // 队伍指针
pub const PARTY_SLOT_SIZE: u64 = 0x10; // 每槽位 0x10
pub const PARTY_MAX_SLOTS: u64 = 5;

// 特殊角色
pub const LYRIA: u32 = 0x3529CC90;

#[derive(Serialize, Clone)]
pub struct GameStatus {
    pub running: bool,
    pub base: Option<u64>,
    pub party_ptr: Option<u64>,
    pub slots: Vec<SlotInfo>,
}

#[derive(Serialize, Clone)]
pub struct SlotInfo {
    pub index: u32,
    pub id: u32,
    pub name: String,
}

#[derive(Serialize, Clone)]
pub struct SlotUpdate {
    pub slot: u32,
    pub id: u32,
    pub name: String,
}

/// 获取游戏状态 (进程/模块/队伍)
pub fn game_status() -> GameStatus {
    let pid = match Process::find_by_name(GAME_PROCESS) {
        Some(p) => p,
        None => return GameStatus { running: false, base: None, party_ptr: None, slots: vec![] },
    };
    let proc = match Process::open(pid) {
        Ok(p) => p,
        Err(_) => return GameStatus { running: false, base: None, party_ptr: None, slots: vec![] },
    };
    let base = proc.module_base(GAME_PROCESS);
    let party_ptr = base.map(|b| proc.read_u64(b + PARTY_PTR_RVA).unwrap_or(0));
    let mut slots = vec![];
    if let Some(pp) = party_ptr {
        for i in 0..PARTY_MAX_SLOTS {
            let addr = pp + i * PARTY_SLOT_SIZE;
            let id = proc.read_u32(addr).unwrap_or(0);
            slots.push(SlotInfo {
                index: i as u32,
                id,
                name: chars::char_name(id).to_string(),
            });
        }
    }
    GameStatus { running: true, base, party_ptr, slots }
}

/// 设置队伍槽位
pub fn set_slot(slot: u32, id: u32) -> Result<SlotUpdate, String> {
    if slot as u64 >= PARTY_MAX_SLOTS {
        return Err(format!("槽位超出范围: {}", slot));
    }
    let pid = Process::find_by_name(GAME_PROCESS).ok_or("游戏未运行")?;
    let proc = Process::open(pid).map_err(|e| e.to_string())?;
    let base = proc.module_base(GAME_PROCESS).ok_or("找不到模块")?;
    let party_ptr = proc.read_u64(base + PARTY_PTR_RVA).ok_or("队伍指针无效")?;
    let addr = party_ptr + slot as u64 * PARTY_SLOT_SIZE;
    if !proc.write_u32(addr, id) {
        return Err("写入失败".into());
    }
    Ok(SlotUpdate { slot, id, name: chars::char_name(id).to_string() })
}

/// 露莉亚切换: on = 露莉亚入队, off = 恢复原角色
pub fn lyria_switch(mode: &str) -> Result<String, String> {
    let pid = Process::find_by_name(GAME_PROCESS).ok_or("游戏未运行")?;
    let proc = Process::open(pid).map_err(|e| e.to_string())?;
    let base = proc.module_base(GAME_PROCESS).ok_or("找不到模块")?;
    let party_ptr = proc.read_u64(base + PARTY_PTR_RVA).ok_or("队伍指针无效")?;
    let slot0 = party_ptr; // 槽位 0

    match mode {
        "on" => {
            let cur = proc.read_u32(slot0).unwrap_or(0);
            if cur == LYRIA {
                Ok("已经在用露莉亚了".into())
            } else {
                // 保存原角色到隐藏槽(+0x40)作为备份
                proc.write_u32(party_ptr + 4 * PARTY_SLOT_SIZE, cur);
                proc.write_u32(slot0, LYRIA);
                Ok(format!("已切换: {:08X} -> 露莉亚({:08X})\n现在可以进战斗, 但不要开菜单!", cur, LYRIA))
            }
        }
        "off" => {
            // 从隐藏槽恢复
            let saved = proc.read_u32(party_ptr + 4 * PARTY_SLOT_SIZE).unwrap_or(0);
            let cur = proc.read_u32(slot0).unwrap_or(0);
            if saved != 0 && saved != LYRIA {
                proc.write_u32(slot0, saved);
                Ok(format!("已恢复: {:08X} -> {:08X}\n现在可以安全开菜单了", cur, saved))
            } else {
                Err("没有保存的原角色记录 (隐藏槽为空)".into())
            }
        }
        _ => Err("无效模式".into()),
    }
}



/// 战斗作弊: 无CD / 无限血 (RVA + 原始字节, 可开关)
pub struct BattlePatch {
    pub name: &'static str,
    pub rva: u64,
    pub orig: &'static [u8],
    pub patched: &'static [u8],
    pub enabled: bool,
}

pub const NO_CD: BattlePatch = BattlePatch {
    name: "no_cd",
    rva: 0x21EA5D9,
    orig: &[0xC5, 0xFA, 0x11, 0x4E, 0x1C],  // vmovss [rsi+1C],xmm1
    patched: &[0x0F, 0x57, 0xC9, 0x90, 0x90], // xorps xmm1,xmm1; nop; nop
    enabled: false,
};

pub const INFINITE_HP: BattlePatch = BattlePatch {
    name: "infinite_hp",
    rva: 0x1FB8D96,
    orig: &[0x48, 0x63, 0x96, 0xD4, 0x00, 0x00, 0x00],  // movsxd rdx,[rsi+D4]
    patched: &[0x31, 0xD2, 0x90, 0x90, 0x90, 0x90, 0x90], // xor edx,edx; nop*5
    enabled: false,
};

pub fn apply_patch(patch: &BattlePatch, enable: bool) -> Result<(), String> {
    let pid = Process::find_by_name(GAME_PROCESS).ok_or("游戏未运行")?;
    let proc = Process::open(pid).map_err(|e| e.to_string())?;
    let base = proc.module_base(GAME_PROCESS).ok_or("找不到模块")?;
    let addr = base + patch.rva;
    let data = if enable { &patch.patched } else { &patch.orig };
    if !proc.write(addr, data) {
        return Err(format!("写入失败: {}", patch.name));
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub struct CheatState {
    pub no_cd: bool,
    pub infinite_hp: bool,
}


// ============ 选中角色修改 (罗兰因子方法) ============

/// 全内存扫描 4字节值, 返回所有匹配地址 (绝对地址)
pub fn scan_u32_all(value: u32) -> Vec<u64> {
    let pid = match Process::find_by_name(GAME_PROCESS) { Some(p) => p, None => return vec![] };
    let proc = match Process::open(pid) { Ok(p) => p, Err(_) => return vec![] };
    let mut hits = vec![];
    unsafe {
        let mut addr: usize = 0;
        loop {
            let mut mbi: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ok = windows_sys::Win32::System::Memory::VirtualQueryEx(
                proc.handle, addr as *const _, &mut mbi,
                std::mem::size_of::<windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION>());
            if ok == 0 { break; }
            let base_addr = mbi.BaseAddress as u64;
            let region = mbi.RegionSize as u64;
            if mbi.State == 0x1000 /* MEM_COMMIT */ && (mbi.Protect & 0xFF) != 0 {
                let prot = mbi.Protect & 0xFF;
                if prot == 0x02 || prot == 0x04 || prot == 0x08 || prot == 0x10 || prot == 0x20 || prot == 0x40 || prot == 0x80 {
                    let size = region.min(0x20000000);
                    let mut off = 0u64;
                    while off < size {
                        let chunk = size - off;
                        let chunk = chunk.min(0x200000) as usize;
                        if let Some(data) = proc.read(base_addr + off, chunk) {
                            for i in 0..data.len().saturating_sub(3) {
                                let v = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
                                if v == value {
                                    hits.push(base_addr + off + i as u64);
                                }
                            }
                        }
                        off += chunk as u64;
                    }
                }
            }
            let next = base_addr.checked_add(region);
            match next {
                Some(n) if n > base_addr => addr = n as usize,
                _ => break,
            }
        }
    }
    hits
}

/// 过滤: 保留当前值仍 = role_id 的地址 (切换后值变了的位置被淘汰)
pub fn filter_selected(addrs: &[u64], role_id: u32) -> Vec<u64> {
    let pid = match Process::find_by_name(GAME_PROCESS) { Some(p) => p, None => return vec![] };
    let proc = match Process::open(pid) { Ok(p) => p, Err(_) => return vec![] };
    addrs.iter().copied()
        .filter(|a| proc.read_u32(*a) == Some(role_id))
        .collect()
}


// ============ 连接控制 ============
#[derive(serde::Serialize)]
pub struct ConnState {
    pub connected: bool,
    pub base: Option<u64>,
}

pub fn connect() -> Result<ConnState, String> {
    let pid = Process::find_by_name(GAME_PROCESS).ok_or("游戏未运行")?;
    let proc = Process::open(pid).map_err(|e| e.to_string())?;
    let base = proc.module_base(GAME_PROCESS).ok_or("找不到模块")?;
    // 验证队伍指针可读
    proc.read_u64(base + PARTY_PTR_RVA).ok_or("队伍指针无效")?;
    *CONNECTED.lock().unwrap() = true;
    Ok(ConnState { connected: true, base: Some(base) })
}

pub fn disconnect() -> Result<ConnState, String> {
    *CONNECTED.lock().unwrap() = false;
    Ok(ConnState { connected: false, base: None })
}

pub fn conn_state() -> ConnState {
    let c = *CONNECTED.lock().unwrap();
    ConnState { connected: c, base: None }
}
