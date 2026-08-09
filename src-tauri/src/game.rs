// 游戏逻辑: 队伍编辑 / 露莉亚切换 / 选中角色修改
use crate::memory::Process;
use crate::chars;
use serde::Serialize;

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

