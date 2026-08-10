// 角色 ID 数据表

#[derive(Clone, Debug, serde::Serialize)]
pub struct CharInfo {
    pub id: u32,
    pub name: &'static str,
    pub note: &'static str,
}

pub fn all_chars() -> Vec<CharInfo> {
    vec![
        CharInfo { id: 0x2A26B1B2, name: "Gran", note: "主角" },
        CharInfo { id: 0xA4ACBA76, name: "Djeeta", note: "主角" },
        CharInfo { id: 0x18E2F9F9, name: "Katalina", note: "卡塔莉娜" },
        CharInfo { id: 0x079DF0CC, name: "Rackham", note: "拉卡姆" },
        CharInfo { id: 0x4D0A60C3, name: "Io", note: "伊欧" },
        CharInfo { id: 0xDD7A151E, name: "Eugen", note: "欧根" },
        CharInfo { id: 0xC8616284, name: "Rosetta", note: "罗塞塔" },
        CharInfo { id: 0xC3FFD418, name: "Ferry", note: "菲莉" },
        CharInfo { id: 0x22E437E5, name: "Lancelot", note: "兰斯洛特" },
        CharInfo { id: 0x2EBE91D5, name: "Vane", note: "巴恩" },
        CharInfo { id: 0xBDEF7181, name: "Percival", note: "珀西瓦尔" },
        CharInfo { id: 0x627BCB0D, name: "Siegfried", note: "齐格飞" },
        CharInfo { id: 0xFD3BE362, name: "Charlotta", note: "夏洛特" },
        CharInfo { id: 0xFC6CDF7B, name: "Yodarha", note: "尤达哈拉" },
        CharInfo { id: 0xE7053919, name: "Narmaya", note: "娜露梅亚" },
        CharInfo { id: 0x978E4B18, name: "Ghandagoza", note: "冈达葛萨" },
        CharInfo { id: 0x0D21B430, name: "Zeta", note: "塞达" },
        CharInfo { id: 0xF0EB77EF, name: "Vaseraga", note: "巴萨拉卡" },
        CharInfo { id: 0xAA66178A, name: "Cagliostro", note: "卡莉奥丝特罗" },
        CharInfo { id: 0xA3A3CB2F, name: "Id", note: "伊德" },
        CharInfo { id: 0x718E1A14, name: "Sandalphon", note: "圣德芬" },
        CharInfo { id: 0xBAD16E3B, name: "Tweyen", note: "索恩" },
        CharInfo { id: 0x296471BE, name: "Seofon", note: "希耶提" },
        CharInfo { id: 0x74DD4C79, name: "Fediel", note: "菲迪埃尔" },
        CharInfo { id: 0x1BB37EF0, name: "Gallanza", note: "伽兰查" },
        CharInfo { id: 0x25D46F4B, name: "Maglielle", note: "玛奇拉菲拉" },
        CharInfo { id: 0x9A8AF295, name: "Beatrix", note: "贝阿朵丽丝" },
        CharInfo { id: 0x9B15CFB1, name: "Eustace", note: "尤斯提斯" },
        CharInfo { id: 0x646C3168, name: "Fraux", note: "芙劳" },
        CharInfo { id: 0x28A87C8A, name: "罗兰", note: "★全功能可用" },
        CharInfo { id: 0x3529CC90, name: "露莉亚", note: "★战斗可用,菜单闪退" },
        CharInfo { id: 0xF92C7821, name: "龙人伊德", note: "非战斗角色" },
        CharInfo { id: 0x887AE0B0, name: "(空)", note: "空槽位" },
    ]
}

pub fn char_name(id: u32) -> &'static str {
    all_chars()
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.name)
        .unwrap_or("未知")
}
