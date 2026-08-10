# GBFR Magic

Granblue Fantasy: Relink memory modding tool (Rust + Tauri 2)

**Languages:** [English](README.md) · [中文](README_ZH.md) · [日本語](README_JA.md)

## Features

### Party Editor
- Modify all 5 party slots' character IDs directly (`exe+0x701C420`, 0x10 per slot)

### Lyria Switch
- One-click switch Lyria / restore to Katalina (legal character)
- Lyria works in battle / returning / town, but **opening menu crashes** (enemy model data)
- Flow: switch to Lyria → battle → restore Katalina before menu/save (prevents save corruption)

### Character Mod (Roland sigil method)
- Show any character (e.g. Roland) in the sigil screen to open equipment/sigil window
- Principle: locate "current selected character ID" pointer, change to target character ID
- Steps: select char A in sigil screen -> scan -> switch to char B -> filter -> back to A -> filter -> write target

### Battle Cheats
- **No CD**: skills have no cooldown
- **Infinite HP**: damage taken zero, your attacks normal
- Toggle anytime, restores original bytes when off

### Character Reference
- All character IDs (hex + decimal)

### Connection Control
- Manual "Connect / Disconnect" buttons (no auto-connect)
- Validates game process and party pointer on connect

### i18n
- Chinese / Japanese / English UI, switchable in header, persisted

## Special Character Status

| Character | Party | Battle | Menu | Sigil |
|---|---|---|---|---|
| Roland | ✅ | ✅ | ✅ | ✅ Full |
| Lyria | ✅ | ✅ | ❌ crash | ❌ |
| Dragon Id | ✅ | ❌ non-combat | - | ❌ |

## Build

```bash
cd src-tauri
cargo build --release
# Output: target/release/gbfr_tool.exe
```

## Usage

1. Start the game
2. Run `gbfr_tool.exe`
3. Click **Connect**
4. Use the tabs

## Technical

- Rust + Tauri 2 (windows-sys FFI)
- Party pointer: `exe+0x701C420` (5 slots x 0x10)
- Battle cheats via runtime patch (fixed RVA, re-apply after restart)
- Character mod via memory scan + filter to locate selected char pointer (re-locate each restart)
