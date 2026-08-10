// 内存读写 - windows-sys
use std::io;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

pub struct Process {
    pub handle: HANDLE,
    pub pid: u32,
}

impl Process {
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn find_by_name(name: &str) -> Option<u32> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut pid = None;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let exe = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_lowercase();
                    if exe == name.to_lowercase() {
                        pid = Some(entry.th32ProcessID);
                        break;
                    }
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            pid
        }
    }

    pub fn open(pid: u32) -> io::Result<Self> {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                0,
                pid,
            );
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Process { handle, pid })
        }
    }

    pub fn module_base(&self, name: &str) -> Option<u64> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid);
            if snap == INVALID_HANDLE_VALUE {
                return None;
            }
            let mut entry: MODULEENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            let mut base = None;
            if Module32FirstW(snap, &mut entry) != 0 {
                loop {
                    let mname = String::from_utf16_lossy(&entry.szModule)
                        .trim_end_matches('\0')
                        .to_lowercase();
                    if mname == name.to_lowercase() {
                        base = Some(entry.modBaseAddr as u64);
                        break;
                    }
                    if Module32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            base
        }
    }

    pub fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        unsafe {
            let mut buf = vec![0u8; size];
            let mut n = 0usize;
            if ReadProcessMemory(self.handle, addr as *const _, buf.as_mut_ptr() as *mut _, size, &mut n) != 0 {
                buf.truncate(n);
                Some(buf)
            } else {
                None
            }
        }
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        unsafe {
            let mut n = 0usize;
            WriteProcessMemory(self.handle, addr as *mut _, data.as_ptr() as *const _, data.len(), &mut n) != 0
        }
    }

    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        self.read(addr, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&self, addr: u64) -> Option<u64> {
        self.read(addr, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn write_u32(&self, addr: u64, value: u32) -> bool {
        self.write(addr, &value.to_le_bytes())
    }

    /// 遍历全部可读内存区域, 返回 (基址, 大小, 保护属性, 类型)
    /// 封装 VirtualQueryEx, 过滤 MEM_COMMIT + 可读保护页
    /// type: MEM_PRIVATE=0x20000 (堆/动态分配), MEM_IMAGE=0x1000000 (exe/dll 映射), MEM_MAPPED=0x40000
    pub fn readable_regions(&self) -> Vec<(u64, usize, u32, u32)> {
        use windows_sys::Win32::System::Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY,
        };
        let mut regions = Vec::new();
        unsafe {
            let mut addr: usize = 0;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            while VirtualQueryEx(
                self.handle,
                addr as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                let ba = mbi.BaseAddress as usize;
                let rs = mbi.RegionSize;
                let prot = mbi.Protect & 0xFF;
                let readable = matches!(
                    prot,
                    PAGE_READWRITE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_WRITECOPY
                        | PAGE_EXECUTE_WRITECOPY
                );
                if mbi.State == 0x1000 /* MEM_COMMIT */ && readable {
                    regions.push((ba as u64, rs, prot, mbi.Type));
                }
                let next = ba + rs;
                if next <= addr {
                    break;
                }
                addr = next;
            }
        }
        regions
    }

    /// 只扫堆区域 (MEM_PRIVATE) — 动态数据 (JSON/对象) 都在堆, 跳过 exe/dll 映像省大量读取
    pub fn heap_regions(&self) -> Vec<(u64, usize)> {
        const MEM_PRIVATE: u32 = 0x20000;
        self.readable_regions()
            .into_iter()
            .filter(|(_, _, _, t)| *t == MEM_PRIVATE)
            .map(|(a, s, _, _)| (a, s))
            .collect()
    }

}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
