// GBFR SDK DLL 注入器
// 用法: gbfr_sdk_inject.exe <pid> [dll路径]
// 标准注入: VirtualAllocEx + WriteProcessMemory(路径) + CreateRemoteThread(LoadLibraryW)
use std::env;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, CreateRemoteThread, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

const INJECT_ACCESS: u32 = PROCESS_CREATE_THREAD
    | PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: gbfr_sdk_inject.exe <pid> [dll_path]");
        return;
    }
    let pid: u32 = args[1].parse().expect("pid");
    let dll = if args.len() >= 3 {
        args[2].clone()
    } else {
        // 默认: 本 exe 同目录的 gbfr_sdk_dll.dll
        let exe = env::current_exe().unwrap();
        let dir = exe.parent().unwrap();
        dir.join("gbfr_sdk_dll.dll").to_string_lossy().to_string()
    };

    unsafe {
        // Request only the rights required by VirtualAllocEx/WriteProcessMemory/CRT.
        // PROCESS_ALL_ACCESS is rejected by some target security descriptors even when
        // the narrower injection rights are granted.
        let hproc = OpenProcess(INJECT_ACCESS, 0, pid);
        if hproc.is_null() {
            println!("OpenProcess failed: {}", std::io::Error::last_os_error());
            return;
        }

        // 写 DLL 路径到目标进程
        let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
        let size = wide.len() * 2;
        let remote = VirtualAllocEx(hproc, ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote.is_null() {
            println!("VirtualAllocEx failed");
            CloseHandle(hproc);
            return;
        }
        if WriteProcessMemory(hproc, remote, wide.as_ptr() as *const c_void, size, ptr::null_mut()) == 0 {
            println!("WriteProcessMemory failed: {}", std::io::Error::last_os_error());
            VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
            CloseHandle(hproc);
            return;
        }

        // 目标进程内 LoadLibraryW
        let kernel32 = GetModuleHandleW(windows_sys::core::w!("kernel32.dll"));
        let loadlib = GetProcAddress(kernel32, windows_sys::core::s!("LoadLibraryW"))
            .expect("LoadLibraryW");
        let thread = CreateRemoteThread(
            hproc,
            ptr::null(),
            0,
            Some(std::mem::transmute(loadlib)),
            remote as *const c_void,
            0,
            ptr::null_mut(),
        );
        if thread.is_null() {
            println!("CreateRemoteThread failed: {}", std::io::Error::last_os_error());
            VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
            CloseHandle(hproc);
            return;
        }

        // 等待 LoadLibrary 返回
        WaitForSingleObject(thread, 5000);
        let mut code: u32 = 0;
        windows_sys::Win32::System::Threading::GetExitCodeThread(thread, &mut code);
        println!("LoadLibraryW result: 0x{:X} (非0=成功)", code);

        CloseHandle(thread);
        VirtualFreeEx(hproc, remote, 0, MEM_RELEASE);
        CloseHandle(hproc);
    }
}
