#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused_assignments)]

use std::{
    ffi::c_void,
    mem::{size_of, transmute},
    ptr::null_mut,
    arch::asm,
};
use clap::Parser;
use ntapi::ntpebteb::{PEB, TEB};
use windows::Win32::{
    Foundation::{BOOL, FARPROC},
    System::{
        Diagnostics::Debug::*,
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::*,
        SystemServices::*,
        Threading::*,
        WindowsProgramming::IMAGE_THUNK_DATA64,
        Kernel::NT_TIB,
    },
};
use windows::core::PCSTR;

/// Constants
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// Type Definitions
pub type Main = unsafe extern "system" fn() -> BOOL;

/// Argument parsing using Clap
#[derive(Parser)]
#[clap(name = "local_pe_injection", author = "joaojj", long_about = None)]
pub struct Args {
    #[clap(short, long, required = false, help = "Insert args")]
    pub arg: Option<String>,

    #[clap(short, long, required = true, help = "Insert EXE")]
    pub pe: String,
}

/// Structs and Implementations

#[derive(Debug, Clone, Copy)]
pub struct BASE_RELOCATION_ENTRY {
    pub data: u16,
}

impl BASE_RELOCATION_ENTRY {
    pub fn offset(&self) -> u16 {
        self.data & 0x0FFF
    }

    pub fn type_(&self) -> u16 {
        (self.data >> 12) & 0xF
    }
}

pub fn image_snap_by_ordinal(ordinal: u64) -> bool {
    ordinal & IMAGE_ORDINAL_FLAG64 != 0
}

pub fn image_ordinal(ordinal: u64) -> u64 {
    ordinal & 0xffff
}

pub unsafe fn get_peb() -> *mut PEB {
    let teb_offset = ntapi::FIELD_OFFSET!(NT_TIB, Self_) as u32;

    #[cfg(target_arch = "x86_64")]
    {
        let teb = __readgsqword(teb_offset) as *mut TEB;
        (*teb).ProcessEnvironmentBlock
    }

    #[cfg(target_arch = "x86")]
    {
        let teb = __readfsdword(teb_offset) as *mut TEB;
        (*teb).ProcessEnvironmentBlock
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn __readgsqword(offset: u32) -> u64 {
    let output: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) output,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    output
}

#[cfg(target_arch = "x86")]
unsafe fn __readfsdword(offset: u32) -> u32 {
    let output: u32;
    asm!(
        "mov {:e}, fs:[{:e}]",
        lateout(reg) output,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    output
}

/// PE Struct and Implementation
#[derive(Debug)]
pub struct PE {
    pub file_buffer: Vec<u8>,
    pub nt_header: *mut IMAGE_NT_HEADERS64,
    pub section_header: *mut IMAGE_SECTION_HEADER,
    pub entry_import_data: IMAGE_DATA_DIRECTORY,
    pub entry_basereloc_data: IMAGE_DATA_DIRECTORY,
    pub entry_tls_data: IMAGE_DATA_DIRECTORY,
    pub entry_exception: IMAGE_DATA_DIRECTORY,
    pub entry_export_data: IMAGE_DATA_DIRECTORY,
}

impl PE {
    /// Creates a new PE instance from a file buffer
    pub fn new(buffer: Vec<u8>) -> Option<Self> {
        unsafe {
            let dos_header = buffer.as_ptr() as *mut IMAGE_DOS_HEADER;
            if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
                return None;
            }

            let nt_header = (dos_header as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
            if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
                return None;
            }

            let section_header = (nt_header as usize + size_of::<IMAGE_NT_HEADERS64>()) as *mut IMAGE_SECTION_HEADER;

            Some(Self {
                file_buffer: buffer,
                nt_header,
                section_header,
                entry_import_data: (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize],
                entry_basereloc_data: (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC.0 as usize],
                entry_tls_data: (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS.0 as usize],
                entry_exception: (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION.0 as usize],
                entry_export_data: (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize],
            })
        }
    }

    /// Executes the PE locally with given parameters
    pub fn local_pe_exec(&mut self, param: String) -> Result<(), String> {
        unsafe {
            let address = VirtualAlloc(
                None,
                (*self.nt_header).OptionalHeader.SizeOfImage as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if address.is_null() {
                return Err("[!] Failed to allocate memory".to_string());
            }

            let mut tmp_section = self.section_header;

            for _ in 0..(*self.nt_header).FileHeader.NumberOfSections {
                let dst = (*tmp_section).VirtualAddress as isize;
                let src_start = (*tmp_section).PointerToRawData as usize;
                let src_end = src_start + (*tmp_section).SizeOfRawData as usize;

                if src_end <= self.file_buffer.len() {
                    let src = &self.file_buffer[src_start..src_end];
                    std::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        address.offset(dst) as _,
                        src.len(),
                    );
                } else {
                    return Err("[!] Section outside the buffer limits".to_string());
                }

                tmp_section = tmp_section.add(1);
            }

            self.resolve_import(address)?;
            self.realoc_image(address)?;
            self.resolve_memory(address)?;

            if self.entry_exception.Size != 0 {
                let func_entries = std::slice::from_raw_parts(
                    address.offset(self.entry_exception.VirtualAddress as isize) as *mut IMAGE_RUNTIME_FUNCTION_ENTRY,
                    (self.entry_exception.Size / size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>() as u32) as usize,
                );
                let status = RtlAddFunctionTable(func_entries, address as u64);

                if !status.as_bool() {
                    return Err("[!] Failed to call RtlAddFunctionTable".to_string());
                }   
            }

            if self.entry_tls_data.Size != 0 {
                let img_tls_directory = address.offset(self.entry_tls_data.VirtualAddress as isize) as *mut IMAGE_TLS_DIRECTORY64;
                let img_tls_callback = (*img_tls_directory).AddressOfCallBacks as *mut PIMAGE_TLS_CALLBACK;

                let mut i = 0;
                while let Some(callback) = *img_tls_callback.offset(i) {
                    callback(address, DLL_PROCESS_ATTACH, null_mut());
                    i += 1;
                } 
            }

            self.fixing_arguments(param);
            
            // Execute the entry point
            let entry_point = address.offset((*self.nt_header).OptionalHeader.AddressOfEntryPoint as isize);
            let func = transmute::<_, Main>(entry_point);
            func();

            Ok(())
        }
    }

    /// Handles image relocations
    fn realoc_image(&self, address: *mut c_void) -> Result<(), String> {
        unsafe {
            let mut base_relocation = address.offset(self.entry_basereloc_data.VirtualAddress as isize) as *mut IMAGE_BASE_RELOCATION;
            let offset = address as usize - (*self.nt_header).OptionalHeader.ImageBase as usize;
            
            while (*base_relocation).VirtualAddress != 0 {
                let mut base_entry = base_relocation.offset(1) as *mut BASE_RELOCATION_ENTRY;
                let block_end = (base_relocation as *mut u8).offset((*base_relocation).SizeOfBlock as isize) as *mut BASE_RELOCATION_ENTRY;
                
                while base_entry < block_end {
                    let entry = *base_entry;
                    let entry_type = entry.type_();
                    let entry_offset = entry.offset() as u32;
                    let target_address = (address as usize + (*base_relocation).VirtualAddress as usize + entry_offset as usize) as *mut c_void;
        
                    match entry_type as u32 {
                        IMAGE_REL_BASED_DIR64 => {
                            let patch_address = target_address as *mut isize;
                            *patch_address += offset as isize;
                        }
                        IMAGE_REL_BASED_HIGHLOW => {
                            let patch_address = target_address as *mut u32;
                            *patch_address = patch_address.read().wrapping_add(offset as u32);
                        }
                        IMAGE_REL_BASED_HIGH => {
                            let patch_address = target_address as *mut u16;
                            let high = (*patch_address as u32).wrapping_add((offset as u32 >> 16) & 0xFFFF);
                            *patch_address = high as u16
                        }
                        IMAGE_REL_BASED_LOW => {
                            let patch_address = target_address as *mut u16;
                            let low = (*patch_address as u32).wrapping_add(offset as u32 & 0xFFFF);
                            *patch_address = low as u16;
                        }
                        IMAGE_REL_BASED_ABSOLUTE => {}
                        _ => {
                            return Err("[!] Unknown relocation type".to_string());
                        }
                    }
        
                    base_entry = base_entry.offset(1);
                }
        
                base_relocation = base_entry as *mut IMAGE_BASE_RELOCATION;
            }    
        }

        Ok(())
    }

    /// Resolves imported functions
    fn resolve_import(&mut self, address: *mut c_void) -> Result<(), String> {
        unsafe {
            // Calculate the number of entries in the import table
            let entries = (self.entry_import_data.Size as usize / size_of::<IMAGE_IMPORT_DESCRIPTOR>()) as u32;
            let img_import_descriptor = address.offset(self.entry_import_data.VirtualAddress as isize) as *mut IMAGE_IMPORT_DESCRIPTOR;

            for i in 0..entries {
                let img_import_descriptor = img_import_descriptor.add(i as usize);
                let original_first_chunk_rva = (*img_import_descriptor).Anonymous.OriginalFirstThunk;
                let first_thunk_rva = (*img_import_descriptor).FirstThunk;

                // Break if both RVAs are zero
                if original_first_chunk_rva == 0 && first_thunk_rva == 0 {
                    break;
                }

                // Retrieve the DLL name
                let dll_name_ptr = (address as usize + (*img_import_descriptor).Name as usize) as *const i8;
                let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr).to_string_lossy();
                let h_module = LoadLibraryA(PCSTR(dll_name.as_ptr())).expect("[!] Error loading library");

                // Initialize thunk size
                let mut thunk_size = 0;

                loop {
                    let original_first_chunk = (address as usize + original_first_chunk_rva as usize + thunk_size as usize) as *mut IMAGE_THUNK_DATA64;
                    let first_thunk = (address as usize + first_thunk_rva as usize + thunk_size as usize) as *mut IMAGE_THUNK_DATA64;
                    let mut func_address: FARPROC = Default::default();
                    
                    // Break if both function pointers are zero
                    if (*original_first_chunk).u1.Function == 0 && (*first_thunk).u1.Function == 0  {
                        break;
                    }

                    // Check if the function is by ordinal or by name
                    if image_snap_by_ordinal((*original_first_chunk).u1.Ordinal) {
                        let ordinal = image_ordinal((*original_first_chunk).u1.Ordinal);
                        func_address = GetProcAddress(h_module, PCSTR(ordinal as _));
                    } else {
                        let image_import_name = (address as usize + (*original_first_chunk).u1.AddressOfData as usize) as *mut IMAGE_IMPORT_BY_NAME;
                        let name = &(*image_import_name).Name as *const i8;
                        func_address = GetProcAddress(h_module, PCSTR(name as _));
                    }

                    match func_address {
                        Some(f) => {
                            (*first_thunk).u1.Function = f as *const () as u64;
                        },
                        None => {
                            return Err("[!] The expected function was not found".to_string());
                        }
                    }

                    // Increment the thunk size
                    thunk_size += size_of::<IMAGE_THUNK_DATA64>() as isize;
                }
            }
        }

        Ok(())
    }

    /// Adjusts memory protections based on section characteristics
    fn resolve_memory(&mut self, address: *mut c_void) -> Result<(), String> {
        unsafe { 
            for _ in 0..(*self.nt_header).FileHeader.NumberOfSections {
                let mut protection = PAGE_PROTECTION_FLAGS(0);
                let image_section_characteristics = IMAGE_SECTION_CHARACTERISTICS(0);
                if (*self.section_header).SizeOfRawData == 0 || (*self.section_header).VirtualAddress == 0 {
                    self.section_header = self.section_header.add(1);
                    continue;
                } 

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_WRITE != image_section_characteristics {
                    protection = PAGE_WRITECOPY
                }

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_READ != image_section_characteristics {
                    protection = PAGE_READONLY
                }

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_WRITE != image_section_characteristics  
                    && (*self.section_header).Characteristics & IMAGE_SCN_MEM_READ != image_section_characteristics {
                    protection = PAGE_READWRITE
                }

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_EXECUTE != image_section_characteristics {
                    protection = PAGE_EXECUTE
                }

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_EXECUTE != image_section_characteristics
                    && (*self.section_header).Characteristics & IMAGE_SCN_MEM_WRITE != image_section_characteristics {
                    protection = PAGE_EXECUTE_WRITECOPY
                }

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_EXECUTE != image_section_characteristics 
                    && (*self.section_header).Characteristics & IMAGE_SCN_MEM_READ != image_section_characteristics {
                        protection = PAGE_EXECUTE_READ
                }

                if (*self.section_header).Characteristics & IMAGE_SCN_MEM_EXECUTE != image_section_characteristics 
                    && (*self.section_header).Characteristics & IMAGE_SCN_MEM_WRITE != image_section_characteristics
                    && (*self.section_header).Characteristics & IMAGE_SCN_MEM_READ != image_section_characteristics {
                        protection = PAGE_EXECUTE_READWRITE;
                }

                let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                let region = address.offset((*self.section_header).VirtualAddress as isize);
                let size = (*self.section_header).SizeOfRawData as usize;

                VirtualProtect(
                    region,
                    size, 
                    protection, 
                    &mut old_protect,
                ).expect("Error when calling VirtualProtect");

                self.section_header = self.section_header.add(1);
            }
        }

        Ok(())
    }

    /// Adjusts the command line arguments in the PEB
    fn fixing_arguments(&self, args: String) {
        let peb = unsafe { get_peb() };
        let process_parameters = unsafe { (*peb).ProcessParameters as *mut RTL_USER_PROCESS_PARAMETERS };
        unsafe { 
            std::ptr::write_bytes((*process_parameters).CommandLine.Buffer.0, 0, (*process_parameters).CommandLine.Length as usize);

            let current_exe = std::env::current_exe().unwrap();
            let path_name: Vec<u16> = format!("\"{}\" {}\0", current_exe.to_string_lossy(), args)
                .encode_utf16()
                .collect();

            std::ptr::copy_nonoverlapping(path_name.as_ptr(), (*process_parameters).CommandLine.Buffer.0, path_name.len());
            (*process_parameters).CommandLine.Length = (path_name.len() * 2) as u16;
            (*process_parameters).CommandLine.MaximumLength = (path_name.len() * 2) as u16;
        }
    }
}

