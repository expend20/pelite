/*!
Tests for file offset functionality in exception data structures.

These tests verify that the file offsets provided by the new location APIs
correctly correspond to the actual data in the PE file. The tests read
data directly from file offsets and compare against the parsed values
to ensure consistency.
*/

use pelite::pe64::{Pe, PeFile};
use pelite::pe64::exception::HandlerType;
use pelite::pe64::exception_fh3::UnwindInfoFh3Ext;
use pelite::pe64::exception_fh4::{UnwindInfoFh4Ext, UVarIntReader, encode_uvarint, uvarint_encoded_size};
use pelite::pe64::exception_cseh::UnwindInfoCsehExt;
use pelite::pe64::exception_patch;
use pelite::FileMap;
use std::fs;
use std::path::Path;

const TEST_DIR: &str = "tests/exceptions";

/// Helper to read a u32 from bytes at an offset
fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}

/// Helper to read an i32 from bytes at an offset
fn read_i32_at(bytes: &[u8], offset: usize) -> i32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    i32::from_le_bytes(buf)
}

/// Discovers test exe files
fn discover_test_files() -> Vec<(std::path::PathBuf, String)> {
    let test_dir = Path::new(TEST_DIR);
    let mut files = Vec::new();
    
    if let Ok(entries) = fs::read_dir(test_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "exe") {
                let base = path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                files.push((path, base));
            }
        }
    }
    
    files.sort_by(|a, b| a.1.cmp(&b.1));
    files
}

//----------------------------------------------------------------
// RUNTIME_FUNCTION file offset tests
//----------------------------------------------------------------

#[test]
fn test_runtime_function_file_offsets() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        println!("Testing RUNTIME_FUNCTION file offsets for: {}", base_name);
        
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        let raw_bytes = file_map.as_ref();
        let file = PeFile::from_bytes(&file_map)
            .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
        
        let exception = match file.exception() {
            Ok(e) => e,
            Err(_) => continue, // Skip files without exception directory
        };
        
        let mut verified = 0;
        for func in exception.functions() {
            let image = func.image();
            
            // Get the file offset
            let func_offset = match func.file_offset() {
                Ok(o) => o,
                Err(_) => continue,
            };
            
            // Verify by reading directly from the file
            let begin_from_file = read_u32_at(raw_bytes, func_offset);
            let end_from_file = read_u32_at(raw_bytes, func_offset + 4);
            let unwind_from_file = read_u32_at(raw_bytes, func_offset + 8);
            
            assert_eq!(
                begin_from_file, image.BeginAddress,
                "[{}] BeginAddress mismatch at offset 0x{:X}",
                base_name, func_offset
            );
            assert_eq!(
                end_from_file, image.EndAddress,
                "[{}] EndAddress mismatch at offset 0x{:X}",
                base_name, func_offset
            );
            assert_eq!(
                unwind_from_file, image.UnwindData,
                "[{}] UnwindData mismatch at offset 0x{:X}",
                base_name, func_offset
            );
            
            verified += 1;
        }
        
        println!("  Verified {} RUNTIME_FUNCTION file offsets", verified);
    }
}

#[test]
fn test_unwind_info_file_offsets() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        println!("Testing UnwindInfo file offsets for: {}", base_name);
        
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        let raw_bytes = file_map.as_ref();
        let file = PeFile::from_bytes(&file_map)
            .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
        
        let exception = match file.exception() {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let mut verified = 0;
        for func in exception.functions() {
            let unwind_info = match func.unwind_info() {
                Ok(u) => u,
                Err(_) => continue,
            };
            
            let unwind_offset = match unwind_info.file_offset() {
                Ok(o) => o,
                Err(_) => continue,
            };
            
            // The first byte of UNWIND_INFO contains Version (3 bits) and Flags (5 bits)
            let version_flags_from_file = raw_bytes[unwind_offset];
            let image = unwind_info.image();
            
            assert_eq!(
                version_flags_from_file, image.VersionFlags,
                "[{}] VersionFlags mismatch at offset 0x{:X}",
                base_name, unwind_offset
            );
            
            // Verify SizeOfProlog at offset 1
            let prolog_from_file = raw_bytes[unwind_offset + 1];
            assert_eq!(
                prolog_from_file, image.SizeOfProlog,
                "[{}] SizeOfProlog mismatch at offset 0x{:X}",
                base_name, unwind_offset
            );
            
            verified += 1;
        }
        
        println!("  Verified {} UnwindInfo file offsets", verified);
    }
}

//----------------------------------------------------------------
// FH3 file offset tests
//----------------------------------------------------------------

#[test]
fn test_fh3_file_offsets() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        let raw_bytes = file_map.as_ref();
        let file = PeFile::from_bytes(&file_map)
            .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
        
        let exception = match file.exception() {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let mut fh3_verified = 0;
        
        for func in exception.functions() {
            let image = func.image();
            let unwind_info = match func.unwind_info() {
                Ok(u) => u,
                Err(_) => continue,
            };
            
            // Check if this is an FH3 function
            if unwind_info.handler_type(image.BeginAddress, image.EndAddress) != HandlerType::Fh3 {
                continue;
            }
            
            let fh3 = match unwind_info.func_info3() {
                Ok(f) => f,
                Err(_) => continue,
            };
            
            // Verify FuncInfo3 header file offset
            let func_info_offset = fh3.func_info_file_offset;
            let magic_from_file = read_u32_at(raw_bytes, func_info_offset);
            assert_eq!(
                magic_from_file, fh3.magic_number,
                "[{}] FH3 magic number mismatch at offset 0x{:X}",
                base_name, func_info_offset
            );
            
            // Verify IP-to-state map entries
            for entry in &fh3.ip_to_state_map {
                let ip_from_file = read_u32_at(raw_bytes, entry.ip_rva_file_offset);
                let state_from_file = read_i32_at(raw_bytes, entry.state_file_offset);
                
                assert_eq!(
                    ip_from_file, entry.ip_rva,
                    "[{}] FH3 IP RVA mismatch at offset 0x{:X}",
                    base_name, entry.ip_rva_file_offset
                );
                assert_eq!(
                    state_from_file, entry.state,
                    "[{}] FH3 State mismatch at offset 0x{:X}",
                    base_name, entry.state_file_offset
                );
            }
            
            // Verify unwind map entries
            for entry in &fh3.unwind_map {
                let next_from_file = read_i32_at(raw_bytes, entry.next_state_file_offset);
                let action_from_file = read_u32_at(raw_bytes, entry.action_rva_file_offset);
                
                assert_eq!(
                    next_from_file, entry.next_state,
                    "[{}] FH3 Next state mismatch at offset 0x{:X}",
                    base_name, entry.next_state_file_offset
                );
                assert_eq!(
                    action_from_file, entry.action_rva,
                    "[{}] FH3 Action RVA mismatch at offset 0x{:X}",
                    base_name, entry.action_rva_file_offset
                );
            }
            
            // Verify try block entries
            for try_entry in &fh3.try_block_map {
                let handlers_rva_from_file = read_u32_at(raw_bytes, try_entry.handlers_rva_file_offset);
                
                assert_eq!(
                    handlers_rva_from_file, try_entry.handlers_rva,
                    "[{}] FH3 Handlers RVA mismatch at offset 0x{:X}",
                    base_name, try_entry.handlers_rva_file_offset
                );
                
                // Verify handler entries
                for handler in &try_entry.handlers {
                    let handler_rva_from_file = read_u32_at(raw_bytes, handler.handler_rva_file_offset);
                    
                    assert_eq!(
                        handler_rva_from_file, handler.handler_rva,
                        "[{}] FH3 Handler RVA mismatch at offset 0x{:X}",
                        base_name, handler.handler_rva_file_offset
                    );
                }
            }
            
            fh3_verified += 1;
        }
        
        if fh3_verified > 0 {
            println!("[{}] Verified {} FH3 functions with file offsets", base_name, fh3_verified);
        }
    }
}

//----------------------------------------------------------------
// CSEH file offset tests
//----------------------------------------------------------------

#[test]
fn test_cseh_file_offsets() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        let raw_bytes = file_map.as_ref();
        let file = PeFile::from_bytes(&file_map)
            .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
        
        let exception = match file.exception() {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let mut cseh_verified = 0;
        
        for func in exception.functions() {
            let image = func.image();
            let unwind_info = match func.unwind_info() {
                Ok(u) => u,
                Err(_) => continue,
            };
            
            // Check if this is a CSEH function
            if unwind_info.handler_type(image.BeginAddress, image.EndAddress) != HandlerType::Cseh {
                continue;
            }
            
            let cseh = match unwind_info.c_scope_table() {
                Ok(c) => c,
                Err(_) => continue,
            };
            
            // Verify count from file
            let count_from_file = read_u32_at(raw_bytes, cseh.count_file_offset);
            assert_eq!(
                count_from_file, cseh.count,
                "[{}] CSEH count mismatch at offset 0x{:X}",
                base_name, cseh.count_file_offset
            );
            
            // Verify each scope entry
            for entry in &cseh.entries {
                let begin_from_file = read_u32_at(raw_bytes, entry.begin_address_file_offset);
                let end_from_file = read_u32_at(raw_bytes, entry.end_address_file_offset);
                let handler_from_file = read_u32_at(raw_bytes, entry.handler_address_file_offset);
                let jump_from_file = read_u32_at(raw_bytes, entry.jump_target_file_offset);
                
                assert_eq!(
                    begin_from_file, entry.begin_address,
                    "[{}] CSEH begin_address mismatch at offset 0x{:X}",
                    base_name, entry.begin_address_file_offset
                );
                assert_eq!(
                    end_from_file, entry.end_address,
                    "[{}] CSEH end_address mismatch at offset 0x{:X}",
                    base_name, entry.end_address_file_offset
                );
                assert_eq!(
                    handler_from_file, entry.handler_address,
                    "[{}] CSEH handler_address mismatch at offset 0x{:X}",
                    base_name, entry.handler_address_file_offset
                );
                assert_eq!(
                    jump_from_file, entry.jump_target,
                    "[{}] CSEH jump_target mismatch at offset 0x{:X}",
                    base_name, entry.jump_target_file_offset
                );
            }
            
            cseh_verified += 1;
        }
        
        if cseh_verified > 0 {
            println!("[{}] Verified {} CSEH functions with file offsets", base_name, cseh_verified);
        }
    }
}

//----------------------------------------------------------------
// FH4 file offset tests
//----------------------------------------------------------------

#[test]
fn test_fh4_file_offsets() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        let raw_bytes = file_map.as_ref();
        let file = PeFile::from_bytes(&file_map)
            .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
        
        let exception = match file.exception() {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let mut fh4_verified = 0;
        
        for func in exception.functions() {
            let image = func.image();
            let unwind_info = match func.unwind_info() {
                Ok(u) => u,
                Err(_) => continue,
            };
            
            // Check if this is an FH4 function
            if unwind_info.handler_type(image.BeginAddress, image.EndAddress) != HandlerType::Fh4 {
                continue;
            }
            
            let fh4 = match unwind_info.func_info4() {
                Ok(f) => f,
                Err(_) => continue,
            };
            
            // Verify header byte
            let header_from_file = raw_bytes[fh4.func_info_file_offset];
            assert_eq!(
                header_from_file, fh4.header,
                "[{}] FH4 header mismatch at offset 0x{:X}",
                base_name, fh4.func_info_file_offset
            );
            
            // Verify try block handler RVAs (these are fixed 4-byte values)
            for try_entry in &fh4.try_block_map {
                let handlers_rva_from_file = read_u32_at(raw_bytes, try_entry.handlers_rva_file_offset);
                assert_eq!(
                    handlers_rva_from_file, try_entry.handlers_rva,
                    "[{}] FH4 handlers_rva mismatch at offset 0x{:X}",
                    base_name, try_entry.handlers_rva_file_offset
                );
                
                // Verify individual handler RVAs
                for handler in &try_entry.handlers {
                    let handler_rva_from_file = read_u32_at(raw_bytes, handler.handler_rva_file_offset);
                    assert_eq!(
                        handler_rva_from_file, handler.handler_rva,
                        "[{}] FH4 handler_rva mismatch at offset 0x{:X}",
                        base_name, handler.handler_rva_file_offset
                    );
                }
            }
            
            // Verify unwind map action RVAs (when type == 3)
            for unwind_entry in &fh4.unwind_map {
                if unwind_entry.type_ == 3 {
                    if let Some(action_offset) = unwind_entry.action_rva_file_offset {
                        let action_from_file = read_u32_at(raw_bytes, action_offset);
                        assert_eq!(
                            action_from_file, unwind_entry.action_rva,
                            "[{}] FH4 action_rva mismatch at offset 0x{:X}",
                            base_name, action_offset
                        );
                    }
                }
            }
            
            fh4_verified += 1;
        }
        
        if fh4_verified > 0 {
            println!("[{}] Verified {} FH4 functions with file offsets", base_name, fh4_verified);
        }
    }
}

//----------------------------------------------------------------
// Patch helpers tests
//----------------------------------------------------------------

#[test]
fn test_patch_and_verify() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        
        // Make a mutable copy
        let mut bytes = file_map.as_ref().to_vec();
        
        // First pass: extract the info we need
        let patch_info = {
            let file = PeFile::from_bytes(&bytes)
                .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
            
            let exception = match file.exception() {
                Ok(e) => e,
                Err(_) => continue,
            };
            
            // Get info from first function
            let mut info = None;
            for func in exception.functions().take(1) {
                if let Ok(func_offset) = func.file_offset() {
                    let image = func.image();
                    info = Some((func_offset, image.BeginAddress, image.EndAddress));
                    break;
                }
            }
            info
        };
        
        let (func_offset, original_begin, original_end) = match patch_info {
            Some(info) => info,
            None => continue,
        };
        
        // Test patch_runtime_function
        let new_begin = original_begin + 0x1000;
        let new_end = original_end + 0x1000;
        
        exception_patch::patch_runtime_function(
            &mut bytes, 
            func_offset, 
            new_begin, 
            new_end, 
            None
        ).expect("Patch should succeed");
        
        // Verify the patch
        let patched_begin = read_u32_at(&bytes, func_offset);
        let patched_end = read_u32_at(&bytes, func_offset + 4);
        
        assert_eq!(patched_begin, new_begin, "[{}] Patched begin address mismatch", base_name);
        assert_eq!(patched_end, new_end, "[{}] Patched end address mismatch", base_name);
        
        // Test relocate_rva
        exception_patch::relocate_rva(
            &mut bytes,
            func_offset,
            new_begin, // old base
            original_begin // new base (restore)
        ).expect("Relocate should succeed");
        
        let restored_begin = read_u32_at(&bytes, func_offset);
        assert_eq!(restored_begin, original_begin, "[{}] Restored begin address mismatch", base_name);
        
        println!("[{}] Patch helpers verified successfully", base_name);
    }
}

//----------------------------------------------------------------
// RVA to file offset tests
//----------------------------------------------------------------

#[test]
fn test_try_rva_to_file_offset() {
    let test_files = discover_test_files();
    if test_files.is_empty() {
        println!("No test files found, skipping test");
        return;
    }
    
    for (exe_path, base_name) in &test_files {
        let file_map = FileMap::open(exe_path)
            .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", exe_path.display(), e));
        let file = PeFile::from_bytes(&file_map)
            .unwrap_or_else(|e| panic!("Failed to parse PE {}: {:?}", exe_path.display(), e));
        
        // Test that try_rva_to_file_offset returns same as rva_to_file_offset.ok()
        let exception = match file.exception() {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        for func in exception.functions().take(5) {
            let rva = func.image().BeginAddress;
            
            let try_result = file.try_rva_to_file_offset(rva);
            let result_ok = file.rva_to_file_offset(rva).ok();
            
            assert_eq!(
                try_result, result_ok,
                "[{}] try_rva_to_file_offset differs from rva_to_file_offset.ok() for RVA 0x{:X}",
                base_name, rva
            );
        }
        
        // Test invalid RVA returns None
        let invalid_rva = 0xFFFFFFFF;
        assert!(
            file.try_rva_to_file_offset(invalid_rva).is_none(),
            "[{}] Invalid RVA should return None",
            base_name
        );
        
        println!("[{}] try_rva_to_file_offset verified", base_name);
    }
}

//----------------------------------------------------------------
// UVarInt encoder tests
//----------------------------------------------------------------

#[test]
fn test_uvarint_encoder() {
    // Test values that should encode to different sizes
    // 1 byte: 7 bits (max 0x7F = 127)
    // 2 bytes: 14 bits (max 0x3FFF = 16383)
    // 3 bytes: 20 bits (max 0xFFFFF = 1048575)
    // 4 bytes: 27 bits (max 0x7FFFFFF = 134217727)
    let test_values: Vec<u32> = vec![
        0, 1, 63, 64, 127,  // 1 byte range (< 0x80)
        128, 255, 1000, 16383,  // 2 byte range (< 0x4000)
        16384, 100000, 1048575,  // 3 byte range (< 0x100000)
        1048576, 10000000, 134217727,  // 4 byte range
    ];
    
    for &value in &test_values {
        let encoded = encode_uvarint(value);
        let expected_size = uvarint_encoded_size(value);
        
        assert_eq!(
            encoded.len(), expected_size,
            "Encoded size mismatch for value {}. Got {} expected {}",
            value, encoded.len(), expected_size
        );
        
        // Verify by decoding
        let mut reader = UVarIntReader::new(&encoded);
        let decoded = reader.read_u32().expect("Decode should succeed");
        
        assert_eq!(
            decoded, value,
            "Round-trip failed for value {}. Decoded as {}",
            value, decoded
        );
    }
    
    println!("UVarInt encoder verified with {} test values", test_values.len());
}

