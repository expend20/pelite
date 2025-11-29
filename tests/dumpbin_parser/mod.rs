/*!
Parser for Microsoft DUMPBIN tool output.

This module parses the text output from `dumpbin /unwindinfo` to extract
exception handling metadata for use in tests. It supports:
- FH3 (FuncInfo3) exception handling structures
- FH4 (FuncInfo4) exception handling structures
- CSEH (C Structured Exception Handling) structures
- Unwind codes
*/

pub mod cseh;
pub mod fh3;
pub mod fh4;

pub use cseh::*;
pub use fh3::*;
pub use fh4::*;

//----------------------------------------------------------------
// Common utilities
//----------------------------------------------------------------

/// Check if a line looks like a function header (4 8-digit hex numbers)
pub(crate) fn is_function_header(line: &str) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    parts.len() >= 4
        && parts[0].len() == 8 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
        && parts[1].len() == 8 && parts[1].chars().all(|c| c.is_ascii_hexdigit())
        && parts[2].len() == 8 && parts[2].chars().all(|c| c.is_ascii_hexdigit())
        && parts[3].len() == 8 && parts[3].chars().all(|c| c.is_ascii_hexdigit())
}

//----------------------------------------------------------------
// Unwind code structures
//----------------------------------------------------------------

/// Expected unwind code data parsed from DUMPBIN output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedUnwindCode {
    /// Offset in prolog where this code takes effect
    pub code_offset: u8,
    /// The operation type
    pub operation: ExpectedUnwindOp,
}

/// Expected unwind operation from DUMPBIN output
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedUnwindOp {
    /// PUSH_NONVOL: Push a nonvolatile register
    PushNonVol { register: String },
    /// ALLOC_LARGE: Allocate a large area on the stack
    AllocLarge { size: u32 },
    /// ALLOC_SMALL: Allocate a small area on the stack
    AllocSmall { size: u32 },
    /// SET_FPREG: Establish frame pointer register
    SetFpReg,
    /// SAVE_NONVOL: Save a nonvolatile register on the stack
    SaveNonVol { register: String, offset: u32 },
    /// SAVE_NONVOL_FAR: Save a nonvolatile register (large offset)
    SaveNonVolFar { register: String, offset: u32 },
    /// SAVE_XMM128: Save an XMM register
    SaveXmm128 { register: String, offset: u32 },
    /// SAVE_XMM128_FAR: Save an XMM register (large offset)
    SaveXmm128Far { register: String, offset: u32 },
    /// PUSH_MACHFRAME: Push a machine frame
    PushMachFrame { error_code: bool },
    /// Unknown operation
    Unknown { raw: String },
}

/// Expected unwind info for a function
#[derive(Debug, Default, Clone)]
pub struct ExpectedUnwindInfo {
    pub begin_address: u32,
    pub end_address: u32,
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub unwind_codes: Vec<ExpectedUnwindCode>,
}

/// Parse unwind info for all functions from DUMPBIN output
pub fn parse_unwind_info(content: &str) -> Vec<ExpectedUnwindInfo> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    
    while i < lines.len() {
        let line = lines[i].trim();
        
        // Look for function header line: "  00000000 00001500 000015B1 00009D38  main"
        if line.starts_with("00") && line.len() > 30 {
            if let Some(func) = try_parse_unwind_info(&lines, &mut i) {
                functions.push(func);
                continue;
            }
        }
        i += 1;
    }
    
    functions
}

fn try_parse_unwind_info(lines: &[&str], i: &mut usize) -> Option<ExpectedUnwindInfo> {
    let header_line = lines[*i].trim();
    
    // Parse function header: "00000000 00001500 000015B1 00009D38  main"
    let parts: Vec<&str> = header_line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    
    let begin_address = u32::from_str_radix(parts[1], 16).ok()?;
    let end_address = u32::from_str_radix(parts[2], 16).ok()?;
    
    *i += 1;
    
    let mut func = ExpectedUnwindInfo {
        begin_address,
        end_address,
        ..Default::default()
    };
    
    // Find end of this function's block
    let mut func_end = *i;
    while func_end < lines.len() {
        let line = lines[func_end].trim();
        if func_end > *i && is_function_header(line) {
            break;
        }
        if line == "Summary" {
            break;
        }
        func_end += 1;
    }
    
    // Parse the function details
    let mut in_unwind_codes_section = false;
    
    while *i < func_end {
        let line = lines[*i].trim();
        
        // Parse unwind info fields
        if line.starts_with("Unwind version:") {
            if let Some(val) = line.split(':').nth(1) {
                func.version = val.trim().parse().unwrap_or(0);
            }
        } else if line.starts_with("Unwind flags:") {
            // Parse flags - they can be "None" or space-separated flag names
            let flags_str = line.split(':').nth(1).map(|s| s.trim()).unwrap_or("");
            func.flags = parse_unwind_flags(flags_str);
        } else if line.starts_with("Size of prologue:") {
            if let Some(val) = line.split(':').nth(1) {
                let val = val.trim().trim_start_matches("0x");
                func.size_of_prolog = u8::from_str_radix(val, 16).unwrap_or(0);
            }
        } else if line.starts_with("Count of codes:") {
            if let Some(val) = line.split(':').nth(1) {
                func.count_of_codes = val.trim().parse().unwrap_or(0);
            }
        } else if line.starts_with("Unwind codes:") {
            in_unwind_codes_section = true;
            *i += 1;
            continue;
        } else if in_unwind_codes_section {
            // Parse unwind code lines
            // Format: "04: ALLOC_SMALL, size=0x68"
            // Format: "0B: PUSH_NONVOL, register=rdi"
            if let Some(code) = parse_unwind_code_line(line) {
                func.unwind_codes.push(code);
            } else if !line.is_empty() && !line.starts_with("Handler:") && !line.starts_with("EH Handler") {
                // If we hit a non-empty line that's not an unwind code, we've left the section
                if line.chars().next().map(|c| !c.is_ascii_hexdigit()).unwrap_or(true) {
                    in_unwind_codes_section = false;
                }
            }
        }
        
        *i += 1;
    }
    
    // Only return if we found meaningful data
    if func.count_of_codes > 0 || !func.unwind_codes.is_empty() {
        Some(func)
    } else {
        Some(func) // Return even if no codes, version/flags might be useful
    }
}

fn parse_unwind_flags(flags_str: &str) -> u8 {
    let mut flags: u8 = 0;
    for flag in flags_str.split_whitespace() {
        match flag.to_uppercase().as_str() {
            "NONE" => {}
            "EHANDLER" => flags |= 0x01,
            "UHANDLER" => flags |= 0x02,
            "CHAININFO" => flags |= 0x04,
            _ => {}
        }
    }
    flags
}

fn parse_unwind_code_line(line: &str) -> Option<ExpectedUnwindCode> {
    // Format: "04: ALLOC_SMALL, size=0x68"
    // Format: "11: ALLOC_LARGE, size=0xA8"
    // Format: "0B: PUSH_NONVOL, register=rdi"
    // Format: "09: SET_FPREG"
    
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    
    // Parse offset (first 2 hex digits before colon)
    let colon_pos = line.find(':')?;
    let offset_str = line[..colon_pos].trim();
    let code_offset = u8::from_str_radix(offset_str, 16).ok()?;
    
    let rest = line[colon_pos + 1..].trim();
    
    // Parse operation type and parameters
    let operation = if rest.starts_with("ALLOC_SMALL") {
        // Extract size from "ALLOC_SMALL, size=0x68"
        let size = extract_hex_param(rest, "size=")?;
        ExpectedUnwindOp::AllocSmall { size }
    } else if rest.starts_with("ALLOC_LARGE") {
        let size = extract_hex_param(rest, "size=")?;
        ExpectedUnwindOp::AllocLarge { size }
    } else if rest.starts_with("PUSH_NONVOL") {
        let register = extract_string_param(rest, "register=")?;
        ExpectedUnwindOp::PushNonVol { register }
    } else if rest.starts_with("SET_FPREG") {
        ExpectedUnwindOp::SetFpReg
    } else if rest.starts_with("SAVE_NONVOL_FAR") {
        let register = extract_string_param(rest, "register=")?;
        let offset = extract_hex_param(rest, "offset=")?;
        ExpectedUnwindOp::SaveNonVolFar { register, offset }
    } else if rest.starts_with("SAVE_NONVOL") {
        let register = extract_string_param(rest, "register=")?;
        let offset = extract_hex_param(rest, "offset=")?;
        ExpectedUnwindOp::SaveNonVol { register, offset }
    } else if rest.starts_with("SAVE_XMM128_FAR") {
        let register = extract_string_param(rest, "register=")?;
        let offset = extract_hex_param(rest, "offset=")?;
        ExpectedUnwindOp::SaveXmm128Far { register, offset }
    } else if rest.starts_with("SAVE_XMM128") {
        let register = extract_string_param(rest, "register=")?;
        let offset = extract_hex_param(rest, "offset=")?;
        ExpectedUnwindOp::SaveXmm128 { register, offset }
    } else if rest.starts_with("PUSH_MACHFRAME") {
        // Check if error_code parameter exists
        let error_code = rest.contains("error_code=1");
        ExpectedUnwindOp::PushMachFrame { error_code }
    } else {
        ExpectedUnwindOp::Unknown { raw: rest.to_string() }
    };
    
    Some(ExpectedUnwindCode {
        code_offset,
        operation,
    })
}

fn extract_hex_param(s: &str, prefix: &str) -> Option<u32> {
    let start = s.find(prefix)?;
    let rest = &s[start + prefix.len()..];
    let end = rest.find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
        .unwrap_or(rest.len());
    let val_str = rest[..end].trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(val_str, 16).ok()
}

fn extract_string_param(s: &str, prefix: &str) -> Option<String> {
    let start = s.find(prefix)?;
    let rest = &s[start + prefix.len()..];
    // Find end of the value (comma, space, or end of string)
    let end = rest.find(|c: char| c == ',' || c == ' ')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

