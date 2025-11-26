//! C Structured Exception Handling (CSEH) DUMPBIN parser.
//!
//! Parses DUMPBIN output for `__C_specific_handler` exception handling structures.
//! These are used for SEH __try/__except/__finally blocks in C code.

use super::is_function_header;

//----------------------------------------------------------------
// CSEH structures
//----------------------------------------------------------------

/// Expected CSEH function data parsed from DUMPBIN output
#[derive(Debug, Default)]
pub struct ExpectedCseh {
    pub begin_address: u32,
    pub end_address: u32,
    pub scope_table: Vec<ExpectedScopeEntry>,
}

/// A single scope table entry for C SEH
#[derive(Debug, Default, Clone)]
pub struct ExpectedScopeEntry {
    /// Start of the __try block (RVA)
    pub begin_address: u32,
    /// End of the __try block (RVA)
    pub end_address: u32,
    /// Filter or __finally function (RVA)
    pub handler_address: u32,
    /// Jump target after handler (RVA, 0 for __finally handlers)
    pub jump_target: u32,
}

//----------------------------------------------------------------
// CSEH parsing
//----------------------------------------------------------------

/// Parses the DUMPBIN txt file and extracts CSEH function data
pub fn parse_cseh_functions(content: &str) -> Vec<ExpectedCseh> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    
    while i < lines.len() {
        let line = lines[i].trim();
        
        // Look for function header line: "  00000000 00001500 000015B1 00009D38  name"
        if line.starts_with("00") && line.len() > 30 {
            if let Some(func) = try_parse_cseh_function(&lines, &mut i) {
                functions.push(func);
                continue;
            }
        }
        i += 1;
    }
    
    functions
}

fn try_parse_cseh_function(lines: &[&str], i: &mut usize) -> Option<ExpectedCseh> {
    let header_line = lines[*i].trim();
    
    // Parse function header: "00000000 00001500 000015B1 00009D38  name"
    let parts: Vec<&str> = header_line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    
    let begin_address = u32::from_str_radix(parts[1], 16).ok()?;
    let end_address = u32::from_str_radix(parts[2], 16).ok()?;
    
    *i += 1;
    
    // Check if this is a __C_specific_handler function
    let mut is_cseh = false;
    let mut func_end = *i;
    
    // Scan ahead to find if this is CSEH and where the function block ends
    // Function headers have a 5th part (function name or more hex), scope table entries have exactly 4
    while func_end < lines.len() {
        let line = lines[func_end].trim();
        if line.contains("__C_specific_handler") {
            is_cseh = true;
        }
        // Next function starts with format: "  XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX  name"
        // A true function header has more than 4 parts (includes unwind RVA and usually function name)
        // or starts at column 2 (2-space indent), while scope entries are at column 6
        if func_end > *i && is_true_function_header(lines[func_end]) {
            break;
        }
        // Summary section marks end
        if line == "Summary" {
            break;
        }
        func_end += 1;
    }
    
    if !is_cseh {
        *i = func_end;
        return None;
    }
    
    let mut func = ExpectedCseh {
        begin_address,
        end_address,
        ..Default::default()
    };
    
    // Parse the function details
    let mut in_scope_table_section = false;
    let mut skip_header = false;
    
    while *i < func_end {
        let line = lines[*i].trim();
        
        // Track when we enter the scope table section
        if line.starts_with("Count of scope table entries:") {
            in_scope_table_section = true;
            skip_header = true;  // Need to skip "Begin    End      Handler  Target" header
            *i += 1;
            continue;
        }
        
        // Skip the header line
        if skip_header && line.contains("Begin") && line.contains("End") && line.contains("Handler") {
            skip_header = false;
            *i += 1;
            continue;
        }
        
        // Parse scope table entries
        // Format: "      0000224D 00002278 000064AE 00000000"
        if in_scope_table_section && !line.is_empty() {
            if let Some(entry) = parse_scope_entry_line(line) {
                func.scope_table.push(entry);
            }
            // Don't break on parse failure - there might be empty lines or other content
        }
        
        *i += 1;
    }
    
    // Only return if we found scope table entries
    if func.scope_table.is_empty() {
        None
    } else {
        Some(func)
    }
}

/// Check if a line is a true function header (not a scope table entry)
/// Function headers: "  XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX  name" (2-space indent, 5+ parts)
/// Scope entries: "      XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX" (6-space indent, exactly 4 parts)
fn is_true_function_header(line: &str) -> bool {
    // Check indentation: function headers have 2-space indent, scope entries have 6
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();
    
    // Function headers typically have 2 spaces indent
    // Scope table entries have 6 spaces indent
    if indent > 4 {
        return false;
    }
    
    // Also verify it looks like a header (4+ 8-digit hex values)
    is_function_header(trimmed)
}

fn parse_scope_entry_line(line: &str) -> Option<ExpectedScopeEntry> {
    // Format: "      0000224D 00002278 000064AE 00000000"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    
    // All parts should be valid hex numbers
    let begin_address = u32::from_str_radix(parts[0], 16).ok()?;
    let end_address = u32::from_str_radix(parts[1], 16).ok()?;
    let handler_address = u32::from_str_radix(parts[2], 16).ok()?;
    let jump_target = u32::from_str_radix(parts[3], 16).ok()?;
    
    Some(ExpectedScopeEntry {
        begin_address,
        end_address,
        handler_address,
        jump_target,
    })
}

