//! FH4 (FuncInfo4) DUMPBIN parser.
//!
//! Parses DUMPBIN output for FH4 exception handling structures.

use super::is_function_header;

//----------------------------------------------------------------
// FH4 structures
//----------------------------------------------------------------

/// Expected FH4 function data parsed from DUMPBIN output
#[derive(Debug, Default)]
pub struct ExpectedFh4 {
    pub begin_address: u32,
    pub end_address: u32,
    pub ip_to_state: Vec<(u32, i32)>,  // (ip_offset, state)
    pub unwind_map: Vec<(i32, u32)>,   // (next_state, action_rva) - action_rva=0 means no action
    pub try_blocks: Vec<ExpectedTryBlock>,
}

#[derive(Debug, Default)]
pub struct ExpectedTryBlock {
    pub try_low: u32,
    pub try_high: u32,
    pub catch_high: u32,
    pub handlers: Vec<ExpectedHandler>,
}

#[derive(Debug, Default)]
pub struct ExpectedHandler {
    pub adjectives: u32,
    pub type_desc_rva: u32,
    pub catch_obj_offset: u32,
    pub handler_rva: u32,
}

//----------------------------------------------------------------
// FH4 parsing
//----------------------------------------------------------------

/// Parses the DUMPBIN txt file and extracts FH4 function data
pub fn parse_fh4_functions(content: &str) -> Vec<ExpectedFh4> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    
    while i < lines.len() {
        let line = lines[i].trim();
        
        // Look for function header line: "  00000000 00001500 000015B1 00009D38  main"
        if line.starts_with("00") && line.len() > 30 {
            if let Some(func) = try_parse_fh4_function(&lines, &mut i) {
                functions.push(func);
                continue;
            }
        }
        i += 1;
    }
    
    functions
}

fn try_parse_fh4_function(lines: &[&str], i: &mut usize) -> Option<ExpectedFh4> {
    let header_line = lines[*i].trim();
    
    // Parse function header: "00000000 00001500 000015B1 00009D38  main"
    let parts: Vec<&str> = header_line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    
    let begin_address = u32::from_str_radix(parts[1], 16).ok()?;
    let end_address = u32::from_str_radix(parts[2], 16).ok()?;
    
    *i += 1;
    
    // Check if this is an FH4 function by looking for "EH Handler Data (FH4):"
    let mut is_fh4 = false;
    let mut func_end = *i;
    
    // Scan ahead to find if this is FH4 and where the function block ends
    while func_end < lines.len() {
        let line = lines[func_end].trim();
        if line.contains("EH Handler Data (FH4):") {
            is_fh4 = true;
        }
        // Next function starts with format: "  XXXXXXXX XXXXXXXX XXXXXXXX XXXXXXXX  name"
        if func_end > *i && is_function_header(line) {
            break;
        }
        // Summary section marks end
        if line == "Summary" {
            break;
        }
        func_end += 1;
    }
    
    if !is_fh4 {
        *i = func_end;
        return None;
    }
    
    let mut func = ExpectedFh4 {
        begin_address,
        end_address,
        ..Default::default()
    };
    
    // Parse the function details
    let mut in_ip_to_state_section = false;
    let mut in_unwind_map_section = false;
    
    while *i < func_end {
        let line = lines[*i].trim();
        
        // Track which section we're in
        if line.contains("IP (relative to segment") {
            in_ip_to_state_section = true;
            in_unwind_map_section = false;
            *i += 1;
            continue;
        }
        if line.starts_with("Number of States:") {
            in_ip_to_state_section = false;
        }
        if line.starts_with("Unwind Map:") {
            in_ip_to_state_section = false;
            in_unwind_map_section = true;
            *i += 1;
            continue;
        }
        if line.starts_with("Number of Try Blocks:") {
            in_unwind_map_section = false;
        }
        
        // Parse IP to State Map entries when in that section
        // Format: "      00000000         -1 |                   0         0"
        if in_ip_to_state_section && line.contains("|") && !line.contains("IP") && !line.contains("Raw Data") {
            if let Some((ip, state)) = parse_ip_state_line(line) {
                func.ip_to_state.push((ip, state));
            }
        }
        
        // Parse Unwind Map entries
        // Format: "                  0          -1 |    00000001     -00000001 | No unwind state"
        // or:     "                  1           0 |    00000002     -00000001 | Dtor RVA: 00006320"
        if in_unwind_map_section && (line.contains("No unwind state") || line.contains("Dtor RVA:")) {
            if let Some((next_state, action)) = parse_unwind_map_line(line) {
                func.unwind_map.push((next_state, action));
            }
        }
        
        // Parse Try Block Map
        if line.starts_with("Lowest Try State:") {
            if let Some(try_block) = parse_try_block(lines, i, func_end) {
                func.try_blocks.push(try_block);
                continue; // parse_try_block advances i
            }
        }
        
        *i += 1;
    }
    
    Some(func)
}

fn parse_ip_state_line(line: &str) -> Option<(u32, i32)> {
    // Format: "      00000000         -1 |                   0         0"
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 2 {
        return None;
    }
    
    let left_parts: Vec<&str> = parts[0].split_whitespace().collect();
    if left_parts.len() < 2 {
        return None;
    }
    
    let ip = u32::from_str_radix(left_parts[0], 16).ok()?;
    let state = left_parts[1].parse::<i32>().ok()?;
    
    Some((ip, state))
}

fn parse_unwind_map_line(line: &str) -> Option<(i32, u32)> {
    // Format: "                  0          -1 |    00000001     -00000001 | No unwind state"
    // or:     "                  1           0 |    00000002     -00000001 | Dtor RVA: 00006320"
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 3 {
        return None;
    }
    
    // Get next_state from first section
    let left_parts: Vec<&str> = parts[0].split_whitespace().collect();
    if left_parts.len() < 2 {
        return None;
    }
    let next_state = left_parts[1].parse::<i32>().ok()?;
    
    // Get action from last section
    let action_part = parts[2].trim();
    let action = if action_part.contains("Dtor RVA:") {
        let rva_str = action_part.split("Dtor RVA:").nth(1)?.trim();
        u32::from_str_radix(rva_str, 16).ok()?
    } else {
        0 // No unwind state
    };
    
    Some((next_state, action))
}

fn parse_try_block(lines: &[&str], i: &mut usize, func_end: usize) -> Option<ExpectedTryBlock> {
    let mut try_block = ExpectedTryBlock::default();
    
    // Parse try block header lines
    while *i < func_end {
        let line = lines[*i].trim();
        
        if line.starts_with("Lowest Try State:") {
            let val = line.split(':').nth(1)?.trim();
            try_block.try_low = val.parse().ok()?;
        } else if line.starts_with("Highest Try State:") {
            let val = line.split(':').nth(1)?.trim();
            try_block.try_high = val.parse().ok()?;
        } else if line.starts_with("Highest State of Associated Catches:") {
            let val = line.split(':').nth(1)?.trim();
            try_block.catch_high = val.parse().ok()?;
        } else if line.starts_with("Catch Handler #") {
            // Parse catch handler
            if let Some(handler) = parse_handler(lines, i, func_end) {
                try_block.handlers.push(handler);
                continue; // parse_handler advances i
            }
        } else if line.starts_with("Try Block Map #") && !try_block.handlers.is_empty() {
            // Next try block, don't advance i
            return Some(try_block);
        } else if line.starts_with("GS Unwind flags:") || line.starts_with("00") {
            // End of try block section
            return Some(try_block);
        }
        
        *i += 1;
    }
    
    if try_block.handlers.is_empty() && try_block.try_low == 0 && try_block.try_high == 0 {
        None
    } else {
        Some(try_block)
    }
}

fn parse_handler(lines: &[&str], i: &mut usize, func_end: usize) -> Option<ExpectedHandler> {
    let mut handler = ExpectedHandler::default();
    
    *i += 1; // Skip "Catch Handler #N:" line
    
    while *i < func_end {
        let line = lines[*i].trim();
        
        if line.starts_with("Handler Type Adjectives:") {
            let val = line.split(':').nth(1)?.trim();
            handler.adjectives = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("RVA to Type Descriptor:") {
            let val = line.split(':').nth(1)?.trim();
            handler.type_desc_rva = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("Frame offset of Catch Object:") {
            let val = line.split(':').nth(1)?.trim();
            handler.catch_obj_offset = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("RVA to Catch Handler:") {
            let val = line.split(':').nth(1)?.trim();
            handler.handler_rva = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("Catch Handler #") || line.starts_with("GS Unwind") 
                  || line.starts_with("Try Block Map") || line.starts_with("00") {
            // End of handler
            return Some(handler);
        }
        
        *i += 1;
    }
    
    Some(handler)
}

