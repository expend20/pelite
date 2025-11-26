//! FH3 (FuncInfo3) DUMPBIN parser.
//!
//! Parses DUMPBIN output for FH3 exception handling structures.

use super::is_function_header;

//----------------------------------------------------------------
// FH3 structures
//----------------------------------------------------------------

/// Expected FH3 function data parsed from DUMPBIN output
#[derive(Debug, Default)]
pub struct ExpectedFh3 {
    pub begin_address: u32,
    pub end_address: u32,
    pub magic_number: u32,
    pub max_state: u32,
    pub unwind_map_rva: u32,
    pub try_block_count: u32,
    pub try_block_map_rva: u32,
    pub ip_map_count: u32,
    pub ip_map_rva: u32,
    pub frame_offset: i32,
    pub es_type_list_rva: u32,
    pub eh_flags: u32,
    pub ip_to_state: Vec<(u32, i32)>,        // (ip_rva, state)
    pub unwind_map: Vec<(i32, u32)>,         // (next_state, action_rva)
    pub try_blocks: Vec<ExpectedTryBlockFh3>,
}

#[derive(Debug, Default)]
pub struct ExpectedTryBlockFh3 {
    pub try_low: u32,
    pub try_high: u32,
    pub catch_high: u32,
    pub handlers: Vec<ExpectedHandlerFh3>,
}

#[derive(Debug, Default)]
pub struct ExpectedHandlerFh3 {
    pub adjectives: u32,
    pub type_desc_rva: u32,
    pub catch_obj_offset: u32,
    pub handler_rva: u32,
    pub disp_frame: u32,  // Distance Between Handler and Parent FP
}

//----------------------------------------------------------------
// FH3 parsing
//----------------------------------------------------------------

/// Parses the DUMPBIN txt file and extracts FH3 function data
pub fn parse_fh3_functions(content: &str) -> Vec<ExpectedFh3> {
    let mut functions = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    
    while i < lines.len() {
        let line = lines[i].trim();
        
        // Look for function header line: "  00000000 00001500 000015B1 00009D38  main"
        if line.starts_with("00") && line.len() > 30 {
            if let Some(func) = try_parse_fh3_function(&lines, &mut i) {
                functions.push(func);
                continue;
            }
        }
        i += 1;
    }
    
    functions
}

fn try_parse_fh3_function(lines: &[&str], i: &mut usize) -> Option<ExpectedFh3> {
    let header_line = lines[*i].trim();
    
    // Parse function header: "00000000 00001500 000015B1 00009D38  main"
    let parts: Vec<&str> = header_line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    
    let begin_address = u32::from_str_radix(parts[1], 16).ok()?;
    let end_address = u32::from_str_radix(parts[2], 16).ok()?;
    
    *i += 1;
    
    // Check if this is an FH3 function by looking for "Magic Number:" but NOT "EH Handler Data (FH4):"
    let mut is_fh3 = false;
    let mut has_fh4 = false;
    let mut func_end = *i;
    
    // Scan ahead to find if this is FH3 and where the function block ends
    while func_end < lines.len() {
        let line = lines[func_end].trim();
        if line.contains("Magic Number:") && line.contains("19930522") {
            is_fh3 = true;
        }
        if line.contains("EH Handler Data (FH4):") {
            has_fh4 = true;
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
    
    // FH3 has magic number but NOT FH4 marker
    if !is_fh3 || has_fh4 {
        *i = func_end;
        return None;
    }
    
    let mut func = ExpectedFh3 {
        begin_address,
        end_address,
        ..Default::default()
    };
    
    // Parse the function details
    let mut in_ip_to_state_section = false;
    let mut in_unwind_map_section = false;
    
    while *i < func_end {
        let line = lines[*i].trim();
        
        // Parse header fields
        if line.starts_with("Magic Number:") {
            let val = line.split(':').nth(1)?.trim();
            // DUMPBIN shows magic as hex without 0x prefix (e.g., "19930522" means 0x19930522)
            func.magic_number = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("BBT Flags:") {
            // Skip BBT Flags - not actually present in the binary structure
        } else if line.starts_with("Max State:") {
            let val = line.split(':').nth(1)?.trim();
            func.max_state = val.parse().ok()?;
        } else if line.starts_with("RVA to Unwind Map:") {
            let val = line.split(':').nth(1)?.trim();
            func.unwind_map_rva = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("Number of Try Blocks:") {
            let val = line.split(':').nth(1)?.trim();
            func.try_block_count = u32::from_str_radix(val, 16).ok()?;
            in_unwind_map_section = false;
        } else if line.starts_with("RVA to Try Block Map:") {
            let val = line.split(':').nth(1)?.trim();
            func.try_block_map_rva = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("Number of IP Map Entries:") {
            let val = line.split(':').nth(1)?.trim();
            func.ip_map_count = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("RVA to IP to State Map:") {
            let val = line.split(':').nth(1)?.trim();
            func.ip_map_rva = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("Frame Offset of Unwind Helper:") {
            let val = line.split(':').nth(1)?.trim();
            // Frame offset is shown as hex, parse as u32 then convert to i32
            func.frame_offset = u32::from_str_radix(val, 16).ok()? as i32;
        } else if line.starts_with("RVA to ES Type List:") {
            let val = line.split(':').nth(1)?.trim();
            func.es_type_list_rva = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("EH Flags:") {
            let val = line.split(':').nth(1)?.trim();
            func.eh_flags = u32::from_str_radix(val, 16).ok()?;
        }
        
        // Track which section we're in
        if line.starts_with("IP to State Map:") {
            in_ip_to_state_section = true;
            in_unwind_map_section = false;
            *i += 1;
            // Skip the header line "      IP      State"
            if *i < func_end && lines[*i].trim().contains("IP") && lines[*i].trim().contains("State") {
                *i += 1;
            }
            continue;
        }
        if line.starts_with("Unwind Map:") {
            in_ip_to_state_section = false;
            in_unwind_map_section = true;
            *i += 1;
            // Skip the header line "Current State  Next State  RVA to Action"
            if *i < func_end && lines[*i].trim().contains("Current State") {
                *i += 1;
            }
            continue;
        }
        if line.starts_with("Try Block Map") {
            in_ip_to_state_section = false;
            in_unwind_map_section = false;
        }
        
        // Parse IP to State Map entries
        // Format: "      00001177         -1"
        if in_ip_to_state_section && !line.is_empty() && !line.starts_with("Unwind") {
            if let Some((ip, state)) = parse_fh3_ip_state_line(line) {
                func.ip_to_state.push((ip, state));
            }
        }
        
        // Parse Unwind Map entries
        // Format: "                  0          -1       00000000"
        if in_unwind_map_section && !line.is_empty() && !line.starts_with("Try") && !line.starts_with("Number") {
            if let Some((next_state, action)) = parse_fh3_unwind_map_line(line) {
                func.unwind_map.push((next_state, action));
            }
        }
        
        // Parse Try Block Map
        if line.starts_with("Lowest Try State:") {
            if let Some(try_block) = parse_fh3_try_block(lines, i, func_end) {
                func.try_blocks.push(try_block);
                continue; // parse_fh3_try_block advances i
            }
        }
        
        *i += 1;
    }
    
    Some(func)
}

fn parse_fh3_ip_state_line(line: &str) -> Option<(u32, i32)> {
    // Format: "      00001177         -1"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    
    let ip = u32::from_str_radix(parts[0], 16).ok()?;
    let state = parts[1].parse::<i32>().ok()?;
    
    Some((ip, state))
}

fn parse_fh3_unwind_map_line(line: &str) -> Option<(i32, u32)> {
    // Format: "                  0          -1       00000000"
    // Fields: Current State, Next State, RVA to Action
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    
    let next_state = parts[1].parse::<i32>().ok()?;
    let action = u32::from_str_radix(parts[2], 16).ok()?;
    
    Some((next_state, action))
}

fn parse_fh3_try_block(lines: &[&str], i: &mut usize, func_end: usize) -> Option<ExpectedTryBlockFh3> {
    let mut try_block = ExpectedTryBlockFh3::default();
    
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
            if let Some(handler) = parse_fh3_handler(lines, i, func_end) {
                try_block.handlers.push(handler);
                continue; // parse_fh3_handler advances i
            }
        } else if line.starts_with("Try Block Map #") && !try_block.handlers.is_empty() {
            // Next try block, don't advance i
            return Some(try_block);
        } else if line.starts_with("GS Unwind flags:") || (line.starts_with("00") && line.len() > 30) {
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

fn parse_fh3_handler(lines: &[&str], i: &mut usize, func_end: usize) -> Option<ExpectedHandlerFh3> {
    let mut handler = ExpectedHandlerFh3::default();
    
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
        } else if line.starts_with("Distance Between Handler and Parent FP:") {
            let val = line.split(':').nth(1)?.trim();
            handler.disp_frame = u32::from_str_radix(val, 16).ok()?;
        } else if line.starts_with("Catch Handler #") || line.starts_with("GS Unwind") 
                  || line.starts_with("Try Block Map") || (line.starts_with("00") && line.len() > 30) {
            // End of handler
            return Some(handler);
        }
        
        *i += 1;
    }
    
    Some(handler)
}

