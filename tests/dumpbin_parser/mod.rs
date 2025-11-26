/*!
Parser for Microsoft DUMPBIN tool output.

This module parses the text output from `dumpbin /unwindinfo` to extract
exception handling metadata for use in tests. It supports:
- FH3 (FuncInfo3) exception handling structures
- FH4 (FuncInfo4) exception handling structures
- CSEH (C Structured Exception Handling) structures
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

