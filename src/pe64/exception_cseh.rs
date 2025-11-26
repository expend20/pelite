//! C Structured Exception Handling (CSEH) Structures
//!
//! This module provides parsing for `__C_specific_handler` exception handling
//! metadata. This handler is used for C-style SEH (`__try`/`__except`/`__finally`)
//! blocks.
//!
//! ## Structure Layout
//!
//! After the unwind codes in UNWIND_INFO, when the handler is `__C_specific_handler`:
//! - Handler RVA (4 bytes): points to `__C_specific_handler`
//! - Count (4 bytes): number of scope table entries
//! - Scope entries array (16 bytes each):
//!   - BeginAddress (4 bytes RVA): start of `__try` block
//!   - EndAddress (4 bytes RVA): end of `__try` block
//!   - HandlerAddress (4 bytes RVA): filter or `__finally` function
//!   - JumpTarget (4 bytes RVA): target after handler (0 for `__finally`)

use crate::pe64::exception::UnwindInfo;
use crate::{Error, Result};
use super::Pe;

/// C Scope Table parsed from `__C_specific_handler` exception data.
///
/// This structure contains the scope entries that define the `__try`/`__except`/`__finally`
/// blocks for a function using C structured exception handling.
#[derive(Debug, Clone)]
pub struct CScopeTable {
	/// Number of scope entries
	pub count: u32,
	/// Scope table entries
	pub entries: Vec<CScopeEntry>,
}

/// A single entry in the C Scope Table.
///
/// Each entry describes a `__try` block and its associated handler.
#[derive(Debug, Clone)]
pub struct CScopeEntry {
	/// Start address of the `__try` block (RVA)
	pub begin_address: u32,
	/// End address of the `__try` block (RVA)
	pub end_address: u32,
	/// Filter or `__finally` handler address (RVA)
	///
	/// - For `__except(filter)`: RVA of the filter expression function
	/// - For `__finally`: RVA of the finally block code
	pub handler_address: u32,
	/// Jump target after the handler (RVA)
	///
	/// - For `__except`: RVA of the `__except` block body
	/// - For `__finally`: 0 (execution continues normally after finally)
	pub jump_target: u32,
}

impl CScopeEntry {
	/// Returns true if this is a `__finally` handler (jump_target == 0).
	pub fn is_finally(&self) -> bool {
		self.jump_target == 0
	}
	
	/// Returns true if this is an `__except` handler (jump_target != 0).
	pub fn is_except(&self) -> bool {
		self.jump_target != 0
	}
}

impl CScopeTable {
	/// Parse C Scope Table from the given exception data.
	///
	/// # Arguments
	/// * `data` - The exception data bytes starting after the handler RVA
	///
	/// # Returns
	/// A parsed `CScopeTable` structure or an error.
	pub fn parse(data: &[u8]) -> Result<CScopeTable> {
		// Minimum size: 4 bytes for count
		if data.len() < 4 {
			return Err(Error::Bounds);
		}
		
		let read_u32 = |offset: usize| -> u32 {
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[offset..offset + 4]);
			u32::from_le_bytes(buf)
		};
		
		let count = read_u32(0);
		
		// Each entry is 16 bytes (4 x u32)
		let entry_size = 16;
		let required_len = 4 + (count as usize) * entry_size;
		if data.len() < required_len {
			return Err(Error::Bounds);
		}
		
		let mut entries = Vec::with_capacity(count as usize);
		for i in 0..count as usize {
			let offset = 4 + i * entry_size;
			entries.push(CScopeEntry {
				begin_address: read_u32(offset),
				end_address: read_u32(offset + 4),
				handler_address: read_u32(offset + 8),
				jump_target: read_u32(offset + 12),
			});
		}
		
		Ok(CScopeTable {
			count,
			entries,
		})
	}
}

/// Extension trait for accessing C SEH scope table from unwind info.
pub trait UnwindInfoCsehExt<'a, P: Pe<'a>> {
	/// Parse C Scope Table from this unwind info.
	///
	/// This assumes the exception handler is `__C_specific_handler` and
	/// the exception data contains the scope table.
	fn c_scope_table(&self) -> Result<CScopeTable>;
}

impl<'a, P: Pe<'a>> UnwindInfoCsehExt<'a, P> for UnwindInfo<'a, P> {
	fn c_scope_table(&self) -> Result<CScopeTable> {
		let data = self.exception_data()?;
		CScopeTable::parse(data)
	}
}

