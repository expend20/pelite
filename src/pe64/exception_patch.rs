//! Exception Data Patching Helpers
//!
//! This module provides helper functions for patching exception handling data
//! structures in PE files. These are useful for function relocation scenarios
//! where exception metadata RVAs need to be updated.
//!
//! # Safety
//!
//! All patching functions assume the caller has verified that:
//! - The file offset is valid and within bounds
//! - The structure being patched actually exists at that offset
//! - The bytes slice is writable
//!
//! The functions perform bounds checking on the immediate write but do not
//! validate semantic correctness of the patched values.

use crate::{Error, Result};

//----------------------------------------------------------------
// RUNTIME_FUNCTION patching
//----------------------------------------------------------------

/// Patch a RUNTIME_FUNCTION entry at the given file offset.
///
/// # Arguments
/// * `bytes` - Mutable byte slice of the PE file
/// * `file_offset` - File offset of the RUNTIME_FUNCTION entry
/// * `begin_address` - New BeginAddress RVA
/// * `end_address` - New EndAddress RVA
/// * `unwind_data` - New UnwindData RVA (optional, None to keep existing)
///
/// # Returns
/// Ok(()) on success, or an error if bounds check fails.
pub fn patch_runtime_function(
	bytes: &mut [u8],
	file_offset: usize,
	begin_address: u32,
	end_address: u32,
	unwind_data: Option<u32>,
) -> Result<()> {
	let size = if unwind_data.is_some() { 12 } else { 8 };
	if file_offset + size > bytes.len() {
		return Err(Error::Bounds);
	}
	
	bytes[file_offset..file_offset + 4].copy_from_slice(&begin_address.to_le_bytes());
	bytes[file_offset + 4..file_offset + 8].copy_from_slice(&end_address.to_le_bytes());
	
	if let Some(unwind) = unwind_data {
		bytes[file_offset + 8..file_offset + 12].copy_from_slice(&unwind.to_le_bytes());
	}
	
	Ok(())
}

/// Patch only the BeginAddress field of a RUNTIME_FUNCTION.
pub fn patch_runtime_function_begin(
	bytes: &mut [u8],
	file_offset: usize,
	begin_address: u32,
) -> Result<()> {
	if file_offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[file_offset..file_offset + 4].copy_from_slice(&begin_address.to_le_bytes());
	Ok(())
}

/// Patch only the EndAddress field of a RUNTIME_FUNCTION.
pub fn patch_runtime_function_end(
	bytes: &mut [u8],
	file_offset: usize,
	end_address: u32,
) -> Result<()> {
	// EndAddress is at offset 4 from RUNTIME_FUNCTION start
	let offset = file_offset + 4;
	if offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[offset..offset + 4].copy_from_slice(&end_address.to_le_bytes());
	Ok(())
}

/// Patch only the UnwindData field of a RUNTIME_FUNCTION.
pub fn patch_runtime_function_unwind(
	bytes: &mut [u8],
	file_offset: usize,
	unwind_data: u32,
) -> Result<()> {
	// UnwindData is at offset 8 from RUNTIME_FUNCTION start
	let offset = file_offset + 8;
	if offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[offset..offset + 4].copy_from_slice(&unwind_data.to_le_bytes());
	Ok(())
}

//----------------------------------------------------------------
// Generic RVA patching
//----------------------------------------------------------------

/// Patch a 32-bit RVA at the given file offset.
///
/// This is the most basic patching operation, useful for any RVA field.
pub fn patch_rva(bytes: &mut [u8], file_offset: usize, new_rva: u32) -> Result<()> {
	if file_offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[file_offset..file_offset + 4].copy_from_slice(&new_rva.to_le_bytes());
	Ok(())
}

/// Patch a 32-bit signed value at the given file offset.
pub fn patch_i32(bytes: &mut [u8], file_offset: usize, value: i32) -> Result<()> {
	if file_offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[file_offset..file_offset + 4].copy_from_slice(&value.to_le_bytes());
	Ok(())
}

//----------------------------------------------------------------
// FH3 specific patching
//----------------------------------------------------------------

/// Patch an FH3 IP-to-state entry at the given file offset.
///
/// # Arguments
/// * `bytes` - Mutable byte slice of the PE file  
/// * `file_offset` - File offset of the IpStateEntry (ip_rva field)
/// * `new_ip_rva` - New IP RVA value
pub fn patch_fh3_ip_state(
	bytes: &mut [u8],
	file_offset: usize,
	new_ip_rva: u32,
) -> Result<()> {
	patch_rva(bytes, file_offset, new_ip_rva)
}

/// Patch an FH3 unwind map action RVA.
///
/// # Arguments
/// * `bytes` - Mutable byte slice of the PE file
/// * `file_offset` - File offset of the action_rva field
/// * `new_action_rva` - New action (destructor) RVA
pub fn patch_fh3_unwind_action(
	bytes: &mut [u8],
	file_offset: usize,
	new_action_rva: u32,
) -> Result<()> {
	patch_rva(bytes, file_offset, new_action_rva)
}

/// Patch an FH3 handler RVA in a catch handler entry.
///
/// # Arguments
/// * `bytes` - Mutable byte slice of the PE file
/// * `file_offset` - File offset of the handler_rva field
/// * `new_handler_rva` - New handler function RVA
pub fn patch_fh3_handler(
	bytes: &mut [u8],
	file_offset: usize,
	new_handler_rva: u32,
) -> Result<()> {
	patch_rva(bytes, file_offset, new_handler_rva)
}

//----------------------------------------------------------------
// CSEH specific patching
//----------------------------------------------------------------

/// Patch a CSEH scope entry at the given file offset.
///
/// # Arguments
/// * `bytes` - Mutable byte slice of the PE file
/// * `file_offset` - File offset of the CScopeEntry (begin_address field)
/// * `begin_address` - New begin address RVA
/// * `end_address` - New end address RVA
/// * `handler_address` - New handler address RVA
/// * `jump_target` - New jump target RVA
pub fn patch_cseh_scope_entry(
	bytes: &mut [u8],
	file_offset: usize,
	begin_address: u32,
	end_address: u32,
	handler_address: u32,
	jump_target: u32,
) -> Result<()> {
	if file_offset + 16 > bytes.len() {
		return Err(Error::Bounds);
	}
	
	bytes[file_offset..file_offset + 4].copy_from_slice(&begin_address.to_le_bytes());
	bytes[file_offset + 4..file_offset + 8].copy_from_slice(&end_address.to_le_bytes());
	bytes[file_offset + 8..file_offset + 12].copy_from_slice(&handler_address.to_le_bytes());
	bytes[file_offset + 12..file_offset + 16].copy_from_slice(&jump_target.to_le_bytes());
	
	Ok(())
}

/// Patch only the begin/end addresses of a CSEH scope entry.
pub fn patch_cseh_scope_range(
	bytes: &mut [u8],
	file_offset: usize,
	begin_address: u32,
	end_address: u32,
) -> Result<()> {
	if file_offset + 8 > bytes.len() {
		return Err(Error::Bounds);
	}
	
	bytes[file_offset..file_offset + 4].copy_from_slice(&begin_address.to_le_bytes());
	bytes[file_offset + 4..file_offset + 8].copy_from_slice(&end_address.to_le_bytes());
	
	Ok(())
}

/// Patch only the handler_address field of a CSEH scope entry.
pub fn patch_cseh_handler(
	bytes: &mut [u8],
	file_offset: usize,
	handler_address: u32,
) -> Result<()> {
	// handler_address is at offset 8 from scope entry start
	let offset = file_offset + 8;
	if offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[offset..offset + 4].copy_from_slice(&handler_address.to_le_bytes());
	Ok(())
}

/// Patch only the jump_target field of a CSEH scope entry.
pub fn patch_cseh_jump_target(
	bytes: &mut [u8],
	file_offset: usize,
	jump_target: u32,
) -> Result<()> {
	// jump_target is at offset 12 from scope entry start
	let offset = file_offset + 12;
	if offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	bytes[offset..offset + 4].copy_from_slice(&jump_target.to_le_bytes());
	Ok(())
}

//----------------------------------------------------------------
// FH4 specific patching
//----------------------------------------------------------------

/// Check if an FH4 RVA can be patched in place.
///
/// FH4 stores some RVAs as fixed 4-byte values (try block handlers, etc),
/// which can be patched in place.
pub fn can_patch_fh4_rva_in_place(file_offset: usize, bytes_len: usize) -> bool {
	file_offset + 4 <= bytes_len
}

/// Patch an FH4 fixed RVA (handler RVA, handlers_rva, type_desc_rva).
///
/// These RVAs are stored as 4-byte little-endian values in FH4.
pub fn patch_fh4_fixed_rva(
	bytes: &mut [u8],
	file_offset: usize,
	new_rva: u32,
) -> Result<()> {
	patch_rva(bytes, file_offset, new_rva)
}

//----------------------------------------------------------------
// Utility functions
//----------------------------------------------------------------

/// Apply an RVA delta to patch IP-based addresses.
///
/// Useful when relocating a function: reads the current value at file_offset,
/// subtracts old_base, adds new_base, and writes the result back.
///
/// # Arguments
/// * `bytes` - Mutable byte slice
/// * `file_offset` - File offset of the RVA to relocate
/// * `old_base` - Old function base RVA
/// * `new_base` - New function base RVA
pub fn relocate_rva(
	bytes: &mut [u8],
	file_offset: usize,
	old_base: u32,
	new_base: u32,
) -> Result<()> {
	if file_offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&bytes[file_offset..file_offset + 4]);
	let current = u32::from_le_bytes(buf);
	
	// Calculate new value: current - old_base + new_base
	let new_value = current.wrapping_sub(old_base).wrapping_add(new_base);
	
	bytes[file_offset..file_offset + 4].copy_from_slice(&new_value.to_le_bytes());
	Ok(())
}

/// Read a u32 value at the given file offset.
pub fn read_u32(bytes: &[u8], file_offset: usize) -> Result<u32> {
	if file_offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&bytes[file_offset..file_offset + 4]);
	Ok(u32::from_le_bytes(buf))
}

/// Read an i32 value at the given file offset.
pub fn read_i32(bytes: &[u8], file_offset: usize) -> Result<i32> {
	if file_offset + 4 > bytes.len() {
		return Err(Error::Bounds);
	}
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&bytes[file_offset..file_offset + 4]);
	Ok(i32::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
	use super::*;
	
	#[test]
	fn test_patch_rva() {
		let mut bytes = [0u8; 16];
		patch_rva(&mut bytes, 4, 0x12345678).unwrap();
		assert_eq!(&bytes[4..8], &[0x78, 0x56, 0x34, 0x12]);
	}
	
	#[test]
	fn test_patch_runtime_function() {
		let mut bytes = [0u8; 16];
		patch_runtime_function(&mut bytes, 0, 0x1000, 0x2000, Some(0x3000)).unwrap();
		
		assert_eq!(read_u32(&bytes, 0).unwrap(), 0x1000);
		assert_eq!(read_u32(&bytes, 4).unwrap(), 0x2000);
		assert_eq!(read_u32(&bytes, 8).unwrap(), 0x3000);
	}
	
	#[test]
	fn test_relocate_rva() {
		let mut bytes = [0u8; 8];
		// Set initial value to 0x1500
		patch_rva(&mut bytes, 0, 0x1500).unwrap();
		
		// Relocate from base 0x1000 to 0x5000
		relocate_rva(&mut bytes, 0, 0x1000, 0x5000).unwrap();
		
		// Should be 0x1500 - 0x1000 + 0x5000 = 0x5500
		assert_eq!(read_u32(&bytes, 0).unwrap(), 0x5500);
	}
	
	#[test]
	fn test_patch_cseh_scope_entry() {
		let mut bytes = [0u8; 20];
		patch_cseh_scope_entry(&mut bytes, 0, 0x1000, 0x1100, 0x2000, 0x3000).unwrap();
		
		assert_eq!(read_u32(&bytes, 0).unwrap(), 0x1000);
		assert_eq!(read_u32(&bytes, 4).unwrap(), 0x1100);
		assert_eq!(read_u32(&bytes, 8).unwrap(), 0x2000);
		assert_eq!(read_u32(&bytes, 12).unwrap(), 0x3000);
	}
	
	#[test]
	fn test_bounds_check() {
		let mut bytes = [0u8; 4];
		assert!(patch_rva(&mut bytes, 2, 0x1234).is_err());
		assert!(patch_rva(&mut bytes, 0, 0x1234).is_ok());
	}
}

