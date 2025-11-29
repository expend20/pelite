//! FH3 (FuncInfo3) C++ Exception Handling Structures
//!
//! This module provides parsing for MSVC's `__CxxFrameHandler3` exception handling
//! metadata. FH3 uses fixed-size structures with plain RVAs, unlike FH4 which uses
//! variable-length encoded integers.
//!
//! The FH3 format is identified by a magic number of `0x19930522` in the header.

use crate::pe64::exception::UnwindInfo;
use crate::{Error, Result};
use super::Pe;

/// Magic number identifying FH3 exception handling data.
/// This is 0x19930522, representing the date 1993/05/22.
pub const FH3_MAGIC: u32 = 0x19930522;

/// Function Info 3 (FH3) header structure.
///
/// This structure is pointed to by the exception handler data in the unwind info.
/// Note: The actual binary structure does NOT have a BBT flags field at offset 4.
/// DUMPBIN shows BBT Flags but it may be computed or from extended data.
#[derive(Debug, Clone)]
pub struct FuncInfo3 {
	/// Magic number, should be `FH3_MAGIC` (0x19930522)
	pub magic_number: u32,
	/// Maximum state number (number of unwind entries)
	pub max_state: u32,
	/// RVA to the unwind map array
	pub unwind_map_rva: u32,
	/// Number of try blocks
	pub try_block_count: u32,
	/// RVA to the try block map array
	pub try_block_map_rva: u32,
	/// Number of IP to state map entries
	pub ip_map_count: u32,
	/// RVA to the IP to state map array
	pub ip_map_rva: u32,
	/// Frame offset of the unwind helper (EH unwind help)
	pub frame_offset: i32,
	/// RVA to the ES (Expected State) type list
	pub es_type_list_rva: u32,
	/// Exception handling flags
	pub eh_flags: u32,
	/// Parsed unwind map entries
	pub unwind_map: Vec<UnwindMapEntry3>,
	/// Parsed try block map entries
	pub try_block_map: Vec<TryBlockMapEntry3>,
	/// Parsed IP to state map entries
	pub ip_to_state_map: Vec<IpStateEntry3>,
}

/// Unwind map entry for FH3.
///
/// Each entry describes a state transition during stack unwinding.
#[derive(Debug, Clone)]
pub struct UnwindMapEntry3 {
	/// State to transition to (usually state - 1, or -1 for terminal)
	pub next_state: i32,
	/// RVA of the destructor/cleanup action to call (0 if no action)
	pub action_rva: u32,
}

/// Try block map entry for FH3.
///
/// Describes a try/catch block and its associated catch handlers.
#[derive(Debug, Clone)]
pub struct TryBlockMapEntry3 {
	/// Lowest state covered by this try block
	pub try_low: u32,
	/// Highest state covered by this try block
	pub try_high: u32,
	/// Highest state of associated catch handlers
	pub catch_high: u32,
	/// Number of catch handlers
	pub handler_count: u32,
	/// RVA to the array of catch handlers
	pub handlers_rva: u32,
	/// Parsed catch handlers
	pub handlers: Vec<HandlerType3>,
}

/// Catch handler entry for FH3.
///
/// Describes a single catch handler within a try block.
#[derive(Debug, Clone)]
pub struct HandlerType3 {
	/// Handler adjectives/flags
	pub adjectives: u32,
	/// RVA to the type descriptor for the caught exception type
	pub type_desc_rva: u32,
	/// Frame offset where the caught object is stored
	pub catch_obj_offset: u32,
	/// RVA of the catch handler function
	pub handler_rva: u32,
	/// Distance between handler and parent frame pointer
	pub disp_frame: u32,
}

/// IP to state map entry for FH3.
///
/// Maps instruction pointer addresses to exception handling states.
#[derive(Debug, Clone)]
pub struct IpStateEntry3 {
	/// RVA of the instruction pointer
	pub ip_rva: u32,
	/// Exception handling state at this IP
	pub state: i32,
}

impl FuncInfo3 {
	/// Parse FH3 exception handling data from the given data slice.
	///
	/// # Arguments
	/// * `pe` - The PE file to resolve RVAs
	/// * `data` - The raw bytes starting at the FuncInfo3 header
	///
	/// # Returns
	/// A parsed `FuncInfo3` structure or an error.
	pub fn parse<'a, P: Pe<'a>>(pe: P, data: &[u8]) -> Result<FuncInfo3> {
		// FuncInfo3 header is 40 bytes (10 x 4-byte fields)
		if data.len() < 40 {
			return Err(Error::Bounds);
		}

		let read_u32 = |offset: usize| -> u32 {
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[offset..offset + 4]);
			u32::from_le_bytes(buf)
		};

		let read_i32 = |offset: usize| -> i32 {
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[offset..offset + 4]);
			i32::from_le_bytes(buf)
		};

		let magic_number = read_u32(0);
		if magic_number != FH3_MAGIC {
			return Err(Error::Invalid);
		}

		let max_state = read_u32(4);
		let unwind_map_rva = read_u32(8);
		let try_block_count = read_u32(12);
		let try_block_map_rva = read_u32(16);
		let ip_map_count = read_u32(20);
		let ip_map_rva = read_u32(24);
		let frame_offset = read_i32(28);
		let es_type_list_rva = read_u32(32);
		let eh_flags = read_u32(36);

		// Parse Unwind Map
		let mut unwind_map = Vec::new();
		if unwind_map_rva != 0 && max_state > 0 {
			let bytes = pe.slice_bytes(unwind_map_rva)?;
			// Each UnwindMapEntry is 8 bytes (next_state: i32, action_rva: u32)
			let entry_size = 8;
			let required_len = (max_state as usize) * entry_size;
			if bytes.len() < required_len {
				return Err(Error::Bounds);
			}

			for i in 0..max_state as usize {
				let offset = i * entry_size;
				let next_state = read_i32_from(bytes, offset);
				let action_rva = read_u32_from(bytes, offset + 4);
				unwind_map.push(UnwindMapEntry3 {
					next_state,
					action_rva,
				});
			}
		}

		// Parse Try Block Map
		let mut try_block_map = Vec::new();
		if try_block_map_rva != 0 && try_block_count > 0 {
			let bytes = pe.slice_bytes(try_block_map_rva)?;
			// Each TryBlockMapEntry is 20 bytes (5 x u32)
			let entry_size = 20;
			let required_len = (try_block_count as usize) * entry_size;
			if bytes.len() < required_len {
				return Err(Error::Bounds);
			}

			for i in 0..try_block_count as usize {
				let offset = i * entry_size;
				let try_low = read_u32_from(bytes, offset);
				let try_high = read_u32_from(bytes, offset + 4);
				let catch_high = read_u32_from(bytes, offset + 8);
				let handler_count = read_u32_from(bytes, offset + 12);
				let handlers_rva = read_u32_from(bytes, offset + 16);

				// Parse handlers
				let mut handlers = Vec::new();
				if handlers_rva != 0 && handler_count > 0 {
					let h_bytes = pe.slice_bytes(handlers_rva)?;
					// Each HandlerType is 20 bytes (5 x u32)
					let h_entry_size = 20;
					let h_required_len = (handler_count as usize) * h_entry_size;
					if h_bytes.len() < h_required_len {
						return Err(Error::Bounds);
					}

					for j in 0..handler_count as usize {
						let h_offset = j * h_entry_size;
						handlers.push(HandlerType3 {
							adjectives: read_u32_from(h_bytes, h_offset),
							type_desc_rva: read_u32_from(h_bytes, h_offset + 4),
							catch_obj_offset: read_u32_from(h_bytes, h_offset + 8),
							handler_rva: read_u32_from(h_bytes, h_offset + 12),
							disp_frame: read_u32_from(h_bytes, h_offset + 16),
						});
					}
				}

				try_block_map.push(TryBlockMapEntry3 {
					try_low,
					try_high,
					catch_high,
					handler_count,
					handlers_rva,
					handlers,
				});
			}
		}

		// Parse IP to State Map
		let mut ip_to_state_map = Vec::new();
		if ip_map_rva != 0 && ip_map_count > 0 {
			let bytes = pe.slice_bytes(ip_map_rva)?;
			// Each IpStateEntry is 8 bytes (ip_rva: u32, state: i32)
			let entry_size = 8;
			let required_len = (ip_map_count as usize) * entry_size;
			if bytes.len() < required_len {
				return Err(Error::Bounds);
			}

			for i in 0..ip_map_count as usize {
				let offset = i * entry_size;
				let ip_rva = read_u32_from(bytes, offset);
				let state = read_i32_from(bytes, offset + 4);
				ip_to_state_map.push(IpStateEntry3 {
					ip_rva,
					state,
				});
			}
		}

		Ok(FuncInfo3 {
			magic_number,
			max_state,
			unwind_map_rva,
			try_block_count,
			try_block_map_rva,
			ip_map_count,
			ip_map_rva,
			frame_offset,
			es_type_list_rva,
			eh_flags,
			unwind_map,
			try_block_map,
			ip_to_state_map,
		})
	}
}

/// Helper to read u32 from a byte slice at given offset
#[inline]
fn read_u32_from(bytes: &[u8], offset: usize) -> u32 {
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&bytes[offset..offset + 4]);
	u32::from_le_bytes(buf)
}

/// Helper to read i32 from a byte slice at given offset
#[inline]
fn read_i32_from(bytes: &[u8], offset: usize) -> i32 {
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&bytes[offset..offset + 4]);
	i32::from_le_bytes(buf)
}

/// Extension trait for accessing FH3 data from unwind info.
pub trait UnwindInfoFh3Ext<'a, P: Pe<'a>> {
	/// Parse FH3 exception handling data from this unwind info.
	///
	/// This assumes the exception handler data contains an RVA to the FuncInfo3 structure.
	fn func_info3(&self) -> Result<FuncInfo3>;
}

impl<'a, P: Pe<'a>> UnwindInfoFh3Ext<'a, P> for UnwindInfo<'a, P> {
	fn func_info3(&self) -> Result<FuncInfo3> {
		let data = self.exception_data()?;
		
		// The exception data contains an RVA to the FuncInfo3 structure
		if data.len() < 4 {
			return Err(Error::Bounds);
		}
		let mut buf = [0u8; 4];
		buf.copy_from_slice(&data[..4]);
		let rva = u32::from_le_bytes(buf);
		
		if rva == 0 {
			return Err(Error::Invalid);
		}
		
		let bytes = self.pe().slice_bytes(rva)?;
		FuncInfo3::parse(self.pe(), bytes)
	}
}

