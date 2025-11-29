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

/// Function Info 3 (FH3) structure with file offset locations for patching.
///
/// This structure contains both the parsed FH3 data and file offsets
/// for each field, enabling patching/rebuilding use cases.
#[derive(Debug, Clone)]
pub struct FuncInfo3 {
	/// RVA of the FuncInfo3 structure
	pub func_info_rva: u32,
	/// File offset of the FuncInfo3 structure
	pub func_info_file_offset: usize,
	
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
	
	/// IP-to-state map file offset (None if ip_map_rva is 0)
	pub ip_map_file_offset: Option<usize>,
	/// Parsed IP to state map entries with file offsets
	pub ip_to_state_map: Vec<IpStateEntry3>,
	
	/// Unwind map file offset (None if unwind_map_rva is 0)
	pub unwind_map_file_offset: Option<usize>,
	/// Parsed unwind map entries with file offsets
	pub unwind_map: Vec<UnwindMapEntry3>,
	
	/// Try block map file offset (None if try_block_map_rva is 0)
	pub try_block_map_file_offset: Option<usize>,
	/// Parsed try block map entries with file offsets
	pub try_block_map: Vec<TryBlockMapEntry3>,
}

/// Unwind map entry for FH3 with file offset locations.
#[derive(Debug, Clone)]
pub struct UnwindMapEntry3 {
	/// State to transition to (usually state - 1, or -1 for terminal)
	pub next_state: i32,
	/// File offset of the next_state field
	pub next_state_file_offset: usize,
	/// RVA of the destructor/cleanup action to call (0 if no action)
	pub action_rva: u32,
	/// File offset of the action_rva field
	pub action_rva_file_offset: usize,
}

/// Try block map entry for FH3 with file offset locations.
#[derive(Debug, Clone)]
pub struct TryBlockMapEntry3 {
	/// Lowest state covered by this try block
	pub try_low: u32,
	/// File offset of try_low field
	pub try_low_file_offset: usize,
	/// Highest state covered by this try block
	pub try_high: u32,
	/// File offset of try_high field
	pub try_high_file_offset: usize,
	/// Highest state of associated catch handlers
	pub catch_high: u32,
	/// File offset of catch_high field
	pub catch_high_file_offset: usize,
	/// Number of catch handlers
	pub handler_count: u32,
	/// RVA to the array of catch handlers
	pub handlers_rva: u32,
	/// File offset of handlers_rva field
	pub handlers_rva_file_offset: usize,
	/// Parsed catch handlers with file offsets
	pub handlers: Vec<HandlerType3>,
}

/// Catch handler entry for FH3 with file offset locations.
#[derive(Debug, Clone)]
pub struct HandlerType3 {
	/// Handler adjectives/flags
	pub adjectives: u32,
	/// File offset of adjectives field
	pub adjectives_file_offset: usize,
	/// RVA to the type descriptor for the caught exception type
	pub type_desc_rva: u32,
	/// File offset of type_desc_rva field
	pub type_desc_rva_file_offset: usize,
	/// Frame offset where the caught object is stored
	pub catch_obj_offset: u32,
	/// File offset of catch_obj_offset field
	pub catch_obj_offset_file_offset: usize,
	/// RVA of the catch handler function
	pub handler_rva: u32,
	/// File offset of handler_rva field
	pub handler_rva_file_offset: usize,
	/// Distance between handler and parent frame pointer
	pub disp_frame: u32,
	/// File offset of disp_frame field
	pub disp_frame_file_offset: usize,
}

/// IP to state map entry for FH3 with file offset locations.
#[derive(Debug, Clone)]
pub struct IpStateEntry3 {
	/// RVA of the instruction pointer
	pub ip_rva: u32,
	/// File offset where the IP RVA is stored (for patching)
	pub ip_rva_file_offset: usize,
	/// Exception handling state at this IP
	pub state: i32,
	/// File offset where the state is stored
	pub state_file_offset: usize,
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

impl FuncInfo3 {
	/// Parse FH3 exception handling data with file offset locations.
	pub fn parse<'a, P: Pe<'a>>(
		pe: P, 
		data: &[u8], 
		func_info_rva: u32, 
		func_info_file_offset: usize
	) -> Result<FuncInfo3> {
		// FuncInfo3 header is 40 bytes (10 x 4-byte fields)
		if data.len() < 40 {
			return Err(Error::Bounds);
		}

		let magic_number = read_u32_from(data, 0);
		if magic_number != FH3_MAGIC {
			return Err(Error::Invalid);
		}

		let max_state = read_u32_from(data, 4);
		let unwind_map_rva = read_u32_from(data, 8);
		let try_block_count = read_u32_from(data, 12);
		let try_block_map_rva = read_u32_from(data, 16);
		let ip_map_count = read_u32_from(data, 20);
		let ip_map_rva = read_u32_from(data, 24);
		let frame_offset = read_i32_from(data, 28);
		let es_type_list_rva = read_u32_from(data, 32);
		let eh_flags = read_u32_from(data, 36);

		// Parse Unwind Map with locations
		let mut unwind_map = Vec::new();
		let unwind_map_file_offset = if unwind_map_rva != 0 {
			pe.rva_to_file_offset(unwind_map_rva).ok()
		} else {
			None
		};
		
		if unwind_map_rva != 0 && max_state > 0 {
			let bytes = pe.slice_bytes(unwind_map_rva)?;
			let base_file_offset = pe.rva_to_file_offset(unwind_map_rva)?;
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
					next_state_file_offset: base_file_offset + offset,
					action_rva,
					action_rva_file_offset: base_file_offset + offset + 4,
				});
			}
		}

		// Parse Try Block Map with locations
		let mut try_block_map = Vec::new();
		let try_block_map_file_offset = if try_block_map_rva != 0 {
			pe.rva_to_file_offset(try_block_map_rva).ok()
		} else {
			None
		};
		
		if try_block_map_rva != 0 && try_block_count > 0 {
			let bytes = pe.slice_bytes(try_block_map_rva)?;
			let base_file_offset = pe.rva_to_file_offset(try_block_map_rva)?;
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

				// Parse handlers with locations
				let mut handlers = Vec::new();
				if handlers_rva != 0 && handler_count > 0 {
					let h_bytes = pe.slice_bytes(handlers_rva)?;
					let h_base_offset = pe.rva_to_file_offset(handlers_rva)?;
					let h_entry_size = 20;
					let h_required_len = (handler_count as usize) * h_entry_size;
					if h_bytes.len() < h_required_len {
						return Err(Error::Bounds);
					}

					for j in 0..handler_count as usize {
						let h_offset = j * h_entry_size;
						handlers.push(HandlerType3 {
							adjectives: read_u32_from(h_bytes, h_offset),
							adjectives_file_offset: h_base_offset + h_offset,
							type_desc_rva: read_u32_from(h_bytes, h_offset + 4),
							type_desc_rva_file_offset: h_base_offset + h_offset + 4,
							catch_obj_offset: read_u32_from(h_bytes, h_offset + 8),
							catch_obj_offset_file_offset: h_base_offset + h_offset + 8,
							handler_rva: read_u32_from(h_bytes, h_offset + 12),
							handler_rva_file_offset: h_base_offset + h_offset + 12,
							disp_frame: read_u32_from(h_bytes, h_offset + 16),
							disp_frame_file_offset: h_base_offset + h_offset + 16,
						});
					}
				}

				try_block_map.push(TryBlockMapEntry3 {
					try_low,
					try_low_file_offset: base_file_offset + offset,
					try_high,
					try_high_file_offset: base_file_offset + offset + 4,
					catch_high,
					catch_high_file_offset: base_file_offset + offset + 8,
					handler_count,
					handlers_rva,
					handlers_rva_file_offset: base_file_offset + offset + 16,
					handlers,
				});
			}
		}

		// Parse IP to State Map with locations
		let mut ip_to_state_map = Vec::new();
		let ip_map_file_offset = if ip_map_rva != 0 {
			pe.rva_to_file_offset(ip_map_rva).ok()
		} else {
			None
		};
		
		if ip_map_rva != 0 && ip_map_count > 0 {
			let bytes = pe.slice_bytes(ip_map_rva)?;
			let base_file_offset = pe.rva_to_file_offset(ip_map_rva)?;
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
					ip_rva_file_offset: base_file_offset + offset,
					state,
					state_file_offset: base_file_offset + offset + 4,
				});
			}
		}

		Ok(FuncInfo3 {
			func_info_rva,
			func_info_file_offset,
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
			ip_map_file_offset,
			ip_to_state_map,
			unwind_map_file_offset,
			unwind_map,
			try_block_map_file_offset,
			try_block_map,
		})
	}
}

/// Extension trait for accessing FH3 data from unwind info.
pub trait UnwindInfoFh3Ext<'a, P: Pe<'a>> {
	/// Parse FH3 exception handling data from this unwind info.
	///
	/// This assumes the exception handler data contains an RVA to the FuncInfo3 structure.
	/// Returns the parsed FuncInfo3 with file offset locations for patching.
	fn func_info3(&self) -> Result<FuncInfo3>;
	
	/// Get the RVA to the FuncInfo3 structure.
	fn func_info3_rva(&self) -> Result<u32>;
}

impl<'a, P: Pe<'a>> UnwindInfoFh3Ext<'a, P> for UnwindInfo<'a, P> {
	fn func_info3(&self) -> Result<FuncInfo3> {
		let func_info3_rva = self.func_info3_rva()?;
		let func_info3_file_offset = self.pe().rva_to_file_offset(func_info3_rva)?;
		let bytes = self.pe().slice_bytes(func_info3_rva)?;
		FuncInfo3::parse(self.pe(), bytes, func_info3_rva, func_info3_file_offset)
	}
	
	fn func_info3_rva(&self) -> Result<u32> {
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
		
		Ok(rva)
	}
}
