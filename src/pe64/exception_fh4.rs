//! FH4 (FuncInfo4) C++ Exception Handling Structures
//!
//! This module provides parsing for MSVC's `__CxxFrameHandler4` exception handling
//! metadata. FH4 uses variable-length encoded integers for compact storage.

use crate::pe64::exception::UnwindInfo;
use crate::{Error, Result};
use super::Pe;

/// Variable length integer reader for FH4.
///
/// FH4 uses a nested continuation bit scheme:
/// - 1 byte:  if bit0=0, value = byte >> 1 (7 bits of data)
/// - 2 bytes: if bit0=1, bit1=0, value = (b0 >> 2) | (b1 << 6) (6+8=14 bits)
/// - 3 bytes: if bit0=1, bit1=1, b1.bit0=0, value = (b0 >> 3) | ((b1 >> 1) << 5) | (b2 << 12) (5+7+8=20 bits)
/// - 4 bytes: if bit0=1, bit1=1, b1.bit0=1, value = (b0 >> 3) | ((b1 >> 2) << 5) | (b2 << 11) | (b3 << 19) (5+6+8+8=27 bits)
pub struct UVarIntReader<'a> {
	pub ptr: &'a [u8],
}
impl<'a> UVarIntReader<'a> {
	pub fn new(ptr: &'a [u8]) -> Self {
		Self { ptr }
	}
	pub fn read_u32(&mut self) -> Result<u32> {
		if self.ptr.is_empty() {
			return Err(Error::Bounds);
		}
		let b0 = self.ptr[0];
		self.ptr = &self.ptr[1..];

		// 1 byte: bit0 = 0
		if (b0 & 1) == 0 {
			return Ok((b0 >> 1) as u32);
		}

		// 2+ bytes: bit0 = 1
		if self.ptr.is_empty() {
			return Err(Error::Bounds);
		}
		let b1 = self.ptr[0];
		self.ptr = &self.ptr[1..];

		// 2 bytes: bit1 = 0
		if (b0 & 2) == 0 {
			return Ok(((b0 >> 2) as u32) | ((b1 as u32) << 6));
		}

		// 3+ bytes: bit1 = 1
		if self.ptr.is_empty() {
			return Err(Error::Bounds);
		}
		let b2 = self.ptr[0];
		self.ptr = &self.ptr[1..];

		// 3 bytes: b1.bit0 = 0
		if (b1 & 1) == 0 {
			return Ok(((b0 >> 3) as u32) | (((b1 >> 1) as u32) << 5) | ((b2 as u32) << 12));
		}

		// 4 bytes: b1.bit0 = 1
		if self.ptr.is_empty() {
			return Err(Error::Bounds);
		}
		let b3 = self.ptr[0];
		self.ptr = &self.ptr[1..];

		Ok(((b0 >> 3) as u32) | (((b1 >> 2) as u32) << 5) | ((b2 as u32) << 11) | ((b3 as u32) << 19))
	}
	pub fn read_i32(&mut self) -> Result<i32> {
		Ok(self.read_u32()? as i32)
	}
}

//----------------------------------------------------------------
// UVarInt Writer for FH4 encoding
//----------------------------------------------------------------

/// Variable length integer writer for FH4.
///
/// Encodes unsigned 32-bit integers using FH4's variable-length format.
pub struct UVarIntWriter {
	buffer: Vec<u8>,
}

impl UVarIntWriter {
	/// Create a new UVarIntWriter.
	pub fn new() -> Self {
		Self { buffer: Vec::new() }
	}
	
	/// Write a u32 value in FH4 variable-length encoding.
	pub fn write_u32(&mut self, value: u32) {
		let bytes = encode_uvarint(value);
		self.buffer.extend_from_slice(&bytes);
	}
	
	/// Write an i32 value (cast to u32).
	pub fn write_i32(&mut self, value: i32) {
		self.write_u32(value as u32);
	}
	
	/// Consume the writer and return the encoded bytes.
	pub fn into_bytes(self) -> Vec<u8> {
		self.buffer
	}
	
	/// Get the current encoded bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.buffer
	}
}

impl Default for UVarIntWriter {
	fn default() -> Self {
		Self::new()
	}
}

/// Calculate the encoded size of a u32 in UVarInt format.
pub fn uvarint_encoded_size(value: u32) -> usize {
	// 1 byte: 7 bits of data (max 0x7F = 127)
	// 2 bytes: 6 + 8 = 14 bits (max 0x3FFF = 16383)
	// 3 bytes: 5 + 7 + 8 = 20 bits (max 0xFFFFF = 1048575)
	// 4 bytes: 5 + 6 + 8 + 8 = 27 bits (max 0x7FFFFFF = 134217727)
	if value < 0x80 {
		1
	} else if value < 0x4000 {
		2
	} else if value < 0x100000 {
		3
	} else {
		4
	}
}

/// Encode a u32 value to FH4 variable-length bytes.
pub fn encode_uvarint(value: u32) -> Vec<u8> {
	// FH4 encoding scheme:
	// 1 byte:  if bit0=0, value = byte >> 1 (7 bits of data, max 0x7F)
	// 2 bytes: if bit0=1, bit1=0, value = (b0 >> 2) | (b1 << 6) (6+8=14 bits, max 0x3FFF)
	// 3 bytes: if bit0=1, bit1=1, b1.bit0=0, value = (b0 >> 3) | ((b1 >> 1) << 5) | (b2 << 12) (5+7+8=20 bits, max 0xFFFFF)
	// 4 bytes: if bit0=1, bit1=1, b1.bit0=1, value = (b0 >> 3) | ((b1 >> 2) << 5) | (b2 << 11) | (b3 << 19) (5+6+8+8=27 bits)
	
	if value < 0x80 {
		// 1 byte: bit0=0, data in bits 1-7
		vec![(value << 1) as u8]
	} else if value < 0x4000 {
		// 2 bytes: bit0=1, bit1=0, 6 bits in b0[2:7], 8 bits in b1
		let b0 = ((value & 0x3F) << 2) | 0x01;
		let b1 = (value >> 6) & 0xFF;
		vec![b0 as u8, b1 as u8]
	} else if value < 0x100000 {
		// 3 bytes: bit0=1, bit1=1, b1.bit0=0
		// b0[3:7] = 5 bits, b1[1:7] = 7 bits, b2 = 8 bits
		let b0 = ((value & 0x1F) << 3) | 0x03;
		let b1 = ((value >> 5) & 0x7F) << 1;
		let b2 = (value >> 12) & 0xFF;
		vec![b0 as u8, b1 as u8, b2 as u8]
	} else {
		// 4 bytes: bit0=1, bit1=1, b1.bit0=1
		// b0[3:7] = 5 bits, b1[2:7] = 6 bits, b2 = 8 bits, b3 = 8 bits
		let b0 = ((value & 0x1F) << 3) | 0x03;
		let b1 = (((value >> 5) & 0x3F) << 2) | 0x01;
		let b2 = (value >> 11) & 0xFF;
		let b3 = (value >> 19) & 0xFF;
		vec![b0 as u8, b1 as u8, b2 as u8, b3 as u8]
	}
}

//----------------------------------------------------------------
// FH4 header flag bits
//----------------------------------------------------------------

/// These control which optional RVA fields are present in the FH4 header
const FH4_HAS_BBT_FLAGS: u8 = 0x01;      // BBT flags present (4 bytes)
const FH4_HAS_UNWIND_MAP: u8 = 0x08;     // Unwind map RVA present
const FH4_HAS_TRY_BLOCK_MAP: u8 = 0x10;  // Try block map RVA present
const FH4_HAS_IP_TO_STATE: u8 = 0x20;    // IP to state map RVA present
#[allow(dead_code)]
const FH4_IS_CATCH_FUNCLET: u8 = 0x02;   // Is catch funclet
#[allow(dead_code)]
const FH4_HAS_SEPARATE_GS: u8 = 0x04;    // Has separate GS unwind info

//----------------------------------------------------------------
// FH4 structures with file offset locations
//----------------------------------------------------------------

/// Function Info 4 (FH4) structure with file offset locations for patching.
#[derive(Debug, Clone)]
pub struct FuncInfo4 {
	/// RVA of the FuncInfo4 data
	pub func_info_rva: u32,
	/// File offset of the FuncInfo4 data
	pub func_info_file_offset: usize,
	
	/// Header byte containing flags
	pub header: u8,
	
	/// Unwind map RVA
	pub unwind_map_rva: u32,
	/// Unwind map file offset
	pub unwind_map_file_offset: Option<usize>,
	/// Unwind map entries with file offsets
	pub unwind_map: Vec<UnwindMapEntry4>,
	
	/// Try block map RVA
	pub try_block_map_rva: u32,
	/// Try block map file offset
	pub try_block_map_file_offset: Option<usize>,
	/// Try block entries with file offsets
	pub try_block_map: Vec<TryBlockMapEntry4>,
	
	/// IP to state map RVA
	pub ip_map_rva: u32,
	/// IP to state map file offset
	pub ip_map_file_offset: Option<usize>,
	/// IP to state entries with file offsets
	pub ip_to_state_map: Vec<IpStateEntry4>,
}

/// Unwind map entry for FH4 with file offset locations.
///
/// Note: FH4 uses variable-length encoding, so in-place patching may not
/// always be possible if the new value requires more bytes.
#[derive(Debug, Clone)]
pub struct UnwindMapEntry4 {
	/// The entry offset within the unwind map
	pub entry_offset: u32,
	/// File offset of the entry data
	pub file_offset: usize,
	/// The encoded size of this entry in bytes
	pub encoded_size: usize,
	/// Type of unwind action (0-3)
	pub type_: u8,
	/// Next offset (relative, negative means back)
	pub next_offset: i32,
	/// Action RVA (destructor address, only valid if type_ == 3)
	pub action_rva: u32,
	/// File offset of the action RVA (only valid if type_ == 3)
	pub action_rva_file_offset: Option<usize>,
}

/// Try block map entry for FH4 with file offset locations.
#[derive(Debug, Clone)]
pub struct TryBlockMapEntry4 {
	/// File offset of this entry
	pub file_offset: usize,
	/// Try low state
	pub try_low: u32,
	/// Try high state
	pub try_high: u32,
	/// Catch high state
	pub catch_high: u32,
	/// Handlers RVA
	pub handlers_rva: u32,
	/// File offset of handlers RVA
	pub handlers_rva_file_offset: usize,
	/// Handler entries with file offsets
	pub handlers: Vec<HandlerEntry4>,
}

/// Handler entry for FH4 with file offset locations.
#[derive(Debug, Clone)]
pub struct HandlerEntry4 {
	/// File offset of this handler entry
	pub file_offset: usize,
	/// Header byte containing flags
	pub header: u8,
	/// Adjectives/flags
	pub adjectives: u32,
	/// Type descriptor RVA (0 if not present)
	pub type_desc_rva: u32,
	/// File offset of type descriptor RVA (only valid if present)
	pub type_desc_rva_file_offset: Option<usize>,
	/// Catch object frame offset
	pub catch_obj_offset: u32,
	/// Handler function RVA
	pub handler_rva: u32,
	/// File offset of handler RVA
	pub handler_rva_file_offset: usize,
}

/// IP to state entry for FH4 with file offset locations.
#[derive(Debug, Clone)]
pub struct IpStateEntry4 {
	/// File offset of this entry
	pub file_offset: usize,
	/// Encoded size of this entry in bytes
	pub encoded_size: usize,
	/// Accumulated IP offset from function start
	pub ip_offset: u32,
	/// Delta from previous IP entry
	pub delta: u32,
	/// State value
	pub state: i32,
}

impl FuncInfo4 {
	/// Parse FH4 data with file offset locations.
	pub fn parse<'a, P: Pe<'a>>(
		pe: P,
		data: &[u8],
		func_info_rva: u32,
		func_info_file_offset: usize
	) -> Result<FuncInfo4> {
		if data.is_empty() {
			return Err(Error::Bounds);
		}

		let header = data[0];
		let mut offset = 1usize;
		
		// Skip BBT flags if present (4 bytes)
		if (header & FH4_HAS_BBT_FLAGS) != 0 {
			offset += 4;
		}
		
		// Read Unwind Map RVA if present
		let unwind_rva = if (header & FH4_HAS_UNWIND_MAP) != 0 {
			if data.len() < offset + 4 { return Err(Error::Bounds); }
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[offset..offset + 4]);
			offset += 4;
			u32::from_le_bytes(buf)
		} else {
			0
		};
		
		// Read Try Block Map RVA if present
		let try_rva = if (header & FH4_HAS_TRY_BLOCK_MAP) != 0 {
			if data.len() < offset + 4 { return Err(Error::Bounds); }
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[offset..offset + 4]);
			offset += 4;
			u32::from_le_bytes(buf)
		} else {
			0
		};
		
		// Read IP to State Map RVA if present
		let ip_rva = if (header & FH4_HAS_IP_TO_STATE) != 0 {
			if data.len() < offset + 4 { return Err(Error::Bounds); }
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[offset..offset + 4]);
			u32::from_le_bytes(buf)
		} else {
			0
		};

		// Parse Unwind Map with locations
		let mut unwind_map = Vec::new();
		let unwind_map_file_offset = if unwind_rva != 0 {
			pe.rva_to_file_offset(unwind_rva).ok()
		} else {
			None
		};
		
		if unwind_rva != 0 {
			let bytes = pe.slice_bytes(unwind_rva)?;
			let base_file_offset = pe.rva_to_file_offset(unwind_rva)?;
			let mut reader = UVarIntReader::new(bytes);
			let count = reader.read_u32()?;
			
			for _ in 0..count {
				let entry_start = bytes.len() - reader.ptr.len();
				let val = reader.read_u32()?;
				let type_ = (val & 3) as u8;
				let back_offset = (val >> 2) as i32;
				let next_offset = -back_offset;

				let action = if type_ == 3 {
					if reader.ptr.len() < 4 { return Err(Error::Bounds); }
					let mut buf = [0u8; 4];
					buf.copy_from_slice(&reader.ptr[0..4]);
					reader.ptr = &reader.ptr[4..];
					u32::from_le_bytes(buf)
				} else {
					0
				};
				
				let entry_end = bytes.len() - reader.ptr.len();
				
				let action_rva_file_offset = if type_ == 3 {
					Some(base_file_offset + entry_end - 4)
				} else {
					None
				};
				
				unwind_map.push(UnwindMapEntry4 {
					entry_offset: entry_start as u32,
					file_offset: base_file_offset + entry_start,
					encoded_size: entry_end - entry_start,
					type_,
					next_offset,
					action_rva: action,
					action_rva_file_offset,
				});
			}
		}

		// Parse Try Block Map with locations
		let mut try_block_map = Vec::new();
		let try_block_map_file_offset = if try_rva != 0 {
			pe.rva_to_file_offset(try_rva).ok()
		} else {
			None
		};
		
		if try_rva != 0 {
			let bytes = pe.slice_bytes(try_rva)?;
			let base_file_offset = pe.rva_to_file_offset(try_rva)?;
			let mut reader = UVarIntReader::new(bytes);
			let count = reader.read_u32()?;
			
			for _ in 0..count {
				let entry_start = bytes.len() - reader.ptr.len();
				let try_low = reader.read_u32()?;
				let try_high = reader.read_u32()?;
				let catch_high = reader.read_u32()?;
				
				if reader.ptr.len() < 4 { return Err(Error::Bounds); }
				let handlers_rva_offset = bytes.len() - reader.ptr.len();
				let mut buf = [0u8; 4];
				buf.copy_from_slice(&reader.ptr[0..4]);
				reader.ptr = &reader.ptr[4..];
				let handlers_rva = u32::from_le_bytes(buf);
				
				// Parse Handlers with locations
				let mut handlers = Vec::new();
				if handlers_rva != 0 {
					let h_bytes = pe.slice_bytes(handlers_rva)?;
					let h_base_offset = pe.rva_to_file_offset(handlers_rva)?;
					let mut h_reader = UVarIntReader::new(h_bytes);
					let h_count = h_reader.read_u32()?;
					
					for _ in 0..h_count {
						let h_entry_start = h_bytes.len() - h_reader.ptr.len();
						
						if h_reader.ptr.is_empty() { return Err(Error::Bounds); }
						let h_header = h_reader.ptr[0];
						h_reader.ptr = &h_reader.ptr[1..];

						let adj = h_reader.read_u32()?;
						
						let (type_desc_rva, type_desc_rva_file_offset) = if (h_header & 0x02) != 0 {
							let td_offset = h_bytes.len() - h_reader.ptr.len();
							if h_reader.ptr.len() < 4 { return Err(Error::Bounds); }
							let mut buf = [0u8; 4];
							buf.copy_from_slice(&h_reader.ptr[0..4]);
							h_reader.ptr = &h_reader.ptr[4..];
							(u32::from_le_bytes(buf), Some(h_base_offset + td_offset))
						} else {
							(0, None)
						};
						
						let catch_obj = if (h_header & 0x04) != 0 {
							h_reader.read_u32()?
						} else {
							0
						};
						
						let handler_rva_offset = h_bytes.len() - h_reader.ptr.len();
						if h_reader.ptr.len() < 4 { return Err(Error::Bounds); }
						let mut buf = [0u8; 4];
						buf.copy_from_slice(&h_reader.ptr[0..4]);
						h_reader.ptr = &h_reader.ptr[4..];
						let handler_rva = u32::from_le_bytes(buf);
						
						handlers.push(HandlerEntry4 {
							file_offset: h_base_offset + h_entry_start,
							header: h_header,
							adjectives: adj,
							type_desc_rva,
							type_desc_rva_file_offset,
							catch_obj_offset: catch_obj,
							handler_rva,
							handler_rva_file_offset: h_base_offset + handler_rva_offset,
						});
					}
				}
				
				try_block_map.push(TryBlockMapEntry4 {
					file_offset: base_file_offset + entry_start,
					try_low,
					try_high,
					catch_high,
					handlers_rva,
					handlers_rva_file_offset: base_file_offset + handlers_rva_offset,
					handlers,
				});
			}
		}

		// Parse IP to State Map with locations
		let mut ip_to_state_map = Vec::new();
		let ip_map_file_offset = if ip_rva != 0 {
			pe.rva_to_file_offset(ip_rva).ok()
		} else {
			None
		};
		
		if ip_rva != 0 {
			let bytes = pe.slice_bytes(ip_rva)?;
			let base_file_offset = pe.rva_to_file_offset(ip_rva)?;
			let mut reader = UVarIntReader::new(bytes);
			let count = reader.read_u32()?;
			
			let mut current_ip_offset = 0;
			
			for _ in 0..count {
				let entry_start = bytes.len() - reader.ptr.len();
				let delta = reader.read_u32()?;
				let raw_state = reader.read_u32()?;
				let entry_end = bytes.len() - reader.ptr.len();
				
				current_ip_offset += delta;
				let state = (raw_state as i32) - 1;
				
				ip_to_state_map.push(IpStateEntry4 {
					file_offset: base_file_offset + entry_start,
					encoded_size: entry_end - entry_start,
					ip_offset: current_ip_offset,
					delta,
					state,
				});
			}
		}

		Ok(FuncInfo4 {
			func_info_rva,
			func_info_file_offset,
			header,
			unwind_map_rva: unwind_rva,
			unwind_map_file_offset,
			unwind_map,
			try_block_map_rva: try_rva,
			try_block_map_file_offset,
			try_block_map,
			ip_map_rva: ip_rva,
			ip_map_file_offset,
			ip_to_state_map,
		})
	}
}

/// Attempts to parse FH4 data that may either be embedded directly or referenced indirectly.
///
/// Different exception handlers store FH4 data differently:
/// - `__CxxFrameHandler4`: stores RVA to FH4 data in exception_data
/// - `__GSHandlerCheck_EH4`: may embed FH4 data directly
///
/// This function tries both interpretations and returns the one that yields more
/// meaningful content (more map entries), since incorrect parsing typically results
/// in empty maps due to wrong flag interpretation.
pub fn try_parse_fh4<'a, P: Pe<'a>>(
	pe: P,
	data: &[u8],
	exception_data_rva: u32,
	exception_data_file_offset: usize,
) -> Result<FuncInfo4> {
	let direct_result = FuncInfo4::parse(pe, data, exception_data_rva, exception_data_file_offset);
	let indirect_result = try_parse_indirect_fh4(pe, data);

	match (&direct_result, &indirect_result) {
		(Ok(direct), Ok(indirect)) => {
			// Compare which interpretation yielded more data
			let direct_count = direct.ip_to_state_map.len()
				+ direct.unwind_map.len()
				+ direct.try_block_map.len();
			let indirect_count = indirect.ip_to_state_map.len()
				+ indirect.unwind_map.len()
				+ indirect.try_block_map.len();

			// Prefer the result with more content
			if indirect_count > direct_count {
				indirect_result
			} else {
				direct_result
			}
		}
		(Ok(_), Err(_)) => direct_result,
		(Err(_), Ok(_)) => indirect_result,
		(Err(e), Err(_)) => Err(e.clone()),
	}
}

/// Attempts to parse FH4 data that is referenced via an RVA stored in the exception data.
fn try_parse_indirect_fh4<'a, P: Pe<'a>>(pe: P, data: &[u8]) -> Result<FuncInfo4> {
	if data.len() < 4 {
		return Err(Error::Bounds);
	}
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&data[..4]);
	let rva = u32::from_le_bytes(buf);
	if rva == 0 {
		return Err(Error::Invalid);
	}
	let file_offset = pe.rva_to_file_offset(rva)?;
	let bytes = pe.slice_bytes(rva)?;
	FuncInfo4::parse(pe, bytes, rva, file_offset)
}

/// Extension trait for accessing FH4 data from unwind info.
pub trait UnwindInfoFh4Ext<'a, P: Pe<'a>> {
	/// Parse FH4 exception handling data from this unwind info.
	///
	/// Returns the parsed FuncInfo4 with file offset locations for patching.
	fn func_info4(&self) -> Result<FuncInfo4>;
	
	/// Get the RVA to the FuncInfo4 data.
	///
	/// Tries to determine if FH4 data is stored directly or via RVA indirection.
	fn func_info4_rva(&self) -> Result<u32>;
}

impl<'a, P: Pe<'a>> UnwindInfoFh4Ext<'a, P> for UnwindInfo<'a, P> {
	fn func_info4(&self) -> Result<FuncInfo4> {
		let data = self.exception_data()?;
		let exception_data_rva = self.exception_data_rva()?;
		let exception_data_file_offset = self.pe().rva_to_file_offset(exception_data_rva)?;
		try_parse_fh4(self.pe(), data, exception_data_rva, exception_data_file_offset)
	}
	
	fn func_info4_rva(&self) -> Result<u32> {
		// FH4 can be stored directly in exception_data or via RVA
		// Try to determine which based on parsing success
		let data = self.exception_data()?;
		let exception_data_rva = self.exception_data_rva()?;
		let exception_data_file_offset = self.pe().rva_to_file_offset(exception_data_rva)?;
		
		// First try direct interpretation
		if FuncInfo4::parse(self.pe(), data, exception_data_rva, exception_data_file_offset).is_ok() {
			// Data is stored directly in exception_data
			return Ok(exception_data_rva);
		}
		
		// Try indirect via RVA
		if data.len() >= 4 {
			let mut buf = [0u8; 4];
			buf.copy_from_slice(&data[..4]);
			let rva = u32::from_le_bytes(buf);
			if rva != 0 {
				let file_offset = self.pe().rva_to_file_offset(rva)?;
				if let Ok(bytes) = self.pe().slice_bytes(rva) {
					if FuncInfo4::parse(self.pe(), bytes, rva, file_offset).is_ok() {
						return Ok(rva);
					}
				}
			}
		}
		
		Err(Error::Invalid)
	}
}
