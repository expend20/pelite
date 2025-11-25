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

/// Function Info 4 (FH4) structure for C++ exception handling.
#[derive(Debug, Clone)]
pub struct FuncInfo4 {
	pub header: u8,
	pub unwind_map: Vec<UnwindMapEntry>,
	pub try_block_map: Vec<TryBlockMapEntry>,
	pub ip_to_state_map: Vec<IpStateEntry>,
}

#[derive(Debug, Clone)]
pub struct UnwindMapEntry {
	pub offset: u32,
	pub type_: u8,
	pub next_offset: i32,
	pub action: u32,
}

#[derive(Debug, Clone)]
pub struct TryBlockMapEntry {
	pub try_low: u32,
	pub try_high: u32,
	pub catch_high: u32,
	pub handlers_rva: u32,
	pub handlers: Vec<HandlerEntry>,
}

#[derive(Debug, Clone)]
pub struct HandlerEntry {
	pub unknown1: u32, // The 07 byte
	pub adjectives: u32,
	pub type_desc_rva: u32,
	pub catch_obj_offset: u32,
	pub handler_rva: u32,
}

#[derive(Debug, Clone)]
pub struct IpStateEntry {
	pub ip_offset: u32, // Accumulated offset
	pub delta: u32,
	pub state: i32,
}

impl FuncInfo4 {
	pub fn parse<'a, P: Pe<'a>>(pe: P, data: &[u8]) -> Result<FuncInfo4> {
		if data.len() < 13 {
			return Err(Error::Bounds);
		}

		let header = data[0];
		// Read 3 u32s (unaligned)
		let mut buf = [0u8; 4];
		buf.copy_from_slice(&data[1..5]);
		let unwind_rva = u32::from_le_bytes(buf);
		buf.copy_from_slice(&data[5..9]);
		let try_rva = u32::from_le_bytes(buf);
		buf.copy_from_slice(&data[9..13]);
		let ip_rva = u32::from_le_bytes(buf);

		// Parse Unwind Map
		let mut unwind_map = Vec::new();
		if unwind_rva != 0 {
			let bytes = pe.slice_bytes(unwind_rva)?;
			let mut reader = UVarIntReader::new(bytes);
			let count = reader.read_u32()?;
			
			// We need to track offset from start of entries (after count)
			// reader.ptr is advanced. We can calculate offset.
			
			for _ in 0..count {
				let current_offset = bytes.len() - reader.ptr.len(); // Absolute offset
				let val = reader.read_u32()?;
				let type_ = (val & 3) as u8;
				let back_offset = (val >> 2) as i32;
				
				// Calculate Next Offset
				// Logic: relative to the START of entries?
				// Or relative to current byte?
				// Let's assume it's just `-back_offset`.
				let next_offset = -back_offset;

				let action = if type_ == 3 {
					// Read RVA (4 bytes)
					if reader.ptr.len() < 4 { return Err(Error::Bounds); }
					let mut buf = [0u8; 4];
					buf.copy_from_slice(&reader.ptr[0..4]);
					reader.ptr = &reader.ptr[4..];
					u32::from_le_bytes(buf)
				} else {
					0
				};

				unwind_map.push(UnwindMapEntry {
					offset: current_offset as u32,
					type_,
					next_offset,
					action,
				});
			}
		}

		// Parse Try Block Map
		let mut try_block_map = Vec::new();
		if try_rva != 0 {
			let bytes = pe.slice_bytes(try_rva)?;
			let mut reader = UVarIntReader::new(bytes);
			let count = reader.read_u32()?;
			
			for _ in 0..count {
				let try_low = reader.read_u32()?;
				let try_high = reader.read_u32()?;
				let catch_high = reader.read_u32()?;
				// Read Handler Array RVA (4 bytes inline? No, UVarInt + RVA?)
				// Example: 6A 9D 00 00. It's 4 bytes.
				if reader.ptr.len() < 4 { return Err(Error::Bounds); }
				let mut buf = [0u8; 4];
				buf.copy_from_slice(&reader.ptr[0..4]);
				reader.ptr = &reader.ptr[4..];
				let handlers_rva = u32::from_le_bytes(buf);
				
				// Parse Handlers
				let mut handlers = Vec::new();
				if handlers_rva != 0 {
					let h_bytes = pe.slice_bytes(handlers_rva)?;
					let mut h_reader = UVarIntReader::new(h_bytes);
					let h_count = h_reader.read_u32()?;
					
					for _ in 0..h_count {
						// First field seems to be a generic u8 or flags, not UVarInt?
						// In the example: 07 12 ...
						// 07 has bit 0 set, so if UVarInt it consumes next byte.
						// But next byte 12 is Adjectives (yielding 9).
						// So we must read 07 as a raw byte.
						if h_reader.ptr.is_empty() { return Err(Error::Bounds); }
						let u1 = h_reader.ptr[0] as u32;
						h_reader.ptr = &h_reader.ptr[1..];

						let adj = h_reader.read_u32()?;
						
						// Type Desc RVA
						if h_reader.ptr.len() < 4 { return Err(Error::Bounds); }
						let mut buf = [0u8; 4];
						buf.copy_from_slice(&h_reader.ptr[0..4]);
						h_reader.ptr = &h_reader.ptr[4..];
						let type_desc_rva = u32::from_le_bytes(buf);
						
						let catch_obj = h_reader.read_u32()?;
						
						// Handler RVA
						if h_reader.ptr.len() < 4 { return Err(Error::Bounds); }
						let mut buf = [0u8; 4];
						buf.copy_from_slice(&h_reader.ptr[0..4]);
						h_reader.ptr = &h_reader.ptr[4..];
						let handler_rva = u32::from_le_bytes(buf);
						
						handlers.push(HandlerEntry {
							unknown1: u1,
							adjectives: adj,
							type_desc_rva,
							catch_obj_offset: catch_obj,
							handler_rva,
						});
					}
				}
				
				try_block_map.push(TryBlockMapEntry {
					try_low,
					try_high,
					catch_high,
					handlers_rva,
					handlers,
				});
			}
		}

		// Parse IP to State Map
		let mut ip_to_state_map = Vec::new();
		if ip_rva != 0 {
			let bytes = pe.slice_bytes(ip_rva)?;
			let mut reader = UVarIntReader::new(bytes);
			let count = reader.read_u32()?;
			
			let mut current_ip_offset = 0;
			
			for _ in 0..count {
				let delta = reader.read_u32()?;
				let raw_state = reader.read_u32()?;
				
				current_ip_offset += delta;
				// State is encoded as (State + 1)
				// read_u32 already decodes the value (b >> 1)
				let state = (raw_state as i32) - 1;
				
				ip_to_state_map.push(IpStateEntry {
					ip_offset: current_ip_offset,
					delta,
					state,
				});
			}
		}

		Ok(FuncInfo4 {
			header,
			unwind_map,
			try_block_map,
			ip_to_state_map,
		})
	}
}

/// Attempts to parse FH4 data that may either be embedded directly or referenced indirectly.
pub fn try_parse_fh4<'a, P: Pe<'a>>(pe: P, data: &[u8]) -> Result<FuncInfo4> {
	match FuncInfo4::parse(pe, data) {
		Ok(fh4) => Ok(fh4),
		Err(_) => try_parse_indirect_fh4(pe, data),
	}
}

/// Attempts to parse FH4 data that is referenced via an RVA stored in the exception data.
pub fn try_parse_indirect_fh4<'a, P: Pe<'a>>(pe: P, data: &[u8]) -> Result<FuncInfo4> {
	if data.len() < 4 {
		return Err(Error::Bounds);
	}
	let mut buf = [0u8; 4];
	buf.copy_from_slice(&data[..4]);
	let rva = u32::from_le_bytes(buf);
	if rva == 0 {
		return Err(Error::Invalid);
	}
	let bytes = pe.slice_bytes(rva)?;
	FuncInfo4::parse(pe, bytes)
}

/// Extension trait for accessing FH4 data from unwind info.
pub trait UnwindInfoFh4Ext<'a, P: Pe<'a>> {
	fn func_info4(&self) -> Result<FuncInfo4>;
}

impl<'a, P: Pe<'a>> UnwindInfoFh4Ext<'a, P> for UnwindInfo<'a, P> {
	fn func_info4(&self) -> Result<FuncInfo4> {
		let data = self.exception_data()?;
		try_parse_fh4(self.pe(), data)
	}
}

