/*!
Unwind Code decoding for x64 PE files.

This module provides functionality to decode the raw UNWIND_CODE structures
into a higher-level representation with resolved operands.
*/

use std::fmt;

use super::image::*;
use crate::stringify::UnwindOp;

//----------------------------------------------------------------
// Register names
//----------------------------------------------------------------

/// Register names for x64 unwind codes
const REG_NAMES: [&str; 16] = [
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

/// XMM register names
const XMM_NAMES: [&str; 16] = [
	"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
	"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
];

//----------------------------------------------------------------
// Decoded unwind codes
//----------------------------------------------------------------

/// A decoded unwind code with all operands resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedUnwindCode {
	/// Offset in prolog where this code takes effect
	pub code_offset: u8,
	/// The unwind operation
	pub operation: DecodedUnwindOp,
}

/// Decoded unwind operation with operands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedUnwindOp {
	/// UWOP_PUSH_NONVOL: Push a nonvolatile register
	PushNonVol {
		/// Register index (0-15)
		register: u8,
	},
	/// UWOP_ALLOC_LARGE: Allocate a large area on the stack
	AllocLarge {
		/// Size in bytes
		size: u32,
	},
	/// UWOP_ALLOC_SMALL: Allocate a small area on the stack (8-128 bytes)
	AllocSmall {
		/// Size in bytes
		size: u32,
	},
	/// UWOP_SET_FPREG: Establish frame pointer register
	SetFpReg,
	/// UWOP_SAVE_NONVOL: Save a nonvolatile register on the stack
	SaveNonVol {
		/// Register index (0-15)
		register: u8,
		/// Offset from RSP (in bytes)
		offset: u32,
	},
	/// UWOP_SAVE_NONVOL_FAR: Save a nonvolatile register (large offset)
	SaveNonVolFar {
		/// Register index (0-15)
		register: u8,
		/// Offset from RSP (in bytes)
		offset: u32,
	},
	/// UWOP_SAVE_XMM128: Save an XMM register
	SaveXmm128 {
		/// XMM register index (0-15)
		register: u8,
		/// Offset from RSP (in bytes)
		offset: u32,
	},
	/// UWOP_SAVE_XMM128_FAR: Save an XMM register (large offset)
	SaveXmm128Far {
		/// XMM register index (0-15)
		register: u8,
		/// Offset from RSP (in bytes)
		offset: u32,
	},
	/// UWOP_PUSH_MACHFRAME: Push a machine frame
	PushMachFrame {
		/// 1 if error code is present, 0 otherwise
		error_code: bool,
	},
	/// Unknown or unsupported operation
	Unknown {
		/// Raw operation code
		op: u8,
		/// Raw info field
		info: u8,
	},
}

impl DecodedUnwindCode {
	/// Format register name for display
	pub fn register_name(index: u8) -> &'static str {
		REG_NAMES.get(index as usize).copied().unwrap_or("???")
	}

	/// Format XMM register name for display
	pub fn xmm_name(index: u8) -> &'static str {
		XMM_NAMES.get(index as usize).copied().unwrap_or("???")
	}
}

impl fmt::Display for DecodedUnwindCode {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:02X}: ", self.code_offset)?;
		match &self.operation {
			DecodedUnwindOp::PushNonVol { register } => {
				let op_str = UnwindOp(UWOP_PUSH_NONVOL).to_str().unwrap_or("PUSH_NONVOL");
				write!(f, "{}, register={}", op_str.to_uppercase(), DecodedUnwindCode::register_name(*register))
			}
			DecodedUnwindOp::AllocLarge { size } => {
				let op_str = UnwindOp(UWOP_ALLOC_LARGE).to_str().unwrap_or("ALLOC_LARGE");
				write!(f, "{}, size=0x{:X}", op_str.to_uppercase(), size)
			}
			DecodedUnwindOp::AllocSmall { size } => {
				let op_str = UnwindOp(UWOP_ALLOC_SMALL).to_str().unwrap_or("ALLOC_SMALL");
				write!(f, "{}, size=0x{:X}", op_str.to_uppercase(), size)
			}
			DecodedUnwindOp::SetFpReg => {
				let op_str = UnwindOp(UWOP_SET_FPREG).to_str().unwrap_or("SET_FPREG");
				write!(f, "{}", op_str.to_uppercase())
			}
			DecodedUnwindOp::SaveNonVol { register, offset } => {
				let op_str = UnwindOp(UWOP_SAVE_NONVOL).to_str().unwrap_or("SAVE_NONVOL");
				write!(f, "{}, register={}, offset=0x{:X}", op_str.to_uppercase(), DecodedUnwindCode::register_name(*register), offset)
			}
			DecodedUnwindOp::SaveNonVolFar { register, offset } => {
				let op_str = UnwindOp(UWOP_SAVE_NONVOL_FAR).to_str().unwrap_or("SAVE_NONVOL_FAR");
				write!(f, "{}, register={}, offset=0x{:X}", op_str.to_uppercase(), DecodedUnwindCode::register_name(*register), offset)
			}
			DecodedUnwindOp::SaveXmm128 { register, offset } => {
				let op_str = UnwindOp(UWOP_SAVE_XMM128).to_str().unwrap_or("SAVE_XMM128");
				write!(f, "{}, register={}, offset=0x{:X}", op_str.to_uppercase(), DecodedUnwindCode::xmm_name(*register), offset)
			}
			DecodedUnwindOp::SaveXmm128Far { register, offset } => {
				let op_str = UnwindOp(UWOP_SAVE_XMM128_FAR).to_str().unwrap_or("SAVE_XMM128_FAR");
				write!(f, "{}, register={}, offset=0x{:X}", op_str.to_uppercase(), DecodedUnwindCode::xmm_name(*register), offset)
			}
			DecodedUnwindOp::PushMachFrame { error_code } => {
				let op_str = UnwindOp(UWOP_PUSH_MACHFRAME).to_str().unwrap_or("PUSH_MACHFRAME");
				write!(f, "{}, error_code={}", op_str.to_uppercase(), if *error_code { 1 } else { 0 })
			}
			DecodedUnwindOp::Unknown { op, info } => {
				write!(f, "UNKNOWN(op={}, info={})", op, info)
			}
		}
	}
}

/// Decode raw unwind codes into a higher-level representation.
///
/// Returns a vector of decoded unwind codes, consuming multiple raw codes as needed
/// for operations that require additional slots.
pub fn decode_unwind_codes(raw_codes: &[UNWIND_CODE]) -> Vec<DecodedUnwindCode> {
	let mut result = Vec::new();
	let mut i = 0;
	
	while i < raw_codes.len() {
		let code = &raw_codes[i];
		let op = code.UnwindOpInfo & 0x0F;
		let info = code.UnwindOpInfo >> 4;
		let code_offset = code.CodeOffset;
		
		let (operation, slots_consumed) = match op {
			UWOP_PUSH_NONVOL => {
				(DecodedUnwindOp::PushNonVol { register: info }, 1)
			}
			UWOP_ALLOC_LARGE => {
				// info == 0: size in next slot * 8
				// info == 1: size in next 2 slots (raw 32-bit value)
				if info == 0 && i + 1 < raw_codes.len() {
					let next = &raw_codes[i + 1];
					let size_raw = (next.CodeOffset as u32) | ((next.UnwindOpInfo as u32) << 8);
					let size = size_raw * 8;
					(DecodedUnwindOp::AllocLarge { size }, 2)
				} else if info == 1 && i + 2 < raw_codes.len() {
					let next1 = &raw_codes[i + 1];
					let next2 = &raw_codes[i + 2];
					let size = (next1.CodeOffset as u32) | ((next1.UnwindOpInfo as u32) << 8)
						| ((next2.CodeOffset as u32) << 16) | ((next2.UnwindOpInfo as u32) << 24);
					(DecodedUnwindOp::AllocLarge { size }, 3)
				} else {
					(DecodedUnwindOp::Unknown { op, info }, 1)
				}
			}
			UWOP_ALLOC_SMALL => {
				let size = (info as u32 + 1) * 8;
				(DecodedUnwindOp::AllocSmall { size }, 1)
			}
			UWOP_SET_FPREG => {
				(DecodedUnwindOp::SetFpReg, 1)
			}
			UWOP_SAVE_NONVOL => {
				if i + 1 < raw_codes.len() {
					let next = &raw_codes[i + 1];
					let offset_raw = (next.CodeOffset as u32) | ((next.UnwindOpInfo as u32) << 8);
					let offset = offset_raw * 8;
					(DecodedUnwindOp::SaveNonVol { register: info, offset }, 2)
				} else {
					(DecodedUnwindOp::Unknown { op, info }, 1)
				}
			}
			UWOP_SAVE_NONVOL_FAR => {
				if i + 2 < raw_codes.len() {
					let next1 = &raw_codes[i + 1];
					let next2 = &raw_codes[i + 2];
					let offset = (next1.CodeOffset as u32) | ((next1.UnwindOpInfo as u32) << 8)
						| ((next2.CodeOffset as u32) << 16) | ((next2.UnwindOpInfo as u32) << 24);
					(DecodedUnwindOp::SaveNonVolFar { register: info, offset }, 3)
				} else {
					(DecodedUnwindOp::Unknown { op, info }, 1)
				}
			}
			UWOP_SAVE_XMM128 => {
				if i + 1 < raw_codes.len() {
					let next = &raw_codes[i + 1];
					let offset_raw = (next.CodeOffset as u32) | ((next.UnwindOpInfo as u32) << 8);
					let offset = offset_raw * 16;
					(DecodedUnwindOp::SaveXmm128 { register: info, offset }, 2)
				} else {
					(DecodedUnwindOp::Unknown { op, info }, 1)
				}
			}
			UWOP_SAVE_XMM128_FAR => {
				if i + 2 < raw_codes.len() {
					let next1 = &raw_codes[i + 1];
					let next2 = &raw_codes[i + 2];
					let offset = (next1.CodeOffset as u32) | ((next1.UnwindOpInfo as u32) << 8)
						| ((next2.CodeOffset as u32) << 16) | ((next2.UnwindOpInfo as u32) << 24);
					(DecodedUnwindOp::SaveXmm128Far { register: info, offset }, 3)
				} else {
					(DecodedUnwindOp::Unknown { op, info }, 1)
				}
			}
			UWOP_PUSH_MACHFRAME => {
				(DecodedUnwindOp::PushMachFrame { error_code: info != 0 }, 1)
			}
			_ => {
				(DecodedUnwindOp::Unknown { op, info }, 1)
			}
		};
		
		result.push(DecodedUnwindCode {
			code_offset,
			operation,
		});
		
		i += slots_consumed;
	}
	
	result
}

