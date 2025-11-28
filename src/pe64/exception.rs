/*!
Exception Directory.
*/

use std::cmp::Ordering;
use std::{fmt, iter, mem, slice};

use crate::{Error, Result};

use super::image::*;
use super::Pe;
use crate::pe64::exception_fh3::FH3_MAGIC;

//----------------------------------------------------------------

/// Type of exception handler detected from unwind info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerType {
	/// FH3 (__CxxFrameHandler3) - C++ exception handling with fixed-size structures
	Fh3,
	/// FH4 (__CxxFrameHandler4) - C++ exception handling with variable-length encoding
	Fh4,
	/// CSEH (__C_specific_handler) - C structured exception handling
	Cseh,
	/// Unknown handler type
	Unknown,
}

//----------------------------------------------------------------

/// Exception Directory.
///
/// For more information see the [module-level documentation](index.html).
#[derive(Copy, Clone)]
pub struct Exception<'a, P> {
	pe: P,
	image: &'a [RUNTIME_FUNCTION],
}
impl<'a, P: Pe<'a>> Exception<'a, P> {
	pub(crate) fn try_from(pe: P) -> Result<Exception<'a, P>> {
		let datadir = pe.data_directory().get(IMAGE_DIRECTORY_ENTRY_EXCEPTION).ok_or(Error::Bounds)?;
		let len = datadir.Size as usize / mem::size_of::<RUNTIME_FUNCTION>();
		let rem = datadir.Size as usize % mem::size_of::<RUNTIME_FUNCTION>();
		if rem != 0 {
			return Err(Error::Invalid);
		}
		let image = pe.derva_slice(datadir.VirtualAddress, len)?;
		Ok(Exception { pe, image })
	}
	/// Gets the PE instance.
	pub fn pe(&self) -> P {
		self.pe
	}
	/// Returns the functions slice.
	pub fn image(&self) -> &'a [RUNTIME_FUNCTION] {
		self.image
	}
	/// Checks if the function table is sorted.
	///
	/// The PE specification says that the list of runtime functions should be sorted to allow binary search.
	/// This function checks if the runtime functions are actually sorted, if not then lookups may fail unexpectedly.
	pub fn check_sorted(&self) -> bool {
		#[rustfmt::skip]
		fn check_sorted(window: &[RUNTIME_FUNCTION]) -> bool {
			return
				window[0].BeginAddress <= window[0].EndAddress &&
				window[0].EndAddress <= window[1].BeginAddress &&
				window[1].BeginAddress <= window[1].EndAddress;
		}
		self.image.windows(2).all(check_sorted)
	}
	/// Gets an iterator over the function records.
	pub fn functions(&self) -> iter::Map<slice::Iter<'a, RUNTIME_FUNCTION>, impl Clone + FnMut(&'a RUNTIME_FUNCTION) -> Function<'a, P>> {
		let pe = self.pe;
		self.image.iter().map(move |image| Function { pe, image })
	}
	/// Finds the index of the function for the given program counter.
	pub fn index_of(&self, pc: Rva) -> std::result::Result<usize, usize> {
		self.image.binary_search_by(|rf| {
			if pc < rf.BeginAddress {
				Ordering::Less
			}
			else if pc > rf.EndAddress {
				Ordering::Greater
			}
			else {
				Ordering::Equal
			}
		})
	}
	/// Finds the function for the given 'program counter' address.
	///
	/// The function records are sorted by their address allowing binary search for the record.
	pub fn lookup_function_entry(&self, pc: Rva) -> Option<Function<'a, P>> {
		self.index_of(pc)
			.map(|index| Function {
				pe: self.pe,
				image: &self.image[index],
			})
			.ok()
	}
}
#[rustfmt::skip]
impl<'a, P: Pe<'a>> fmt::Debug for Exception<'a, P> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(f, "Exception {{")?;
		writeln!(f, "    functions.len: {},", self.image.len())?;
		writeln!(f, "    functions: [")?;
		for (index, function) in self.functions().enumerate() {
			let image = function.image();
			let size = image.EndAddress.saturating_sub(image.BeginAddress);
			writeln!(
				f,
				"        [{:04}] begin=0x{:08x} end=0x{:08x} size=0x{:04x} unwind=0x{:08x},",
				index,
				image.BeginAddress,
				image.EndAddress,
				size,
				image.UnwindData
			)?;
		}
		writeln!(f, "    ]")?;
		write!(f, "}}")
	}
}

//----------------------------------------------------------------

/// Runtime function.
#[derive(Copy, Clone)]
pub struct Function<'a, P> {
	pe: P,
	image: &'a RUNTIME_FUNCTION,
}
impl<'a, P: Pe<'a>> Function<'a, P> {
	/// Gets the PE instance.
	pub fn pe(&self) -> P {
		self.pe
	}
	/// Returns the underlying runtime function image.
	pub fn image(&self) -> &'a RUNTIME_FUNCTION {
		self.image
	}
	/// Gets the function bytes.
	pub fn bytes(&self) -> Result<&'a [u8]> {
		let len = if self.image.BeginAddress > self.image.EndAddress {
			return Err(Error::Overflow);
		}
		else {
			(self.image.EndAddress - self.image.BeginAddress) as usize
		};
		self.pe.derva_slice(self.image.BeginAddress, len)
	}
	/// Gets the unwind info.
	pub fn unwind_info(&self) -> Result<UnwindInfo<'a, P>> {
		// Read as many bytes as we can for interpretation
		let bytes = self.pe.slice(
			self.image.UnwindData,
			mem::size_of::<UNWIND_INFO>(),
			if cfg!(feature = "unsafe_alignment") { 1 } else { mem::align_of::<UNWIND_INFO>() },
		)?;
		let image = unsafe { &*(bytes.as_ptr() as *const UNWIND_INFO) };
		// Calculate actual size including size of unwind codes
		let min_size_of = mem::size_of::<UNWIND_INFO>() + mem::size_of::<UNWIND_CODE>() * image.CountOfCodes as usize;
		if bytes.len() < min_size_of {
			return Err(Error::Bounds);
		}
		// Ok
		Ok(UnwindInfo { pe: self.pe, image })
	}
}
#[rustfmt::skip]
impl<'a, P: Pe<'a>> fmt::Debug for Function<'a, P> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("Function")
			.field("bytes.len", &self.bytes().map(<[_]>::len))
			.finish()
	}
}

//----------------------------------------------------------------

/// Unwind info.
#[derive(Copy, Clone)]
pub struct UnwindInfo<'a, P> {
	pe: P,
	image: &'a UNWIND_INFO,
}
impl<'a, P: Pe<'a>> UnwindInfo<'a, P> {
	/// Gets the PE instance.
	pub fn pe(&self) -> P {
		self.pe
	}
	/// Returns the underlying unwind info image.
	pub fn image(&self) -> &'a UNWIND_INFO {
		self.image
	}
	pub fn version(&self) -> u8 {
		self.image.VersionFlags & 0b00000111
	}
	pub fn flags(&self) -> u8 {
		self.image.VersionFlags >> 3
	}
	pub fn size_of_prolog(&self) -> usize {
		self.image.SizeOfProlog as usize
	}
	pub fn frame_register(&self) -> u8 {
		self.image.FrameRegisterOffset & 0b00001111
	}
	pub fn frame_offset(&self) -> u8 {
		self.image.FrameRegisterOffset >> 4
	}
	pub fn unwind_codes(&self) -> &'a [UNWIND_CODE] {
		let len = self.image.CountOfCodes as usize;
		unsafe { slice::from_raw_parts(self.image.UnwindCode.as_ptr(), len) }
	}
	pub fn handler(&self) -> Option<u32> {
		let flags = self.flags();
		if (flags & UNW_FLAG_EHANDLER) != 0 || (flags & UNW_FLAG_UHANDLER) != 0 {
			let codes_len = self.image.CountOfCodes as usize;
			let aligned_codes_len = if codes_len % 2 == 0 { codes_len } else { codes_len + 1 };
			let offset = mem::size_of::<UNWIND_INFO>() + aligned_codes_len * mem::size_of::<UNWIND_CODE>();

			// Get the slice from pe.image() that corresponds to UnwindInfo
			let image_bytes = self.pe.image();
			let info_ptr = self.image as *const _ as *const u8;
			let start_ptr = image_bytes.as_ptr();

			// Safety: assumes info_ptr points within image_bytes
			// We can verify this or trust it because UnwindInfo is created from pe.slice
			let start_offset = unsafe { info_ptr.offset_from(start_ptr) } as usize;

			if start_offset + offset + 4 <= image_bytes.len() {
				let handler_bytes = &image_bytes[start_offset + offset..start_offset + offset + 4];
				let mut rva_bytes = [0u8; 4];
				rva_bytes.copy_from_slice(handler_bytes);
				Some(u32::from_le_bytes(rva_bytes))
			}
			else {
				None
			}
		}
		else {
			None
		}
	}
	pub fn exception_data(&self) -> Result<&'a [u8]> {
		let flags = self.flags();
		if (flags & UNW_FLAG_EHANDLER) != 0 || (flags & UNW_FLAG_UHANDLER) != 0 {
			let codes_len = self.image.CountOfCodes as usize;
			let aligned_codes_len = if codes_len % 2 == 0 { codes_len } else { codes_len + 1 };
			let offset = mem::size_of::<UNWIND_INFO>() + aligned_codes_len * mem::size_of::<UNWIND_CODE>() + 4;

			let image_bytes = self.pe.image();
			let info_ptr = self.image as *const _ as *const u8;
			let start_ptr = image_bytes.as_ptr();
			let start_offset = unsafe { info_ptr.offset_from(start_ptr) } as usize;

			if start_offset + offset <= image_bytes.len() {
				Ok(&image_bytes[start_offset + offset..])
			}
			else {
				Err(Error::Bounds)
			}
		}
		else {
			Err(Error::Bounds)
		}
	}
	
	/// Detects the type of exception handler based on exception data contents.
	///
	/// This examines the exception data to determine whether this function uses:
	/// - FH3 (__CxxFrameHandler3): C++ EH with fixed-size structures, magic 0x19930522
	/// - FH4 (__CxxFrameHandler4): C++ EH with variable-length encoding
	/// - CSEH (__C_specific_handler): C structured exception handling
	///
	/// # Arguments
	/// * `func_begin` - Begin address of the function (for CSEH validation)
	/// * `func_end` - End address of the function (for CSEH validation)
	pub fn handler_type(&self, func_begin: u32, func_end: u32) -> HandlerType {
		let data = match self.exception_data() {
			Ok(d) => d,
			Err(_) => return HandlerType::Unknown,
		};
		
		if data.len() < 4 {
			return HandlerType::Unknown;
		}
		
		// Read first 4 bytes
		let mut buf = [0u8; 4];
		buf.copy_from_slice(&data[..4]);
		let first_dword = u32::from_le_bytes(buf);
		
		// Check for FH3: first DWORD is an RVA to FuncInfo3 structure
		// We need to dereference it and check if the magic is present
		if first_dword != 0 {
			if let Ok(bytes) = self.pe.slice_bytes(first_dword) {
				if bytes.len() >= 4 {
					let mut magic_buf = [0u8; 4];
					magic_buf.copy_from_slice(&bytes[..4]);
					let magic = u32::from_le_bytes(magic_buf);
					if magic == FH3_MAGIC {
						return HandlerType::Fh3;
					}
				}
			}
		}
		
		// Check for CSEH: first DWORD is count, followed by valid scope entries
		// Count should be reasonable (1-1000) and entries should have valid RVAs
		if first_dword > 0 && first_dword < 1000 {
			let entry_size = 16;
			let required_len = 4 + (first_dword as usize) * entry_size;
			if data.len() >= required_len {
				// Check if entries look like valid scope table entries
				// Each entry has: begin_addr, end_addr, handler_addr, jump_target
				// begin_addr and end_addr should be within or near the function bounds
				let mut valid_cseh = true;
				for i in 0..first_dword as usize {
					let offset = 4 + i * entry_size;
					let mut entry_buf = [0u8; 4];
					
					entry_buf.copy_from_slice(&data[offset..offset + 4]);
					let begin = u32::from_le_bytes(entry_buf);
					
					entry_buf.copy_from_slice(&data[offset + 4..offset + 8]);
					let end = u32::from_le_bytes(entry_buf);
					
					// Scope entry addresses should be within or close to function bounds
					// Allow some slack for funclets
					let func_size = func_end.saturating_sub(func_begin);
					let slack = func_size.max(0x1000);
					
					if begin < func_begin.saturating_sub(slack) || begin > func_end.saturating_add(slack) {
						valid_cseh = false;
						break;
					}
					if end < begin || end > func_end.saturating_add(slack) {
						valid_cseh = false;
						break;
					}
				}
				if valid_cseh {
					return HandlerType::Cseh;
				}
			}
		}
		
		// If we get here, it's likely FH4 (the default for modern MSVC C++ EH)
		// FH4 uses variable-length encoding and may have minimal headers
		// without any map RVA flags set for simple functions
		HandlerType::Fh4
	}
}
impl<'a, P: Pe<'a>> fmt::Debug for UnwindInfo<'a, P> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("UnwindInfo")
			.field("version", &self.version())
			.field("flags", &self.flags())
			.field("size_of_prolog", &self.size_of_prolog())
			.field("frame_register", &self.frame_register())
			.field("frame_offset", &self.frame_offset())
			.field("unwind_codes.len", &self.unwind_codes().len())
			.finish()
	}
}

//----------------------------------------------------------------

#[cfg(test)]
pub(crate) fn test<'a, P: Pe<'a>>(pe: P) -> Result<()> {
	let exception = pe.exception()?;
	let _ = format!("{:?}", exception);

	let sorted = exception.check_sorted();

	for (index, function) in exception.functions().enumerate() {
		let _ = format!("{:?}", function);
		let _bytes = function.bytes();

		if sorted {
			for pc in function.image().BeginAddress..function.image().EndAddress {
				assert_eq!(exception.index_of(pc), Ok(index));
			}
		}

		if let Ok(unwind_info) = function.unwind_info() {
			let _ = format!("{:?}", unwind_info);
			let _version = unwind_info.version();
			let _flags = unwind_info.flags();
			let _size_of_prolog = unwind_info.size_of_prolog();
			let _frame_register = unwind_info.frame_register();
			let _frame_offset = unwind_info.frame_offset();
			let _unwind_codes = unwind_info.unwind_codes();
		}
	}

	Ok(())
}
