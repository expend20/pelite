/*!
Dumps all PE related headers.
 */

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use pelite::image::IMAGE_FILE_MACHINE_ARM64;
use pelite::pe64::Pe;
use pelite::{FileMap, PeFile, Wrap};

//----------------------------------------------------------------

const HELP_TEXT: &str = "
NAME:
  pedump - Inspect PE binary files.

SYNOPSIS:
  pedump FILEPATH
         [-h | --help]
         [-d | --dos]
         [-n | --headers]
         [-s | --sections]
         [-i | --imports]
         [-e | --exports]
         [-r | --relocs]
         [-t | --tls]
         [-c | --exceptions]
         [-x | --resources]
         [-g | --debug-info]

DESCRIPTION:
  Inspect and dump the contents of windows executable files.

OPTIONS:
  -d, --dos
      Print the DOS header and stub.

  -n, --headers
      Print the NT headers.

  -s, --sections
      Print the section headers.

  -i, --imports
      Print the imported symbols.

  -e, --exports
      Print the exported symbols.

  -r, --relocs
      Print the relocation table.

  -l, --load-config
      Prints the load config.

  -t, --tls
      Print the TLS directory.

  -c, --exceptions
      Print the exception directory.

  -x, --resources
      Print the embedded resource filesystem.

  -g, --debug-info
      Print debug information.
";

const SEPARATOR: &'static str = "----------------------------------------------------------------\n";

//----------------------------------------------------------------

const NO_INPUT_VAL: &'static str = "missing path to input binary";
const INVALID_ARG: &'static str = "invalid argument was given";

#[derive(Debug)]
struct Parameters {
	path: PathBuf,
	_hex: bool,
	dos: bool,
	nt: bool,
	sections: bool,
	imports: bool,
	exports: bool,
	relocs: bool,
	load_config: bool,
	tls: bool,
	exceptions: bool,
	resources: bool,
	debug_info: bool,
}

impl Default for Parameters {
	fn default() -> Parameters {
		// Initialize the default arguments of the program
		let mut vars = Parameters {
			path: PathBuf::new(),
			_hex: false,
			dos: false,
			nt: false,
			sections: false,
			imports: false,
			exports: false,
			relocs: false,
			load_config: false,
			tls: false,
			exceptions: false,
			resources: false,
			debug_info: false,
		};

		// Get args and print help text
		let mut args = env::args_os();
		let (_, mut args) = (args.next(), args.peekable());

		if args.peek().is_none() {
			print!("{}", HELP_TEXT);
			process::exit(0);
		}

		// Get the input binary path
		vars.path = args
			.next()
			.map(|path| PathBuf::from(path))
			.map_or(None, |path| {
				if path.starts_with("-") {
					None
				}
				else {
					Some(path)
				}
			})
			.unwrap_or_else(|| abort(NO_INPUT_VAL));

		// Parse the options for the program
		while let Some(arg) = args.next() {
			let arg = arg.into_string().unwrap();
			if arg.starts_with("--") {
				match arg.as_str() {
					"--dos" => vars.dos = true,
					"--nt" => vars.nt = true,
					"--sections" => vars.sections = true,
					"--imports" => vars.imports = true,
					"--exports" => vars.exports = true,
					"--relocs" => vars.relocs = true,
					"--load-config" => vars.load_config = true,
					"--tls" => vars.tls = true,
					"--exceptions" => vars.exceptions = true,
					"--resources" => vars.resources = true,
					"--debug-info" => vars.debug_info = true,
					_ => abort(INVALID_ARG),
				}
			}
			else if arg.starts_with("-") {
				let mut it = arg.chars();
				it.next();
				while let Some(opt) = it.next() {
					match opt {
						'd' => vars.dos = true,
						'n' => vars.nt = true,
						's' => vars.sections = true,
						'i' => vars.imports = true,
						'e' => vars.exports = true,
						'r' => vars.relocs = true,
						'l' => vars.load_config = true,
						't' => vars.tls = true,
						'c' => vars.exceptions = true,
						'x' => vars.resources = true,
						'g' => vars.debug_info = true,
						_ => abort(INVALID_ARG),
					}
				}
			}
			else {
				abort(INVALID_ARG);
			}
		}

		vars
	}
}

//----------------------------------------------------------------

// fn print_dbg(view: &pe::PeView) {
// 	print!("{}", SEPARATOR);
// 	if let Some(dbg) = view.debug_info() {
// 		print!("{:?}", dbg);
// 	}
// 	else {
// 		println!("No Debug Directory found.");
// 	}
// }

//----------------------------------------------------------------

fn abort(message: &str) -> ! {
	{
		let stderr = io::stderr();
		let mut stderr = stderr.lock();
		let _ = stderr.write(b"pedump: ");
		let _ = stderr.write(message.as_bytes());
		let _ = stderr.write(b".\n");
		let _ = stderr.flush();
	}
	process::exit(1);
}

fn main() {
	let args = Parameters::default();
	let map = FileMap::open(&args.path).unwrap_or_else(|e| {
		abort(&format!("{:?}", e));
	});
	match PeFile::from_bytes(&map) {
		Ok(Wrap::T32(file)) => dump_pe32(&args, file),
		Ok(Wrap::T64(file)) => dump_pe64(&args, file),
		Err(err) => abort(&format!("{}", err)),
	}
}

fn dump_pe64(args: &Parameters, file: pelite::pe64::PeFile) {
	if args.dos {
		let dos = file.dos_header();
		print!("{}{:?}", SEPARATOR, dos);
	}
	if args.nt {
		let nt = file.nt_headers();
		print!("{}{:?}", SEPARATOR, nt);
	}
	if args.sections {
		print!("{}", SEPARATOR);
		for sec in file.section_headers() {
			print!("{:?}", sec);
		}
	}
	if args.exports {
		print!("{}", SEPARATOR);
		if let Ok(exports) = file.exports() {
			print!("{:#?}", exports);
		}
		else {
			println!("No Export Directory found.");
		}
	}
	if args.imports {
		print!("{}", SEPARATOR);
		if let Ok(imports) = file.imports() {
			print!("{:#?}", imports);
		}
		else {
			println!("No Import Directory found.");
		}
	}
	if args.resources {
		print!("{}", SEPARATOR);
		if let Ok(res) = file.resources() {
			print!("{:#?}", res);
		}
		else {
			println!("No Resources Directory found.");
		}
	}
	if args.relocs {
		print!("{}", SEPARATOR);
		if let Ok(base_relocs) = file.base_relocs() {
			print!("{:#?}", base_relocs);
		}
		else {
			println!("No BaseRelocation Directory found.");
		}
	}
	if args.load_config {
		print!("{}", SEPARATOR);
		if let Ok(load_config) = file.load_config() {
			print!("{:#?}", load_config);
		}
		else {
			println!("No Load Config Directory found.");
		}
	}
	if args.tls {
		print!("{}", SEPARATOR);
		if let Ok(tls) = file.tls() {
			print!("{:#?}", tls);
		}
		else {
			println!("No TLS Directory found.");
		}
	}
	if args.exceptions {
		print_exception_directory_as_dumpbin(&file);
	}
	if args.debug_info {
		print!("{}", SEPARATOR);
		if let Ok(debug) = file.debug() {
			print!("{:?}", debug);
		}
		else {
			println!("No Debug Directory found.");
		}
	}
}

fn print_exception_directory_as_dumpbin(file: &pelite::pe64::PeFile) {
	use pelite::pe64::exception_arm64::Arm64ExceptionExt;
	use pelite::pe64::exception_cseh::UnwindInfoCsehExt;
	use pelite::pe64::exception_fh3::UnwindInfoFh3Ext;
	use pelite::pe64::exception_fh4::UnwindInfoFh4Ext;

	print!("{}", SEPARATOR);
	if file.file_header().Machine == IMAGE_FILE_MACHINE_ARM64 {
		match file.exception_arm64() {
			Ok(exceptions) => print!("{:#?}", exceptions),
			Err(_) => println!("No Exception Directory found."),
		}
		return;
	}

	match file.exception() {
		Ok(exceptions) => {
			println!("Exception Directory - {} entries", exceptions.image().len());
			for (index, func) in exceptions.functions().enumerate() {
				let image = func.image();
				println!(
					"[{:04}] begin=0x{:08x} end=0x{:08x} unwind=0x{:08x}",
					index,
					image.BeginAddress,
					image.EndAddress,
					image.UnwindData,
				);

				if let Ok(info) = func.unwind_info() {
					println!("    Unwind version: {}", info.version());
					println!("    Unwind flags: {:x}", info.flags());
					println!("    Size of prologue: {:#x}", info.size_of_prolog());
					println!("    Count of codes: {}", info.image().CountOfCodes);

					if let Some(handler) = info.handler() {
						println!("    Handler: {:08x}", handler);
					}

					// Determine handler type by examining exception data
					// Order: FH3 (check magic via RVA), CSEH (check valid scope table), FH4
					{
						use pelite::pe64::HandlerType;
						let handler_type = info.handler_type(image.BeginAddress, image.EndAddress);
						match handler_type {
							HandlerType::Fh3 => {
								if let Ok(fh3) = info.func_info3() {
									println!("    EH Handler Data (FH3):");
									print_fh3_as_dumpbin(&fh3);
								}
							}
							HandlerType::Cseh => {
								if let Ok(cseh) = info.c_scope_table() {
									println!("    C Scope Table (__C_specific_handler):");
									print_cseh_as_dumpbin(&cseh);
								}
							}
							HandlerType::Fh4 => {
								if let Ok(fh4) = info.func_info4() {
									println!("    EH Handler Data (FH4): Header {:02x}", fh4.header);
									print_fh4_as_dumpbin(&fh4);
								}
							}
							HandlerType::Unknown => {
								// Try each parser and use whichever works best
								if let Ok(fh4) = info.func_info4() {
									if !fh4.ip_to_state_map.is_empty() || !fh4.unwind_map.is_empty() {
										println!("    EH Handler Data (FH4): Header {:02x}", fh4.header);
										print_fh4_as_dumpbin(&fh4);
									}
								} else if let Ok(fh3) = info.func_info3() {
									println!("    EH Handler Data (FH3):");
									print_fh3_as_dumpbin(&fh3);
								}
							}
						}
					}
				}
			}
		}
		Err(_) => println!("No Exception Directory found."),
	}
}


fn print_cseh_as_dumpbin(cseh: &pelite::pe64::exception_cseh::CScopeTable) {
	println!("    Count of scope table entries: {}", cseh.count);
	println!();
	println!("      Begin    End      Handler  Target");
	println!();
	for entry in &cseh.entries {
		let handler_type = if entry.is_finally() { "(__finally)" } else { "(__except)" };
		println!("      {:08x} {:08x} {:08x} {:08x} {}", 
			entry.begin_address, 
			entry.end_address, 
			entry.handler_address,
			entry.jump_target,
			handler_type
		);
	}
}

fn print_fh4_as_dumpbin(fh4: &pelite::pe64::exception_fh4::FuncInfo4) {
	println!("    Unwind Map:");
	println!("      Current State  Next State | Raw: Offset   Next Offset | Action");
	
	// Helper to find state by offset
	let find_state_by_offset = |target_offset: u32| -> i32 {
		for (idx, entry) in fh4.unwind_map.iter().enumerate() {
			if entry.offset == target_offset {
				return idx as i32;
			}
		}
		-1
	};

	for (i, entry) in fh4.unwind_map.iter().enumerate() {
		let action_str = if entry.type_ == 3 {
			format!("Dtor RVA: {:08x}", entry.action)
		} else {
			"No unwind state".to_string()
		};
		
		let target_offset = (entry.offset as i32 + entry.next_offset) as u32;
		let next_state = find_state_by_offset(target_offset);

		// Format next_offset as signed hex (e.g. -00000001) to match dumpbin
		let next_offset_hex = if entry.next_offset < 0 {
			format!("-{:08x}", -entry.next_offset)
		} else {
			format!("{:08x}", entry.next_offset)
		};

		println!("      {:13}  {:10} |    {:08x}     {:>9} | {}", 
			i, 
			next_state, 
			entry.offset, 
			next_offset_hex, 
			action_str
		);
	}
	
	println!("\n    Number of Try Blocks:          {:08x}", fh4.try_block_map.len());
	for (i, entry) in fh4.try_block_map.iter().enumerate() {
		println!("    Try Block Map #{}:", i);
		println!("      Lowest Try State:                    {}", entry.try_low);
		println!("      Highest Try State:                   {}", entry.try_high);
		println!("      Highest State of Associated Catches: {}", entry.catch_high);
		println!("      RVA to Catch Handler Array:          {:08x}", entry.handlers_rva);
		
		println!("\n      Number of Associated Catches:        {:08x}", entry.handlers.len());
		for (j, handler) in entry.handlers.iter().enumerate() {
			println!("      Catch Handler #{}:", j);
			println!("        Handler Type Adjectives:                {:08x}", handler.adjectives);
			println!("        RVA to Type Descriptor:                 {:08x}", handler.type_desc_rva);
			println!("        Frame offset of Catch Object:           {:08x}", handler.catch_obj_offset);
			println!("        RVA to Catch Handler:                   {:08x}", handler.handler_rva);
		}
	}
	
	println!("\n    Number of IP Map Entries:      {:08}", fh4.ip_to_state_map.len());
	println!("    IP (relative to segment or function start) to State Map:");
	println!("            IP      State | Raw Data: IP Offset   State+1");
	for entry in fh4.ip_to_state_map.iter() {
		// pedump prints "Raw Data" columns as the decoded delta/state values in HEX?
		// Entry 1: Delta 13 (0x13). Printed "13".
		// Entry 2: Delta 64 (0x40). Printed "40".
		// State+1: -1->0 (0), 0->1 (1).
		println!("      {:08x} {:10} |                  {:02x}         {:1x}", 
			entry.ip_offset, 
			entry.state, 
			entry.delta, 
			entry.state + 1
		);
	}
}

fn print_fh3_as_dumpbin(fh3: &pelite::pe64::exception_fh3::FuncInfo3) {
	println!("      Magic Number:                  {:08x}", fh3.magic_number);
	println!("      Max State:                     {}", fh3.max_state);
	println!("      RVA to Unwind Map:             {:08x}", fh3.unwind_map_rva);
	println!("      Number of Try Blocks:          {:08x}", fh3.try_block_count);
	println!("      RVA to Try Block Map:          {:08x}", fh3.try_block_map_rva);
	println!("      Number of IP Map Entries:      {:08x}", fh3.ip_map_count);
	println!("      RVA to IP to State Map:        {:08x}", fh3.ip_map_rva);
	println!("      Frame Offset of Unwind Helper: {:08x}", fh3.frame_offset as u32);
	println!("      RVA to ES Type List:           {:08x}", fh3.es_type_list_rva);
	println!("      EH Flags:                      {:08x}", fh3.eh_flags);

	// Print IP to State Map
	if !fh3.ip_to_state_map.is_empty() {
		println!("    IP to State Map:");
		println!("            IP      State");
		for entry in fh3.ip_to_state_map.iter() {
			println!("      {:08x} {:10}", entry.ip_rva, entry.state);
		}
	}

	// Print Unwind Map
	if !fh3.unwind_map.is_empty() {
		println!("    Unwind Map:");
		println!("      Current State  Next State  RVA to Action");
		for (i, entry) in fh3.unwind_map.iter().enumerate() {
			let action_str = if entry.action_rva != 0 {
				format!("{:08x}", entry.action_rva)
			} else {
				"00000000".to_string()
			};
			println!("      {:13}  {:10}       {}", i, entry.next_state, action_str);
		}
	}

	// Print Try Block Map
	if !fh3.try_block_map.is_empty() {
		for (i, entry) in fh3.try_block_map.iter().enumerate() {
			println!("    Try Block Map #{}:", i);
			println!("      Lowest Try State:                    {}", entry.try_low);
			println!("      Highest Try State:                   {}", entry.try_high);
			println!("      Highest State of Associated Catches: {}", entry.catch_high);
			println!("      Number of Associated Catches:        {:08x}", entry.handlers.len());
			println!("      RVA to Catch Handler Array:          {:08x}", entry.handlers_rva);
			
			for (j, handler) in entry.handlers.iter().enumerate() {
				println!("      Catch Handler #{}:", j);
				println!("        Handler Type Adjectives:                {:08x}", handler.adjectives);
				println!("        RVA to Type Descriptor:                 {:08x}", handler.type_desc_rva);
				println!("        Frame offset of Catch Object:           {:08x}", handler.catch_obj_offset);
				println!("        RVA to Catch Handler:                   {:08x}", handler.handler_rva);
				println!("        Distance Between Handler and Parent FP: {:08x}", handler.disp_frame);
			}
		}
	}
}

fn dump_pe32(args: &Parameters, file: pelite::pe32::PeFile) {
	use pelite::pe32::Pe;
	if args.dos {
		let dos = file.dos_header();
		print!("{}{:?}", SEPARATOR, dos);
	}
	if args.nt {
		let nt = file.nt_headers();
		print!("{}{:?}", SEPARATOR, nt);
	}
	if args.sections {
		print!("{}", SEPARATOR);
		for sec in file.section_headers() {
			print!("{:?}", sec);
		}
	}
	if args.exports {
		print!("{}", SEPARATOR);
		if let Ok(exports) = file.exports() {
			print!("{:#?}", exports);
		}
		else {
			println!("No Export Directory found.");
		}
	}
	if args.imports {
		print!("{}", SEPARATOR);
		if let Ok(imports) = file.imports() {
			print!("{:#?}", imports);
		}
		else {
			println!("No Import Directory found.");
		}
	}
	if args.resources {
		print!("{}", SEPARATOR);
		if let Ok(res) = file.resources() {
			print!("{:#?}", res);
		}
		else {
			println!("No Resources Directory found.");
		}
	}
	if args.relocs {
		print!("{}", SEPARATOR);
		if let Ok(base_relocs) = file.base_relocs() {
			print!("{:#?}", base_relocs);
		}
		else {
			println!("No BaseRelocation Directory found.");
		}
	}
	if args.load_config {
		print!("{}", SEPARATOR);
		if let Ok(load_config) = file.load_config() {
			print!("{:#?}", load_config);
		}
		else {
			println!("No Load Config Directory found.");
		}
	}
	if args.tls {
		print!("{}", SEPARATOR);
		if let Ok(tls) = file.tls() {
			print!("{:#?}", tls);
		}
		else {
			println!("No TLS Directory found.");
		}
	}
	if args.exceptions {
		print!("{}", SEPARATOR);
		if let Ok(exceptions) = file.exception() {
			println!("Exception Directory - {} entries", exceptions.image().len());
			for (index, func) in exceptions.functions().enumerate() {
				let image = func.image();
				println!(
					"[{:04}] begin=0x{:08x} end=0x{:08x} unwind=0x{:08x}",
					index,
					image.BeginAddress,
					image.EndAddress,
					image.UnwindData,
				);
			}
		}
		else {
			println!("No Exception Directory found.");
		}
	}
	if args.debug_info {
		print!("{}", SEPARATOR);
		if let Ok(debug) = file.debug() {
			print!("{:#?}", debug);
		}
		else {
			println!("No Debug Directory found.");
		}
	}
}
