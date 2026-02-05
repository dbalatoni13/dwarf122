#![deny(unused_crate_dependencies)]
use std::{env, ffi::OsStr, fmt::Display, path::PathBuf, process::exit, str::FromStr};

use anyhow::Error;
use argp::{FromArgValue, FromArgs};
use enable_ansi_support::enable_ansi_support;
use supports_color::Stream;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

pub mod argp_version;
pub mod cmd;
pub mod util;
mod vfs;

// musl's allocator is very slow, so use mimalloc when targeting musl.
// Otherwise, use the system allocator to avoid extra code size.
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return Err(()),
        })
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        })
    }
}

impl FromArgValue for LogLevel {
    fn from_arg_value(value: &OsStr) -> Result<Self, String> {
        String::from_arg_value(value)
            .and_then(|s| Self::from_str(&s).map_err(|_| "Invalid log level".to_string()))
    }
}

#[derive(FromArgs, Debug)]
/// Yet another GameCube/Wii decompilation toolkit.
struct TopLevel {
    #[argp(subcommand)]
    command: SubCommand,
    #[argp(option, short = 'C')]
    /// Change working directory.
    chdir: Option<PathBuf>,
    #[argp(option, short = 'L')]
    /// Minimum logging level. (Default: info)
    /// Possible values: error, warn, info, debug, trace
    log_level: Option<LogLevel>,
    /// Print version information and exit.
    #[argp(switch, short = 'V')]
    #[allow(dead_code)]
    version: bool,
    /// Disable color output. (env: NO_COLOR)
    #[argp(switch)]
    no_color: bool,
}

#[derive(FromArgs, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Dwarf(cmd::dwarf::Args),
}

// Duplicated from supports-color so we can check early.
fn env_no_color() -> bool {
    match env::var("NO_COLOR").as_deref() {
        Ok("") | Ok("0") | Err(_) => false,
        Ok(_) => true,
    }
}

fn main() {
    let args: TopLevel = argp_version::from_env();
    let use_colors = if args.no_color || env_no_color() {
        false
    } else {
        // Try to enable ANSI support on Windows.
        let _ = enable_ansi_support();
        // Disable isatty check for supports-color. (e.g. when used with ninja)
        env::set_var("IGNORE_IS_TERMINAL", "1");
        supports_color::on(Stream::Stdout).is_some_and(|c| c.has_basic)
    };
    // owo-colors uses an old version of supports-color, so we need to override manually.
    // Ideally, we'd be able to remove the old version of supports-color, but disabling the feature
    // in owo-colors removes set_override and if_supports_color entirely.
    owo_colors::set_override(use_colors);

    let format =
        tracing_subscriber::fmt::format().with_ansi(use_colors).with_target(false).without_time();
    let builder = tracing_subscriber::fmt().event_format(format);
    if let Some(level) = args.log_level {
        builder
            .with_max_level(match level {
                LogLevel::Error => LevelFilter::ERROR,
                LogLevel::Warn => LevelFilter::WARN,
                LogLevel::Info => LevelFilter::INFO,
                LogLevel::Debug => LevelFilter::DEBUG,
                LogLevel::Trace => LevelFilter::TRACE,
            })
            .init();
    } else {
        builder
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    }

    let mut result = Ok(());
    if let Some(dir) = &args.chdir {
        result = env::set_current_dir(dir).map_err(|e| {
            Error::new(e)
                .context(format!("Failed to change working directory to '{}'", dir.display()))
        });
    }
    result = result.and_then(|_| match args.command {
        SubCommand::Dwarf(c_args) => cmd::dwarf::run(c_args),
    });
    if let Err(e) = result {
        eprintln!("Failed: {e:?}");
        exit(1);
    }
}

// use gimli::write::{
//     Address, AttributeValue, DebugLineStrOffsets, DebugStrOffsets, DwarfUnit, EndianVec, FileInfo,
//     LineProgram, LineStringTable, Sections, UnitTable, Writer,
// };
// use gimli::{
//     DW_AT_high_pc, DW_AT_language, DW_AT_low_pc, DW_AT_name, DW_AT_producer, DW_TAG_compile_unit,
//     DW_TAG_subprogram, Encoding, Format, RunTimeEndian, DW_LANG_C,
// };
// use object::write::Object;
// use object::{Architecture, BinaryFormat, Endianness};
// use std::fs::File;
// use std::io::Write;

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // 1. Create the encoding configuration
//     let encoding = Encoding {
//         format: Format::Dwarf32,
//         version: 4,
//         address_size: 4, // 64-bit
//     };

//     // 2. Create a compilation unit
//     let mut dwarf = DwarfUnit::new(encoding);

//     // 3. Create the root DIE (Debug Information Entry) - compilation unit
//     let root = dwarf.unit.root();

//     // Add attributes to the compilation unit
//     dwarf
//         .unit
//         .get_mut(root)
//         .set(DW_AT_producer, AttributeValue::String(b"My Custom Compiler".to_vec()));
//     dwarf.unit.get_mut(root).set(DW_AT_language, AttributeValue::Language(gimli::DW_LANG_C_plus_plus));
//     dwarf.unit.get_mut(root).set(DW_AT_name, AttributeValue::String(b"example.c".to_vec()));
//     dwarf
//         .unit
//         .get_mut(root)
//         .set(DW_AT_low_pc, AttributeValue::Address(Address::Constant(0x1000)));
//     dwarf.unit.get_mut(root).set(
//         DW_AT_high_pc,
//         AttributeValue::Udata(0x100), // Size of code
//     );

//     // Define base type: int (32-bit signed)
//     let int_type = dwarf.unit.add(root, gimli::DW_TAG_base_type);
//     dwarf.unit.get_mut(int_type).set(
//         DW_AT_name,
//         AttributeValue::String(b"int".to_vec()),
//     );
//     dwarf.unit.get_mut(int_type).set(
//         gimli::DW_AT_byte_size,
//         AttributeValue::Data1(4), // 4 bytes
//     );
//     dwarf.unit.get_mut(int_type).set(
//         gimli::DW_AT_encoding,
//         AttributeValue::Encoding(gimli::DW_ATE_signed),
//     );

//     // Define struct type: struct Point { int x; int y; }
//     let struct_type = dwarf.unit.add(root, gimli::DW_TAG_structure_type);
//     dwarf.unit.get_mut(struct_type).set(
//         DW_AT_name,
//         AttributeValue::String(b"Point".to_vec()),
//     );
//     dwarf.unit.get_mut(struct_type).set(
//         gimli::DW_AT_byte_size,
//         AttributeValue::Data1(8), // 2 ints = 8 bytes
//     );

//     // Add member: int x
//     let member_x = dwarf.unit.add(struct_type, gimli::DW_TAG_member);
//     dwarf.unit.get_mut(member_x).set(
//         DW_AT_name,
//         AttributeValue::String(b"x".to_vec()),
//     );
//     dwarf.unit.get_mut(member_x).set(
//         gimli::DW_AT_type,
//         AttributeValue::UnitRef(int_type), // <-- Reference to int type
//     );
//     dwarf.unit.get_mut(member_x).set(
//         gimli::DW_AT_data_member_location,
//         AttributeValue::Data1(0), // Offset 0 bytes in struct
//     );

//     // Add member: int y
//     let member_y = dwarf.unit.add(struct_type, gimli::DW_TAG_member);
//     dwarf.unit.get_mut(member_y).set(
//         DW_AT_name,
//         AttributeValue::String(b"y".to_vec()),
//     );
//     dwarf.unit.get_mut(member_y).set(
//         gimli::DW_AT_type,
//         AttributeValue::UnitRef(int_type), // <-- Reference to int type
//     );
//     dwarf.unit.get_mut(member_y).set(
//         gimli::DW_AT_data_member_location,
//         AttributeValue::Data1(4), // Offset 4 bytes in struct
//     );

//     // Define function: void process_point(struct Point p)
//     let subprogram = dwarf.unit.add(root, DW_TAG_subprogram);
//     dwarf.unit.get_mut(subprogram).set(
//         DW_AT_name,
//         AttributeValue::String(b"process_point".to_vec()),
//     );
//     dwarf.unit.get_mut(subprogram).set(
//         DW_AT_low_pc,
//         AttributeValue::Address(Address::Constant(0x1000)),
//     );
//     dwarf.unit.get_mut(subprogram).set(
//         DW_AT_high_pc,
//         AttributeValue::Udata(0x50),
//     );

//     // Add parameter to function: struct Point p
//     let param = dwarf.unit.add(subprogram, gimli::DW_TAG_formal_parameter);
//     dwarf.unit.get_mut(param).set(
//         DW_AT_name,
//         AttributeValue::String(b"p".to_vec()),
//     );
//     dwarf.unit.get_mut(param).set(
//         gimli::DW_AT_type,
//         AttributeValue::UnitRef(struct_type), // <-- Reference to struct type!
//     );
//     // Optionally add location (e.g., register or stack location)
//     dwarf.unit.get_mut(param).set(
//         gimli::DW_AT_location,
//         AttributeValue::Exprloc(gimli::write::Expression::new()),
//     );

//     // Add a local variable of struct type
//     let local_var = dwarf.unit.add(subprogram, gimli::DW_TAG_variable);
//     dwarf.unit.get_mut(local_var).set(
//         DW_AT_name,
//         AttributeValue::String(b"local_point".to_vec()),
//     );
//     dwarf.unit.get_mut(local_var).set(
//         gimli::DW_AT_type,
//         AttributeValue::UnitRef(struct_type), // <-- Reference to struct type!
//     );
//     dwarf.unit.get_mut(local_var).set(
//         gimli::DW_AT_location,
//         AttributeValue::Exprloc(gimli::write::Expression::new()),
//     );

//     // 4. Add a subprogram (function)
//     let subprogram = dwarf.unit.add(root, DW_TAG_subprogram);
//     dwarf.unit.get_mut(subprogram).set(DW_AT_name, AttributeValue::String(b"main".to_vec()));
//     dwarf
//         .unit
//         .get_mut(subprogram)
//         .set(DW_AT_low_pc, AttributeValue::Address(Address::Constant(0x1000)));
//     dwarf.unit.get_mut(subprogram).set(DW_AT_high_pc, AttributeValue::Udata(0x50));

//     // 5. Create line program
//     let mut line_program = LineProgram::new(
//         encoding,
//         gimli::LineEncoding::default(),
//         gimli::write::LineString::String(b"example.c".to_vec()), // comp_file
//         None,                                                    // comp_dir
//         gimli::write::LineString::String(b"/path/to".to_vec()),  // comp_file_dir
//         None,                                                    // file_info
//     );

//     // Add rows to the line program (maps addresses to source lines)
//     line_program.begin_sequence(Some(Address::Constant(0x1000)));
//     line_program.row().line = 1;
//     line_program.generate_row();
//     line_program.row().address_offset = 0x10;
//     line_program.row().line = 2;
//     line_program.generate_row();
//     line_program.end_sequence(0x50);

//     // 6. Create sections and write DWARF data
//     let mut sections = Sections::new(EndianVec::new(RunTimeEndian::Big));

//     // Add the unit to a unit table
//     let mut units = UnitTable::default();
//     let unit_id = units.add(dwarf.unit);

//     // Create offset tables
//     let line_str_offsets = DebugLineStrOffsets::none();
//     let str_offsets = DebugStrOffsets::none();

//     // Write units to sections
//     units.write(&mut sections, &line_str_offsets, &str_offsets)?;

//     // Write line program to debug_line section
//     let line_strings = LineStringTable::default();
//     line_program.write(&mut sections.debug_line, encoding, &line_str_offsets, &str_offsets)?;

//     // 7. Create ELF file using object crate
//     let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Big);

//     // Add a simple text section with dummy code
//     let text_section = obj.add_section(vec![], b".text".to_vec(), object::SectionKind::Text);
//     obj.section_mut(text_section).set_data(vec![0x90; 0x100], 8);
//     obj.section_mut(text_section).flags = object::SectionFlags::Elf {
//         sh_flags: (object::elf::SHF_ALLOC | object::elf::SHF_EXECINSTR) as u64,
//     };

//     // 8. Add DWARF sections to the ELF file
//     add_dwarf_section(&mut obj, ".debug_abbrev", sections.debug_abbrev.slice());
//     add_dwarf_section(&mut obj, ".debug_info", sections.debug_info.slice());
//     add_dwarf_section(&mut obj, ".debug_line", sections.debug_line.slice());
//     add_dwarf_section(&mut obj, ".debug_str", sections.debug_str.slice());

//     // 9. Write the ELF file
//     let elf_data = obj.write()?;
//     let mut file = File::create("output.elf")?;
//     file.write_all(&elf_data)?;

//     println!("ELF file with debug info written to output.elf");

//     Ok(())
// }
