use std::{
    collections::{BTreeMap, HashMap, btree_map},
    fs::File,
    io::{Cursor, Read, Write, stdout},
    ops::Bound::{Excluded, Unbounded},
};

use anyhow::{Result, anyhow, bail};
use argp::FromArgs;
use gimli::write::Writer;
use object::{
    Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, Section, elf,
    write::StreamingBuffer,
};
use typed_path::Utf8NativePathBuf;

use crate::{
    util::{
        dwarf::{
            io::{parse_producer, read_debug_section},
            process::{
                build_fundemantal_typemap, create_void_pointer, process_compile_unit,
                process_cu_tag, process_overlay_branch, ref_fixup_cu_tag,
            },
            types::{AttributeKind, Dwarf2Types, TagKind, TypedefMap},
        },
        path::native_path,
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing DWARF 1.1 information.
#[argp(subcommand, name = "dwarf")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Convert(ConvertArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Converts DWARF 1.1 info of an object into DWARF 2+.
#[argp(subcommand, name = "convert")]
pub struct ConvertArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// Input object. (ELF or archive)
    in_file: Utf8NativePathBuf,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// Output file. (Or directory, for archive)
    out: Option<Utf8NativePathBuf>,
    #[argp(switch)]
    /// Add PowerPC specific hacks which import better into Ghidra.
    ppc_hacks: bool,
    #[argp(option, default = "4")]
    /// Specify the dwarf version. 4 by default.
    dwarf_version: u16,
    #[argp(switch)]
    /// Attempt to reconstruct tags that have been removed by the linker, e.g.
    /// tags from unused functions or functions that have been inlined away.
    include_erased: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Convert(c_args) => convert(c_args),
    }
}

fn convert(args: ConvertArgs) -> Result<()> {
    let mut file = open_file(&args.in_file)?;
    let buf = file.map()?;
    if buf.starts_with(b"!<arch>\n") {
        // TODO DWARF122 archive stuff
        let mut archive = ar::Archive::new(buf);
        while let Some(result) = archive.next_entry() {
            let mut e = match result {
                Ok(e) => e,
                Err(e) => bail!("Failed to read archive entry: {:?}", e),
            };
            let name = String::from_utf8_lossy(e.header().identifier()).to_string();
            let mut data = vec![0u8; e.header().size() as usize];
            e.read_exact(&mut data)?;
            let obj_file = object::read::File::parse(&*data)?;
            let debug_section = match obj_file.section_by_name(".debug") {
                Some(section) => {
                    log::info!("Processing '{}'", name);
                    section
                }
                None => {
                    log::warn!("Object '{}' missing .debug section", name);
                    continue;
                }
            };
            println!("\n// File {name}:");
            convert_debug_section(&args, &mut stdout(), &obj_file, &data, debug_section)?;
        }
    } else {
        let obj_file = object::read::File::parse(buf)?;
        let debug_section = obj_file
            .section_by_name(".debug")
            .ok_or_else(|| anyhow!("Failed to locate .debug section"))?;
        convert_debug_section(&args, &mut stdout(), &obj_file, buf, debug_section)?;
    }
    Ok(())
}

fn convert_debug_section<W>(
    args: &ConvertArgs,
    w: &mut W,
    obj_file: &object::File<'_>,
    raw_elf: &[u8],
    debug_section: Section,
) -> Result<()>
where
    W: Write + ?Sized,
{
    let mut data = debug_section.uncompressed_data()?.into_owned();

    // Apply relocations to data
    for (addr, reloc) in debug_section.relocations() {
        match reloc.flags() {
            RelocationFlags::Elf { r_type: elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 } => {
                let target = match reloc.target() {
                    RelocationTarget::Symbol(symbol_idx) => {
                        let symbol = obj_file.symbol_by_index(symbol_idx)?;
                        (symbol.address() as i64 + reloc.addend()) as u32
                    }
                    _ => bail!("Invalid .debug relocation target"),
                };
                data[addr as usize..addr as usize + 4].copy_from_slice(&target.to_be_bytes());
            }
            RelocationFlags::Elf { r_type: elf::R_PPC_NONE } => {}
            _ => bail!("Unhandled .debug relocation type {:?}", reloc.kind()),
        }
    }

    let mut reader = Cursor::new(&*data);
    let encoding = gimli::Encoding {
        format: if obj_file.is_64() { gimli::Format::Dwarf64 } else { gimli::Format::Dwarf32 },
        version: args.dwarf_version,
        address_size: if obj_file.is_64() { 8 } else { 4 }, // TODO "weird" platforms?
    };
    let mut info =
        read_debug_section(&mut reader, obj_file.endianness().into(), args.include_erased)?;
    info.ppc_hacks = args.ppc_hacks;
    info.obj_file = Some(obj_file);

    for (&addr, tag) in &info.tags {
        log::debug!("{}: {:?}", addr, tag);
    }

    let endian = if obj_file.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let mut write_units = gimli::write::UnitTable::default();

    if let Some((_, mut tag)) = info.tags.first_key_value() {
        loop {
            match tag.kind {
                TagKind::Padding => {
                    // TODO
                }
                TagKind::MwOverlayBranch => {
                    let branch = process_overlay_branch(tag)?;
                    writeln!(w, "\n/*\n    Overlay: {}", branch.name)?;
                    writeln!(w, "    Overlay ID: {}", branch.id)?;
                    writeln!(
                        w,
                        "    Code range: {:#010X} -> {:#010X}",
                        branch.start_address, branch.end_address
                    )?;

                    if let Some(unit_addr) = branch.compile_unit {
                        let tag = info
                            .tags
                            .get(&unit_addr)
                            .ok_or_else(|| anyhow!("Failed to get CompileUnit"))?;
                        let unit = process_compile_unit(tag)?;
                        writeln!(w, "    Compile unit: {}", unit.name)?;
                    }

                    writeln!(w, "*/")?;
                }
                TagKind::CompileUnit => {
                    let read_unit = process_compile_unit(tag)?;
                    let mut write_dwarf = gimli::write::DwarfUnit::new(encoding);
                    // TODO DWARF122 move to dwarf2_types?
                    let write_unit = write_dwarf.unit.get_mut(write_dwarf.unit.root());

                    write_unit.set(
                        gimli::DW_AT_name,
                        gimli::write::AttributeValue::String(read_unit.name.clone().into_bytes()),
                    );

                    if let Some(producer) = read_unit.producer {
                        info.producer = parse_producer(&producer);
                        write_unit.set(
                            gimli::DW_AT_producer,
                            gimli::write::AttributeValue::String(producer.into_bytes()),
                        );
                    }
                    if let Some(comp_dir) = read_unit.comp_dir {
                        write_unit.set(
                            gimli::DW_AT_comp_dir,
                            gimli::write::AttributeValue::String(comp_dir.into_bytes()),
                        );
                    }
                    if let Some(language) = read_unit.language {
                        write_unit.set(
                            gimli::DW_AT_language,
                            gimli::write::AttributeValue::Language(language.into()),
                        );
                    }
                    if let (Some(start), Some(end)) =
                        (read_unit.start_address, read_unit.end_address)
                    {
                        write_unit.set(
                            gimli::DW_AT_low_pc,
                            gimli::write::AttributeValue::Address(gimli::write::Address::Constant(
                                start.into(),
                            )),
                        );
                        write_unit.set(
                            gimli::DW_AT_high_pc,
                            gimli::write::AttributeValue::Address(gimli::write::Address::Constant(
                                end.into(),
                            )),
                        );
                    }
                    if let Some(_gcc_srcfile_name_offset) = read_unit.gcc_srcfile_name_offset {
                        // writeln!(
                        //     w,
                        //     "    GCC Source File Name Offset: {gcc_srcfile_name_offset:#010X}"
                        // )?;
                    }
                    if let Some(_gcc_srcinfo_offset) = read_unit.gcc_srcinfo_offset {
                        // writeln!(w, "    GCC Source Info Offset: {gcc_srcinfo_offset:#010X}")?;
                    }
                    // writeln!(w, "*/")?;

                    let mut children = tag.children(&info.tags);

                    // merge in erased tags
                    let range = match tag.next_sibling(&info.tags) {
                        Some(next) => (Excluded(tag.key), Excluded(next.key)),
                        None => (Excluded(tag.key), Unbounded),
                    };
                    for (_, child) in info.tags.range(range) {
                        if child.is_erased_root {
                            children.push(child);
                        }
                    }
                    children.sort_by_key(|x| x.key);

                    let mut typedefs = TypedefMap::new();
                    let mut dwarf2_types = Dwarf2Types {
                        fundamental_map: build_fundemantal_typemap(&mut write_dwarf.unit)?,
                        old_new_tag_map: BTreeMap::new(),
                        modified_type_id_map: HashMap::new(),
                    };
                    create_void_pointer(&mut write_dwarf.unit, &mut dwarf2_types);
                    for &child in &children {
                        match process_cu_tag(&info, &mut write_dwarf.unit, &mut dwarf2_types, child)
                        {
                            Ok(tag_type) => tag_type,
                            Err(e) => {
                                log::error!(
                                    "Failed to process tag {:X} ({:?}) (unit {}): {}",
                                    child.key,
                                    child.kind,
                                    read_unit.name,
                                    e
                                );
                                continue;
                            }
                        };
                        if let TagKind::Typedef = child.kind {
                            // TODO fundamental typedefs?
                            if let Some(ud_type_ref) =
                                child.reference_attribute(AttributeKind::UserDefType)
                            {
                                match typedefs.entry(ud_type_ref) {
                                    btree_map::Entry::Vacant(e) => {
                                        e.insert(vec![child.key]);
                                    }
                                    btree_map::Entry::Occupied(e) => {
                                        e.into_mut().push(child.key);
                                    }
                                }
                            }
                        }
                    }
                    for &child in &children {
                        if let Err(e) =
                            ref_fixup_cu_tag(&info, &mut write_dwarf.unit, &mut dwarf2_types, child)
                        {
                            log::error!(
                                "Failed to fixup tag {:X} ({:?}) (unit {}): {}",
                                child.key,
                                child.kind,
                                read_unit.name,
                                e
                            );
                            continue;
                        }
                    }
                    // TODO DWARF122 remove the fake void type?
                    write_units.add(write_dwarf.unit);
                }
                kind => bail!("Unhandled root tag type {:?}", kind),
            }

            if let Some(next) = tag.next_sibling(&info.tags) {
                tag = next;
            } else {
                break;
            }
        }
    }
    let mut builder = object::build::elf::Builder::read(raw_elf)?;

    // Remove original debug sections
    for section in builder.sections.iter_mut() {
        if section.name.starts_with(b".debug") || section.name.starts_with(b".line") {
            section.delete = true;
        }
    }

    let mut write_dwarf_sections =
        gimli::write::Sections::new(gimli::write::EndianVec::new(endian));

    // TODO
    let mut line_str_offsets = gimli::write::LineStringTable::default();
    let mut str_offsets = gimli::write::StringTable::default();

    // Write units to sections
    write_units.write(&mut write_dwarf_sections, &mut line_str_offsets, &mut str_offsets)?;

    write_dwarf_sections.for_each(|id, dwarf_section| {
        if dwarf_section.len() == 0 {
            return Ok(());
        }

        let write_section = builder.sections.add();

        write_section.name = id.name().as_bytes().to_vec().into();
        write_section.sh_type = object::elf::SHT_PROGBITS; // or appropriate type for debug sections
        write_section.data =
            object::build::elf::SectionData::Data(dwarf_section.slice().to_vec().into());
        write_section.sh_addralign = 1;

        // Set flags for string sections
        if id.is_string() {
            write_section.sh_flags = (object::elf::SHF_STRINGS | object::elf::SHF_MERGE).into();
        }

        Ok::<(), gimli::write::Error>(())
    })?;

    let output_path =
        if let Some(out) = &args.out { out.clone() } else { Utf8NativePathBuf::from("out.elf") };
    let file = File::create(&output_path)?;
    let mut buffer = StreamingBuffer::new(file);

    builder.write(&mut buffer)?;

    println!("ELF file with debug info written to {}", &output_path);
    Ok(())
}
