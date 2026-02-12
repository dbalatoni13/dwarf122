use std::{
    collections::BTreeMap,
    io::{BufRead, Cursor, Seek, SeekFrom},
};

use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSegment};

use crate::util::{
    dwarf::types::{
        Attribute, AttributeKind, AttributeValue, DwarfInfo, FormKind, Producer, Tag, TagKind,
        FORM_MASK,
    },
    reader::{Endian, FromReader},
};

pub fn read_debug_section<R>(reader: &mut R, e: Endian, include_erased: bool) -> Result<DwarfInfo<'_>>
where R: BufRead + Seek + ?Sized {
    let len = {
        let old_pos = reader.stream_position()?;
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(old_pos))?;
        len
    };

    let mut info = DwarfInfo { e, tags: BTreeMap::new(), producer: Producer::OTHER, ppc_hacks: false, obj_file: None };
    loop {
        let position = reader.stream_position()?;
        if position >= len {
            break;
        }
        let tags = read_tags(reader, e, e, include_erased, false)?;
        for tag in tags {
            info.tags.insert(tag.key, tag);
        }
    }
    Ok(info)
}

pub fn parse_producer(producer: &str) -> Producer {
    match producer {
        p if p.starts_with("MW") => Producer::MWCC,
        p if p.starts_with("GNU C") => Producer::GCC,
        _ => Producer::OTHER,
    }
}

#[allow(unused)]
pub fn read_aranges_section<R>(reader: &mut R, e: Endian) -> Result<()>
where R: BufRead + Seek + ?Sized {
    let len = {
        let old_pos = reader.stream_position()?;
        let len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(old_pos))?;
        len
    };

    // let mut tags = BTreeMap::new();
    loop {
        let position = reader.stream_position()?;
        if position >= len {
            break;
        }

        let size = u32::from_reader(reader, e)?;
        let version = u8::from_reader(reader, e)?;
        ensure!(version == 1, "Expected version 1, got {version}");
        let _debug_offs = u32::from_reader(reader, e)?;
        let _debug_size = u32::from_reader(reader, e)?;
        while reader.stream_position()? < position + size as u64 {
            let _address = u32::from_reader(reader, e)?;
            let _length = u32::from_reader(reader, e)?;
        }
    }
    Ok(())
}

fn read_tags<R>(
    reader: &mut R,
    data_endian: Endian,
    addr_endian: Endian,
    include_erased: bool,
    is_erased: bool,
) -> Result<Vec<Tag>>
where
    R: BufRead + Seek + ?Sized,
{
    let mut tags = Vec::new();
    let position = reader.stream_position()?;
    let size = u32::from_reader(reader, data_endian)?;
    if size < 8 {
        // Null entry
        if size > 4 {
            reader.seek(SeekFrom::Current(size as i64 - 4))?;
        }
        tags.push(Tag {
            key: position as u32,
            kind: TagKind::Padding,
            is_erased,
            is_erased_root: false,
            data_endian,
            attributes: Vec::new(),
        });
        return Ok(tags);
    }

    let tag_num = u16::from_reader(reader, data_endian)?;
    let tag = TagKind::try_from(tag_num).context("Unknown DWARF tag type")?;
    if tag == TagKind::Padding {
        if include_erased {
            // Erased entries that have become padding could be either
            // little-endian or big-endian, and we have to guess the length and
            // tag of the first entry. We assume the entry is either a variable
            // or a function, and read until we find the high_pc attribute. Only
            // MwGlobalRef will follow, and these are unlikely to be confused
            // with the length of the next entry.
            let mut attributes = Vec::new();
            let mut is_function = false;

            // Guess endianness based on first attribute
            let data_endian = if is_erased {
                data_endian
            } else {
                // Peek next two bytes
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                let attr_tag = u16::from_reader(&mut Cursor::new(&buf), data_endian)?;
                reader.seek(SeekFrom::Current(-2))?;
                match AttributeKind::try_from(attr_tag) {
                    Ok(_) => data_endian,
                    Err(_) => data_endian.flip(),
                }
            };

            while reader.stream_position()? < position + size as u64 {
                // Peek next two bytes
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                let attr_tag = u16::from_reader(&mut Cursor::new(&buf), data_endian)?;
                reader.seek(SeekFrom::Current(-2))?;

                if is_function && attr_tag != AttributeKind::MwGlobalRef as u16 {
                    break;
                }

                let attr = read_attribute(reader, data_endian, addr_endian)?;
                if attr.kind == AttributeKind::HighPc {
                    is_function = true;
                }
                attributes.push(attr);
            }
            let kind = if is_function { TagKind::Subroutine } else { TagKind::LocalVariable };
            tags.push(Tag {
                key: position as u32,
                kind,
                is_erased: true,
                is_erased_root: true,
                data_endian,
                attributes,
            });

            // Read the rest of the tags
            while reader.stream_position()? < position + size as u64 {
                for tag in read_tags(reader, data_endian, addr_endian, include_erased, true)? {
                    tags.push(tag);
                }
            }
        } else {
            reader.seek(SeekFrom::Start(position + size as u64))?; // Skip padding
        }
    } else {
        let mut attributes = Vec::new();
        while reader.stream_position()? < position + size as u64 {
            attributes.push(read_attribute(reader, data_endian, addr_endian)?);
        }
        tags.push(Tag {
            key: position as u32,
            kind: tag,
            is_erased,
            is_erased_root: false,
            data_endian,
            attributes,
        });
    }
    Ok(tags)
}

// TODO Shift-JIS?
pub fn read_string<R>(reader: &mut R) -> Result<String>
where R: BufRead + ?Sized {
    let mut str = String::new();
    let mut buf = [0u8; 1];
    loop {
        reader.read_exact(&mut buf)?;
        if buf[0] == 0 {
            break;
        }
        str.push(buf[0] as char);
    }
    Ok(str)
}

pub fn read_attribute<R>(
    reader: &mut R,
    data_endian: Endian,
    addr_endian: Endian,
) -> Result<Attribute>
where
    R: BufRead + Seek + ?Sized,
{
    let attr_type = u16::from_reader(reader, data_endian)?;
    let attr = AttributeKind::try_from(attr_type).context("Unknown DWARF attribute type")?;
    let form = FormKind::try_from(attr_type & FORM_MASK).context("Unknown DWARF form type")?;
    let value = match form {
        FormKind::Addr => AttributeValue::Address(u32::from_reader(reader, addr_endian)?),
        FormKind::Ref => AttributeValue::Reference(u32::from_reader(reader, addr_endian)?),
        FormKind::Block2 => {
            let size = u16::from_reader(reader, data_endian)?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            AttributeValue::Block(data)
        }
        FormKind::Block4 => {
            let size = u32::from_reader(reader, data_endian)?;
            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data)?;
            AttributeValue::Block(data)
        }
        FormKind::Data2 => AttributeValue::Data2(u16::from_reader(reader, data_endian)?),
        FormKind::Data4 => AttributeValue::Data4(u32::from_reader(reader, data_endian)?),
        FormKind::Data8 => AttributeValue::Data8(u64::from_reader(reader, data_endian)?),
        FormKind::String => AttributeValue::String(read_string(reader)?),
    };
    Ok(Attribute { kind: attr, value })
}

pub fn read_va<'a>(file: &'a object::File<'a>, addr: u64, size: u64) -> Result<&'a [u8]> {
    for seg in file.segments() {
        let seg_start = seg.address();
        let seg_end = seg_start + seg.size();

        if addr >= seg_start && addr + size <= seg_end {
            let data = seg.data()?;
            let delta = (addr - seg_start) as usize;
            return Ok(&data[delta..delta + size as usize]);
        }
    }
    bail!("address not in any segment");
}