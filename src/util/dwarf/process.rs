use std::{
    collections::{hash_map, BTreeMap},
    io::Cursor,
    num::NonZeroU32,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use gimli::write::{Expression, UnitEntryId};
use num_enum::TryFromPrimitive;

use crate::{
    array_ref,
    util::{
        dwarf::{
            io::{read_attribute, read_string},
            types::{
                ArrayDimension, ArrayOrdering, ArrayType, Attribute, AttributeKind, AttributeValue,
                BitData, CompileUnit, Dwarf2Types, DwarfInfo, EnumerationMember, EnumerationType,
                FundType, Language, LocationOp, Modifier, OverlayBranch, Producer, PtrToMemberType,
                StructureBase, StructureKind, StructureMember, StructureType, SubroutineBlock,
                SubroutineLabel, SubroutineNode, SubroutineParameter, SubroutineType,
                SubroutineVariable, SubscriptFormat, Tag, TagKind, TagType, Type, TypeKind,
                TypedefTag, UnionType, UserDefinedType, VariableTag, Visibility,
            },
        },
        reader::{Endian, FromBytes, FromReader},
    },
};

pub fn process_offset(block: &[u8], e: Endian) -> Result<u32> {
    if block.len() == 6 && block[0] == LocationOp::Const as u8 && block[5] == LocationOp::Add as u8
    {
        Ok(u32::from_bytes(*array_ref!(block, 1, 4), e))
    } else {
        Err(anyhow!("Unhandled location data, expected offset"))
    }
}

pub fn process_address(block: &[u8], e: Endian) -> Result<u32> {
    if block.len() == 5 && block[0] == LocationOp::Address as u8 {
        Ok(u32::from_bytes(*array_ref!(block, 1, 4), e))
    } else {
        Err(anyhow!("Unhandled location data, expected address"))
    }
}

pub const REGISTER_NAMES: [&str; 109] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", // 0-7
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", // 8-15
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", // 16-23
    "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31", // 24-31
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", // 32-39
    "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15", // 40-47
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", // 48-55
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31", // 56-63
    "mq", "lr", "ctr", "ap", "cr0", "cr1", "cr2", "cr3", // 64-71
    "cr4", "cr5", "cr6", "cr7", "xer", "v0", "v1", "v2", // 72-79
    "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", // 80-87
    "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", // 88-95
    "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", // 96-103
    "v27", "v28", "v29", "v30", "v31", // 104-108
];

pub const fn register_name(reg: u32) -> &'static str {
    if reg < REGISTER_NAMES.len() as u32 {
        REGISTER_NAMES[reg as usize]
    } else {
        "[invalid]"
    }
}

pub fn process_variable_location(block: &[u8], e: Endian) -> Result<Expression> {
    let mut expr = gimli::write::Expression::new();
    if block.len() == 5
        && (block[0] == LocationOp::Register as u8
            || block[0] == LocationOp::BaseRegister as u8
            || block[0] == LocationOp::MwFpReg as u8)
    {
        expr.op_reg(gimli::Register(u32::from_bytes(*array_ref!(block, 1, 4), e) as u16));
    } else if block.len() == 5 && block[0] == LocationOp::Address as u8 {
        expr.op_addr(gimli::write::Address::Constant(
            u32::from_bytes(*array_ref!(block, 1, 4), e) as u64
        ));
    } else if block.len() == 11
        && block[0] == LocationOp::BaseRegister as u8
        && block[5] == LocationOp::Const as u8
        && block[10] == LocationOp::Add as u8
    {
        // TODO is it i32 or u32?
        expr.op_breg(
            gimli::Register(u32::from_bytes(*array_ref!(block, 1, 4), e) as u16),
            i32::from_bytes(*array_ref!(block, 6, 4), e) as i64,
        );
    } else {
        return Err(anyhow!("Unhandled location data {:?}, expected variable loc", block));
    }

    Ok(expr)
}

fn process_inheritance_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<StructureBase> {
    ensure!(tag.kind == TagKind::Inheritance, "{:?} is not an Inheritance tag", tag.kind);

    let new_inheritance_id = unit.add(parent, gimli::DW_TAG_inheritance);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_inheritance_id);

    let mut name = None;
    let mut offset = None;
    let mut visibility = None;
    let mut virtual_base = false;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                // done in the fixup stage
            }
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                offset = Some(process_offset(block, info.e)?);
            }
            (AttributeKind::Private, _) => visibility = Some(Visibility::Private),
            (AttributeKind::Protected, _) => visibility = Some(Visibility::Protected),
            (AttributeKind::Public, _) => visibility = Some(Visibility::Public),
            (AttributeKind::Virtual, _) => virtual_base = true,
            _ => {
                bail!("Unhandled Inheritance attribute {:?}", attr);
            }
        }
    }
    if let Some(offs) = offset {
        unit.get_mut(new_inheritance_id)
            .set(gimli::DW_AT_data_member_location, unsigned_dwarf_value(offs));
    }
    if let Some(vis) = visibility {
        let accessibility = match vis {
            Visibility::Private => gimli::DW_ACCESS_public,
            Visibility::Protected => gimli::DW_ACCESS_protected,
            Visibility::Public => gimli::DW_ACCESS_public,
        };
        unit.get_mut(new_inheritance_id).set(
            gimli::DW_AT_visibility,
            gimli::write::AttributeValue::Accessibility(accessibility),
        );
    }

    let virtuality =
        if virtual_base { gimli::DW_VIRTUALITY_virtual } else { gimli::DW_VIRTUALITY_none };
    unit.get_mut(new_inheritance_id)
        .set(gimli::DW_AT_virtuality, gimli::write::AttributeValue::Virtuality(virtuality));

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Inheritance child {:?}", child.kind);
    }

    // let base_type = base_type.ok_or_else(|| anyhow!("Inheritance without base type: {:?}", tag))?;
    let offset = offset.ok_or_else(|| anyhow!("Inheritance without offset: {:?}", tag))?;
    Ok(StructureBase { name, offset, visibility, virtual_base })
}

fn ref_fixup_inheritance_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::Inheritance, "{:?} is not an Inheritance tag", tag.kind);

    let new_inheritance_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown struct"))?;

    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => {}
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                let base_type = process_type(unit, dwarf2_types, attr, info.e)?;
                let inheritance_tag = unit.get_mut(new_inheritance_id);
                inheritance_tag.set(
                    gimli::DW_AT_type,
                    gimli::write::AttributeValue::UnitRef(base_type.entry_id),
                );
            }
            (AttributeKind::Location, AttributeValue::Block(_)) => {}
            (AttributeKind::Private, _) => {}
            (AttributeKind::Protected, _) => {}
            (AttributeKind::Public, _) => {}
            (AttributeKind::Virtual, _) => {}
            _ => {
                bail!("Unhandled Inheritance attribute {:?}", attr);
            }
        }
    }
    Ok(())
}

fn process_structure_member_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<StructureMember> {
    ensure!(tag.kind == TagKind::Member, "{:?} is not a Member tag", tag.kind);

    let new_member_id = unit.add(parent, gimli::DW_TAG_member);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_member_id);

    let mut name = None;
    let mut offset = None;
    let mut byte_size = None;
    let mut bit_size = None;
    let mut bit_offset = None;
    let mut visibility = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => {
                name = Some(s.clone());
                unit.get_mut(new_member_id).set(
                    gimli::DW_AT_name,
                    gimli::write::AttributeValue::String(s.clone().into_bytes()),
                );
            }
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {}
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                let offs = process_offset(block, info.e)?;
                offset = Some(offs);
                unit.get_mut(new_member_id)
                    .set(gimli::DW_AT_data_member_location, unsigned_dwarf_value(offs));
            }
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::BitSize, &AttributeValue::Data4(value)) => bit_size = Some(value),
            (AttributeKind::BitOffset, &AttributeValue::Data2(value)) => bit_offset = Some(value),
            (AttributeKind::Private, _) => visibility = Some(Visibility::Private),
            (AttributeKind::Protected, _) => visibility = Some(Visibility::Protected),
            (AttributeKind::Public, _) => visibility = Some(Visibility::Public),
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled Member attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Member child {:?}", child.kind);
    }

    let offset = offset.ok_or_else(|| anyhow!("Member without offset: {:?}", tag))?;
    let bit = match (bit_size, bit_offset) {
        (Some(bit_size), Some(bit_offset)) => Some(BitData { bit_size, bit_offset }),
        (None, None) => None,
        _ => bail!("Mismatched bit attributes in Member: {tag:?}"),
    };
    let visibility = visibility.unwrap_or(Visibility::Public);
    Ok(StructureMember { name, offset, bit, visibility, byte_size })
}

fn ref_fixup_structure_member_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::Member, "{:?} is not a Member tag", tag.kind);

    let new_member_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown member type"))?;

    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                let member_type = process_type(unit, dwarf2_types, attr, info.e)?;
                unit.get_mut(new_member_id).set(
                    gimli::DW_AT_type,
                    gimli::write::AttributeValue::UnitRef(member_type.entry_id),
                );
            }
            _ => {}
        }
    }
    Ok(())
}

fn process_structure_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    inside_function: bool,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<StructureType> {
    ensure!(
        matches!(tag.kind, TagKind::StructureType | TagKind::ClassType),
        "{:?} is not a Structure type tag",
        tag.kind
    );

    let mut name = None;
    let mut byte_size = None;
    let mut nested = false;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => {
                name = Some(s.clone());
            }
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => {
                byte_size = Some(value);
            }
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                nested = true;
            }
            _ => {
                bail!("Unhandled structure attribute {:?}", attr);
            }
        }
    }

    let mut members = Vec::new();
    let mut static_members = Vec::new();
    let mut bases = Vec::new();
    let mut inner_types = Vec::new();
    let mut typedefs = Vec::new();

    let real_parent = if nested || inside_function { parent } else { unit.root() };

    let new_struct_id = unit.add(real_parent, gimli::DW_TAG_structure_type);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_struct_id);
    let new_struct_tag = unit.get_mut(new_struct_id);

    if let Some(ref name) = name {
        new_struct_tag.set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.clone().into_bytes()),
        );
    }

    if let Some(size) = byte_size {
        new_struct_tag.set(gimli::DW_AT_byte_size, unsigned_dwarf_value(size));
    }

    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::Inheritance => {
                bases.push(process_inheritance_tag(info, unit, new_struct_id, dwarf2_types, child)?)
            }
            TagKind::Member => members.push(process_structure_member_tag(
                info,
                unit,
                new_struct_id,
                dwarf2_types,
                child,
            )?),
            TagKind::Typedef => {
                match info.producer {
                    Producer::MWCC => {
                        // TODO handle visibility
                        // MWCC handles static members as typedefs for whatever reason
                        static_members.push(process_variable_tag(
                            info,
                            unit,
                            new_struct_id,
                            dwarf2_types,
                            child,
                        )?)
                    }
                    _ => {
                        typedefs.push(process_typedef_tag(
                            info,
                            unit,
                            new_struct_id,
                            dwarf2_types,
                            child,
                        )?);
                    }
                }
            }
            TagKind::Subroutine | TagKind::GlobalSubroutine => {
                // TODO
            }
            TagKind::GlobalVariable => {
                // TODO handle visibility
                static_members.push(process_variable_tag(
                    info,
                    unit,
                    new_struct_id,
                    dwarf2_types,
                    child,
                )?)
            }
            TagKind::StructureType | TagKind::ClassType => {
                inner_types.push(UserDefinedType::Structure(process_structure_tag(
                    info,
                    unit,
                    new_struct_id,
                    inside_function,
                    dwarf2_types,
                    child,
                )?))
            }
            TagKind::EnumerationType => inner_types.push(UserDefinedType::Enumeration(
                process_enumeration_tag(info, unit, new_struct_id, dwarf2_types, child)?,
            )),
            TagKind::UnionType => inner_types.push(UserDefinedType::Union(process_union_tag(
                info,
                unit,
                new_struct_id,
                dwarf2_types,
                child,
            )?)),
            TagKind::ArrayType | TagKind::SubroutineType | TagKind::PtrToMemberType => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled StructureType child {:?}", kind),
        }
    }

    Ok(StructureType {
        kind: if tag.kind == TagKind::ClassType {
            StructureKind::Class
        } else {
            StructureKind::Struct
        },
        name,
        byte_size,
        members,
        static_members,
        bases,
        inner_types,
    })
}

fn ref_fixup_structure_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(
        matches!(tag.kind, TagKind::StructureType | TagKind::ClassType),
        "{:?} is not a Structure type tag",
        tag.kind
    );

    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::Inheritance => {
                ref_fixup_inheritance_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::Member => {
                ref_fixup_structure_member_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::Typedef => {
                match info.producer {
                    Producer::MWCC => {
                        // TODO handle visibility
                        // MWCC handles static members as typedefs for whatever reason
                        ref_fixup_variable_tag(info, unit, dwarf2_types, child)?
                    }
                    _ => {
                        ref_fixup_typedef_tag(info, unit, dwarf2_types, child)?;
                    }
                }
            }
            TagKind::Subroutine | TagKind::GlobalSubroutine => {
                // TODO
            }
            TagKind::GlobalVariable => {
                // TODO handle visibility
                // TODO DWARF122
                ref_fixup_variable_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::StructureType | TagKind::ClassType => {
                ref_fixup_structure_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::EnumerationType => {}
            TagKind::UnionType => ref_fixup_union_tag(info, unit, dwarf2_types, child)?,
            TagKind::ArrayType | TagKind::SubroutineType | TagKind::PtrToMemberType => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled StructureType child {:?}", kind),
        }
    }
    Ok(())
}

fn process_array_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<ArrayType> {
    ensure!(tag.kind == TagKind::ArrayType, "{:?} is not an ArrayType tag", tag.kind);

    let new_array_id = unit.add(unit.root(), gimli::DW_TAG_array_type);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_array_id);

    // TODO DWARF122 remove these, as it has to be done in the fixup stage
    let mut subscr_data = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::SubscrData, AttributeValue::Block(data)) => {
                subscr_data = Some(
                    process_array_subscript_data(unit, dwarf2_types, data, info.e).with_context(
                        || format!("Failed to process SubscrData for tag: {tag:?}"),
                    )?,
                )
            }
            (AttributeKind::Ordering, val) => match val {
                AttributeValue::Data2(d2) => {
                    let order = ArrayOrdering::try_from_primitive(*d2)?;
                    if order == ArrayOrdering::ColMajor {
                        log::warn!("Column Major Ordering in Tag {}, Cannot guarantee array will be correct if original source is in different programming language.", tag.key);
                    }
                }
                _ => bail!("Unhandled ArrayType attribute {:?}", attr),
            },
            _ => {
                bail!("Unhandled ArrayType attribute {:?}", attr)
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled ArrayType child {:?}", child.kind);
    }

    let (element_type, dimensions) =
        subscr_data.ok_or_else(|| anyhow!("ArrayType without SubscrData: {:?}", tag))?;
    Ok(ArrayType { element_type: Box::from(element_type), dimensions })
}

fn ref_fixup_array_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::ArrayType, "{:?} is not an ArrayType tag", tag.kind);

    let new_array_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown array type"))?;

    let mut subscr_data = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::SubscrData, AttributeValue::Block(data)) => {
                subscr_data = Some(
                    process_array_subscript_data(unit, dwarf2_types, data, info.e).with_context(
                        || format!("Failed to process SubscrData for tag: {tag:?}"),
                    )?,
                )
            }
            (AttributeKind::Ordering, val) => match val {
                AttributeValue::Data2(d2) => {
                    let order = ArrayOrdering::try_from_primitive(*d2)?;
                    if order == ArrayOrdering::ColMajor {
                        log::warn!("Column Major Ordering in Tag {}, Cannot guarantee array will be correct if original source is in different programming language.", tag.key);
                    }
                }
                _ => bail!("Unhandled ArrayType attribute {:?}", attr),
            },
            _ => {
                bail!("Unhandled ArrayType attribute {:?}", attr)
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled ArrayType child {:?}", child.kind);
    }

    let (element_type, dimensions) =
        subscr_data.ok_or_else(|| anyhow!("ArrayType without SubscrData: {:?}", tag))?;

    unit.get_mut(new_array_id)
        .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(element_type.entry_id));

    for dimension in dimensions {
        let subrange_id = unit.add(new_array_id, gimli::DW_TAG_subrange_type);
        unit.get_mut(subrange_id)
            .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(dimension.index_type));
        if let Some(size) = dimension.size {
            unit.get_mut(subrange_id)
                .set(gimli::DW_AT_upper_bound, unsigned_dwarf_value(size.get() - 1));
        }
    }

    Ok(())
}

fn process_array_subscript_data(
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    data: &[u8],
    e: Endian,
) -> Result<(Type, Vec<ArrayDimension>)> {
    let mut element_type = None;
    let mut dimensions = Vec::new();
    let mut data = data;
    while !data.is_empty() {
        let format = SubscriptFormat::try_from(
            data.first().cloned().ok_or_else(|| anyhow!("Empty SubscrData"))?,
        )
        .context("Unknown array subscript format")?;
        data = &data[1..];
        match format {
            SubscriptFormat::FundTypeConstConst => {
                let index_type = FundType::try_from(u16::from_bytes(data[..2].try_into()?, e))
                    .context("Invalid fundamental type ID")?;
                let low_bound = u32::from_bytes(data[2..6].try_into()?, e);
                ensure!(low_bound == 0, "Invalid array low bound {low_bound}, expected 0");
                let high_bound = u32::from_bytes(data[6..10].try_into()?, e);
                data = &data[10..];
                let index_type = dwarf2_types
                    .fundamental_map
                    .get(&index_type)
                    .ok_or_else(|| anyhow!("Fundamental type missing"))?
                    .clone();
                dimensions.push(ArrayDimension {
                    index_type,
                    // u32::MAX will wrap to 0, meaning unbounded
                    size: NonZeroU32::new(high_bound.wrapping_add(1)),
                });
            }
            SubscriptFormat::FundTypeConstLocation => {
                let index_type = FundType::try_from(u16::from_bytes(*array_ref!(data, 0, 2), e))
                    .context("Invalid fundamental type ID")?;
                let low_bound = u32::from_bytes(*array_ref!(data, 2, 4), e);
                ensure!(low_bound == 0, "Invalid array low bound {low_bound}, expected 0");
                let size = u16::from_bytes(*array_ref!(data, 6, 2), e);
                let (block, remain) = data[8..].split_at(size as usize);
                let location = if block.is_empty() { 0 } else { process_offset(block, e)? };
                data = remain;
                let index_type = dwarf2_types
                    .fundamental_map
                    .get(&index_type)
                    .ok_or_else(|| anyhow!("Fundamental type missing"))?
                    .clone();
                dimensions.push(ArrayDimension { index_type, size: NonZeroU32::new(location) });
            }
            SubscriptFormat::ElementType => {
                let mut cursor = Cursor::new(data);
                // TODO: is this the right endianness to use for erased tags?
                let type_attr = read_attribute(&mut cursor, e, e)?;
                element_type = Some(process_type(unit, dwarf2_types, &type_attr, e)?);
                data = &data[cursor.position() as usize..];
            }
            _ => bail!("Unhandled subscript format type {:?}", format),
        }
    }
    let element_type = element_type.ok_or_else(|| anyhow!("ArrayType without ElementType"))?;
    Ok((element_type, dimensions))
}

fn process_enumeration_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<EnumerationType> {
    ensure!(tag.kind == TagKind::EnumerationType, "{:?} is not an EnumerationType tag", tag.kind);

    let new_enum_id = unit.add(parent, gimli::DW_TAG_enumeration_type);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_enum_id);
    let new_enum_tag = unit.get_mut(new_enum_id);

    let mut name = None;
    let mut byte_size = None;
    let mut members = Vec::new();
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::ElementList, AttributeValue::Block(data)) => {
                let mut cursor = Cursor::new(data);
                while cursor.position() < data.len() as u64 {
                    let value = match byte_size {
                        Some(1) => Some(i8::from_reader(&mut cursor, info.e)? as i32),
                        Some(2) => Some(i16::from_reader(&mut cursor, info.e)? as i32),
                        Some(4) => Some(i32::from_reader(&mut cursor, info.e)?),
                        _ => None,
                    };
                    let name = read_string(&mut cursor)?;
                    if let Some(value) = value {
                        members.push(EnumerationMember { name, value });
                    }
                }
            }
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled EnumerationType attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled EnumerationType child {:?}", child.kind);
    }

    let byte_size =
        byte_size.ok_or_else(|| anyhow!("EnumerationType without ByteSize: {:?}", tag))?;

    if info.producer == Producer::GCC {
        // for some reason enum members are reversed in GCC
        members.reverse();
    }

    if let Some(ref name) = name {
        new_enum_tag.set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.clone().into_bytes()),
        );
    }

    let encoding = match byte_size {
        1 => gimli::DW_ATE_unsigned_char,
        _ => gimli::DW_ATE_unsigned,
    };
    new_enum_tag.set(gimli::DW_AT_encoding, gimli::write::AttributeValue::Encoding(encoding));
    new_enum_tag.set(gimli::DW_AT_byte_size, unsigned_dwarf_value(byte_size));

    // Dwarf 2+ also specifies the type, not just the size
    let kind = match byte_size {
        1 => dwarf2_types.fundamental_map.get(&FundType::UnsignedChar),
        2 => dwarf2_types.fundamental_map.get(&FundType::UnsignedShort),
        4 => dwarf2_types.fundamental_map.get(&FundType::UnsignedInteger),
        8 => dwarf2_types.fundamental_map.get(&FundType::UnsignedLongLong),
        _ => {
            bail!("Wrong enum byte size {:?}", byte_size);
        }
    };

    if let Some(kind) = kind {
        new_enum_tag.set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(*kind));
    }

    for member in &members {
        let enumerator = unit.add(new_enum_id, gimli::DW_TAG_enumerator);
        unit.get_mut(enumerator).set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(member.name.clone().into_bytes()),
        );
        unit.get_mut(enumerator)
            .set(gimli::DW_AT_const_value, unsigned_dwarf_value(member.value as u32));
    }

    Ok(EnumerationType { name, byte_size, members })
}

fn process_union_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<UnionType> {
    ensure!(tag.kind == TagKind::UnionType, "{:?} is not a UnionType tag", tag.kind);

    let new_union_id = unit.add(parent, gimli::DW_TAG_union_type);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_union_id);

    let mut name = None;
    let mut byte_size = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::ByteSize, &AttributeValue::Data4(value)) => byte_size = Some(value),
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled UnionType attribute {:?}", attr);
            }
        }
    }

    let mut members = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::Member => members.push(process_structure_member_tag(
                info,
                unit,
                new_union_id,
                dwarf2_types,
                child,
            )?),
            TagKind::StructureType
            | TagKind::ArrayType
            | TagKind::EnumerationType
            | TagKind::UnionType
            | TagKind::ClassType
            | TagKind::SubroutineType
            | TagKind::PtrToMemberType
            | TagKind::Typedef => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled UnionType child {:?}", kind),
        }
    }

    let byte_size = byte_size.ok_or_else(|| anyhow!("UnionType without ByteSize: {:?}", tag))?;

    let new_union_tag = unit.get_mut(new_union_id);
    if let Some(ref name) = name {
        new_union_tag.set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.clone().into_bytes()),
        );
    }

    new_union_tag.set(gimli::DW_AT_byte_size, unsigned_dwarf_value(byte_size));

    Ok(UnionType { name, byte_size, members })
}

fn ref_fixup_union_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::UnionType, "{:?} is not a UnionType tag", tag.kind);

    for child in tag.children(&info.tags) {
        if matches!(child.kind, TagKind::Member) {
            ref_fixup_structure_member_tag(info, unit, dwarf2_types, child)?
        }
    }

    Ok(())
}

fn process_subroutine_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<SubroutineType> {
    let subroutine_type = match tag.kind {
        TagKind::GlobalSubroutine => gimli::DW_TAG_subprogram,
        TagKind::Subroutine => gimli::DW_TAG_subprogram,
        TagKind::SubroutineType => gimli::DW_TAG_subroutine_type,
        TagKind::InlinedSubroutine => gimli::DW_TAG_inlined_subroutine,
        _ => bail!("{:?} is not a Subroutine tag", tag.kind),
    };
    let new_subroutine_id = unit.add(parent, subroutine_type);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_subroutine_id);

    let mut name = None;
    let mut mangled_name = None;
    let mut prototyped = false;
    let mut parameters = Vec::new();
    let mut var_args = false;
    let mut references = Vec::new();
    let mut member_of = None;
    let mut inline = false;
    let mut start_address = None;
    let mut end_address = None;
    let mut virtual_ = false;
    // as opposed to a higher base class whose function is beging overridden
    let mut this_pointer_found = false;
    let mut direct_base_key = None;
    let mut const_ = false;
    let mut volatile_ = false;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {}
            (AttributeKind::Prototyped, _) => prototyped = true,
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => {
                start_address = Some(addr);
            }
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => {
                end_address = Some(addr);
            }
            (AttributeKind::MwGlobalRef, &AttributeValue::Reference(key)) => {
                references.push(key);
            }
            (AttributeKind::MwGlobalRefsBlock, AttributeValue::Block(_)) => {
                // Global references block
            }
            (AttributeKind::ReturnAddr, AttributeValue::Block(_block)) => {
                // let location = process_variable_location(block)?;
                // info!("ReturnAddr: {}", location);
            }
            (AttributeKind::Member, &AttributeValue::Reference(key)) => {
                member_of = Some(key);
            }
            (AttributeKind::MwPrologueEnd, &AttributeValue::Address(_addr)) => {
                // Prologue end
            }
            (AttributeKind::MwEpilogueStart, &AttributeValue::Address(_addr)) => {
                // Epilogue start
            }
            (
                AttributeKind::MwRestoreSp
                | AttributeKind::MwRestoreS0
                | AttributeKind::MwRestoreS1
                | AttributeKind::MwRestoreS2
                | AttributeKind::MwRestoreS3
                | AttributeKind::MwRestoreS4
                | AttributeKind::MwRestoreS5
                | AttributeKind::MwRestoreS6
                | AttributeKind::MwRestoreS7
                | AttributeKind::MwRestoreS8
                | AttributeKind::MwRestoreF20
                | AttributeKind::MwRestoreF21
                | AttributeKind::MwRestoreF22
                | AttributeKind::MwRestoreF23
                | AttributeKind::MwRestoreF24
                | AttributeKind::MwRestoreF25
                | AttributeKind::MwRestoreF26
                | AttributeKind::MwRestoreF27
                | AttributeKind::MwRestoreF28
                | AttributeKind::MwRestoreF29
                | AttributeKind::MwRestoreF30,
                AttributeValue::Block(_),
            ) => {
                // Restore register
            }
            (AttributeKind::Inline, _) => inline = true,
            (AttributeKind::Virtual, _) => virtual_ = true,
            (AttributeKind::Specification, &AttributeValue::Reference(_key)) => {}
            _ => {
                bail!("Unhandled SubroutineType attribute {:?}", attr);
            }
        }
    }

    let mut labels = Vec::new();
    let mut blocks_and_inlines = Vec::new();
    let mut inner_types = Vec::new();
    let mut typedefs = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::FormalParameter => {
                process_subroutine_parameter_tag(
                    info,
                    unit,
                    new_subroutine_id,
                    dwarf2_types,
                    child,
                )?;
            }
            TagKind::UnspecifiedParameters => var_args = true,
            TagKind::LocalVariable => {
                process_local_variable_tag(info, unit, new_subroutine_id, dwarf2_types, child)?;
            }
            TagKind::GlobalVariable => {
                // TODO GlobalVariable refs?
            }
            TagKind::Label => labels.push(process_subroutine_label_tag(info, child)?),
            TagKind::LexicalBlock => {
                if let Some(block) = process_subroutine_block_tag(
                    info,
                    unit,
                    new_subroutine_id,
                    dwarf2_types,
                    child,
                )? {
                    blocks_and_inlines.push(SubroutineNode::Block(block));
                }
            }
            TagKind::InlinedSubroutine => {
                process_subroutine_tag(info, unit, new_subroutine_id, dwarf2_types, child)?;
            }
            TagKind::StructureType | TagKind::ClassType => {
                inner_types.push(UserDefinedType::Structure(process_structure_tag(
                    info,
                    unit,
                    new_subroutine_id,
                    true,
                    dwarf2_types,
                    child,
                )?))
            }
            TagKind::EnumerationType => inner_types.push(UserDefinedType::Enumeration(
                process_enumeration_tag(info, unit, new_subroutine_id, dwarf2_types, child)?,
            )),
            TagKind::UnionType => inner_types.push(UserDefinedType::Union(process_union_tag(
                info,
                unit,
                new_subroutine_id,
                dwarf2_types,
                child,
            )?)),
            TagKind::Typedef => typedefs.push(process_typedef_tag(
                info,
                unit,
                new_subroutine_id,
                dwarf2_types,
                child,
            )?),
            TagKind::ArrayType => {
                process_array_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::SubroutineType => {
                process_subroutine_tag(info, unit, new_subroutine_id, dwarf2_types, child)?;
            }
            TagKind::PtrToMemberType => {
                // Variable type, ignore
                // TODO DWARF22 might have to parse these to set up types properly, do the compilers emit these inside here at all?
            }
            kind => bail!("Unhandled SubroutineType child {:?}", kind),
        }
    }

    // TODO DWARF122
    // let return_type = return_type
    //     .unwrap_or_else(|| Type { kind: TypeKind::Fundamental(FundType::Void), modifiers: vec![] });
    let direct_member_of = direct_base_key;
    let local = tag.kind == TagKind::Subroutine;

    let mut static_member = false;
    if let Producer::GCC = info.producer {
        // GCC doesn't retain namespaces, so this is a nice way to determine staticness
        static_member = member_of.is_some() && !this_pointer_found;
    }
    let override_ = virtual_ && member_of != direct_member_of;

    let new_subroutine_tag = unit.get_mut(new_subroutine_id);
    if let Some(ref name) = name {
        new_subroutine_tag
            .set(gimli::DW_AT_name, gimli::write::AttributeValue::String(name.as_bytes().to_vec()));
    }
    if let Some(start_address) = start_address {
        new_subroutine_tag.set(
            gimli::DW_AT_low_pc,
            gimli::write::AttributeValue::Address(gimli::write::Address::Constant(
                start_address as u64,
            )),
        );
    }
    if let Some(end_address) = end_address {
        new_subroutine_tag.set(
            gimli::DW_AT_high_pc,
            gimli::write::AttributeValue::Address(gimli::write::Address::Constant(
                end_address as u64,
            )),
        );
    }

    let subroutine = SubroutineType {
        name,
        mangled_name,
        return_type: None,
        parameters,
        var_args,
        prototyped,
        references,
        member_of,
        inline,
        virtual_,
    };
    Ok(subroutine)
}

fn ref_fixup_subroutine_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<SubroutineType> {
    let new_subroutine_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown subroutine"))?;

    let mut name = None;
    let mut mangled_name = None;
    let mut return_type = None;
    let mut prototyped = false;
    let mut parameters = Vec::new();
    let mut var_args = false;
    let mut references = Vec::new();
    let mut member_of = None;
    let mut inline = false;
    let mut virtual_ = false;
    // as opposed to a higher base class whose function is beging overridden
    let mut this_pointer_found = false;
    let mut direct_base_key = None;
    let mut const_ = false;
    let mut volatile_ = false;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                return_type = Some(process_type(unit, dwarf2_types, attr, info.e)?);
            }
            (AttributeKind::Prototyped, _) => prototyped = true,
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => {}
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => {}
            (AttributeKind::MwGlobalRef, &AttributeValue::Reference(key)) => {
                references.push(key);
            }
            (AttributeKind::MwGlobalRefsBlock, AttributeValue::Block(_)) => {
                // Global references block
            }
            (AttributeKind::ReturnAddr, AttributeValue::Block(_block)) => {
                // let location = process_variable_location(block)?;
                // info!("ReturnAddr: {}", location);
            }
            (AttributeKind::Member, &AttributeValue::Reference(key)) => {
                member_of = Some(key);
            }
            (AttributeKind::MwPrologueEnd, &AttributeValue::Address(_addr)) => {
                // Prologue end
            }
            (AttributeKind::MwEpilogueStart, &AttributeValue::Address(_addr)) => {
                // Epilogue start
            }
            (
                AttributeKind::MwRestoreSp
                | AttributeKind::MwRestoreS0
                | AttributeKind::MwRestoreS1
                | AttributeKind::MwRestoreS2
                | AttributeKind::MwRestoreS3
                | AttributeKind::MwRestoreS4
                | AttributeKind::MwRestoreS5
                | AttributeKind::MwRestoreS6
                | AttributeKind::MwRestoreS7
                | AttributeKind::MwRestoreS8
                | AttributeKind::MwRestoreF20
                | AttributeKind::MwRestoreF21
                | AttributeKind::MwRestoreF22
                | AttributeKind::MwRestoreF23
                | AttributeKind::MwRestoreF24
                | AttributeKind::MwRestoreF25
                | AttributeKind::MwRestoreF26
                | AttributeKind::MwRestoreF27
                | AttributeKind::MwRestoreF28
                | AttributeKind::MwRestoreF29
                | AttributeKind::MwRestoreF30,
                AttributeValue::Block(_),
            ) => {
                // Restore register
            }
            (AttributeKind::Inline, _) => inline = true,
            (AttributeKind::Virtual, _) => virtual_ = true,
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = ref_fixup_subroutine_tag(info, unit, dwarf2_types, spec_tag)?;
                name = name.or(spec.name);
                mangled_name = mangled_name.or(spec.mangled_name);
                return_type = return_type.or(spec.return_type);
                prototyped = prototyped || spec.prototyped;
                parameters.extend(spec.parameters);
                var_args = var_args || spec.var_args;
                references.extend(spec.references);
                member_of = member_of.or(spec.member_of);
                inline = inline || spec.inline;
                virtual_ = virtual_ || spec.virtual_;
            }
            _ => {
                bail!("Unhandled SubroutineType attribute {:?}", attr);
            }
        }
    }

    let mut blocks_and_inlines = Vec::new();
    let mut typedefs = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::FormalParameter => {
                let param = ref_fixup_subroutine_parameter_tag(info, unit, dwarf2_types, child)?;
                parameters.push(param);
            }
            TagKind::UnspecifiedParameters => var_args = true,
            TagKind::LocalVariable => {
                ref_fixup_local_variable_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::GlobalVariable => {
                // TODO GlobalVariable refs?
            }
            TagKind::Label => {
                // TODO DWARF122 is this needed?
                // ref_fixup_subroutine_label_tag(info, child)?;
            }
            TagKind::LexicalBlock => {
                if let Some(block) =
                    process_subroutine_block_tag(info, unit, unit.root(), dwarf2_types, child)?
                {
                    blocks_and_inlines.push(SubroutineNode::Block(block));
                }
            }
            TagKind::InlinedSubroutine => blocks_and_inlines.push(SubroutineNode::Inline(
                ref_fixup_subroutine_tag(info, unit, dwarf2_types, child)?,
            )),
            TagKind::StructureType | TagKind::ClassType => {
                ref_fixup_structure_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::EnumerationType => {}
            TagKind::UnionType => {
                ref_fixup_union_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::Typedef => {
                typedefs.push(ref_fixup_typedef_tag(info, unit, dwarf2_types, child)?)
            }
            TagKind::ArrayType => {
                ref_fixup_array_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::SubroutineType => {
                ref_fixup_subroutine_tag(info, unit, dwarf2_types, child)?;
            }
            TagKind::PtrToMemberType => {
                // Variable type, ignore
                // TODO DWARF22 might have to parse these to set up types properly
            }
            kind => bail!("Unhandled SubroutineType child {:?}", kind),
        }
    }

    let direct_member_of = direct_base_key;
    let local = tag.kind == TagKind::Subroutine;

    let mut static_member = false;
    if let Producer::GCC = info.producer {
        // GCC doesn't retain namespaces, so this is a nice way to determine staticness
        static_member = member_of.is_some() && !this_pointer_found;
    }
    let override_ = virtual_ && member_of != direct_member_of;

    let new_subroutine_tag = unit.get_mut(new_subroutine_id);
    if let Some(ref return_type) = return_type {
        new_subroutine_tag
            .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(return_type.entry_id));
    }

    let subroutine = SubroutineType {
        name,
        mangled_name,
        return_type,
        parameters,
        var_args,
        prototyped,
        references,
        member_of,
        inline,
        virtual_,
    };
    Ok(subroutine)
}

fn process_subroutine_label_tag(info: &DwarfInfo, tag: &Tag) -> Result<SubroutineLabel> {
    ensure!(tag.kind == TagKind::Label, "{:?} is not a Label tag", tag.kind);

    let mut name = None;
    let mut address = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => address = Some(addr),
            _ => bail!("Unhandled Label attribute {:?}", attr),
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Label child {:?}", child.kind);
    }

    let name = name.ok_or_else(|| anyhow!("Label without name: {:?}", tag))?;
    let address = address.ok_or_else(|| anyhow!("Label without address: {:?}", tag))?;
    Ok(SubroutineLabel { name, address })
}

fn process_subroutine_block_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<Option<SubroutineBlock>> {
    ensure!(tag.kind == TagKind::LexicalBlock, "{:?} is not a LexicalBlock tag", tag.kind);

    let mut name = None;
    let mut start_address = None;
    let mut end_address = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => start_address = Some(addr),
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => end_address = Some(addr),
            _ => bail!("Unhandled Label attribute {:?}", attr),
        }
    }

    let mut variables = Vec::new();
    let mut blocks_and_inlines = Vec::new();
    let mut inner_types = Vec::new();
    for child in tag.children(&info.tags) {
        match child.kind {
            TagKind::LocalVariable => {
                // TODO DWARF12
                // variables.push(process_local_variable_tag(info, unit, dwarf2_types, child)?)
            }
            TagKind::GlobalVariable => {
                // TODO GlobalVariable refs?
            }
            TagKind::LexicalBlock => {
                if let Some(block) =
                    process_subroutine_block_tag(info, unit, unit.root(), dwarf2_types, child)?
                {
                    // TOO DWARF122 parent
                    blocks_and_inlines.push(SubroutineNode::Block(block));
                }
            }
            TagKind::InlinedSubroutine => {
                // TODO DWARF122
                // blocks_and_inlines.push(SubroutineNode::Inline(process_subroutine_tag(
                //     info,
                //     unit,
                //     unit.root(), // TODO DWARF122 pass the block_id here
                //     dwarf2_types,
                //     child,
                // )?));
            }
            TagKind::StructureType | TagKind::ClassType => {
                inner_types.push(UserDefinedType::Structure(process_structure_tag(
                    info,
                    unit,
                    unit.root(),
                    true,
                    dwarf2_types,
                    child,
                )?))
            } // TOO DWARF122 parent
            TagKind::EnumerationType => {
                // TODO pass correct parent
                inner_types.push(UserDefinedType::Enumeration(process_enumeration_tag(
                    info,
                    unit,
                    unit.root(),
                    dwarf2_types,
                    child,
                )?));
            }
            TagKind::UnionType => {
                // TODO DWARF122 pass parent
                inner_types.push(UserDefinedType::Union(process_union_tag(
                    info,
                    unit,
                    unit.root(),
                    dwarf2_types,
                    child,
                )?))
            }
            TagKind::Typedef => {
                // TODO DWARF122 pass parent
                process_typedef_tag(info, unit, unit.root(), dwarf2_types, child)?
            }
            TagKind::ArrayType | TagKind::SubroutineType | TagKind::PtrToMemberType => {
                // Variable type, ignore
            }
            kind => bail!("Unhandled LexicalBlock child {:?}", kind),
        }
    }

    Ok(Some(SubroutineBlock {
        name,
        start_address,
        end_address,
        variables,
        blocks_and_inlines,
        inner_types,
    }))
}

fn process_subroutine_parameter_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::FormalParameter, "{:?} is not a FormalParameter tag", tag.kind);

    let new_parameter_id = unit.add(parent, gimli::DW_TAG_formal_parameter);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_parameter_id);

    let mut name = None;
    let mut location = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {}
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                if !block.is_empty() {
                    location = Some(process_variable_location(block, tag.data_endian)?);
                }
            }
            (AttributeKind::MwDwarf2Location, AttributeValue::Block(_block)) => {
                // TODO?
                // info!("MwDwarf2Location: {:?} in {:?}", block, tag);
            }
            (AttributeKind::ConstValueBlock2 | AttributeKind::ConstValueBlock4, _) => {
                // TODO?
                // info!("ConstValueBlock: {:?} in {:?}", block, tag);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(_key)) => {}
            _ => bail!("Unhandled SubroutineParameter attribute {:?}", attr),
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled SubroutineParameter child {:?}", child.kind);
    }

    if let Some(ref name) = name {
        unit.get_mut(new_parameter_id).set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.clone().into_bytes()),
        );
    }
    if let Some(location) = location {
        unit.get_mut(new_parameter_id)
            .set(gimli::DW_AT_location, gimli::write::AttributeValue::Exprloc(location));
    }

    Ok(())
}

fn ref_fixup_subroutine_parameter_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<SubroutineParameter> {
    ensure!(tag.kind == TagKind::FormalParameter, "{:?} is not a FormalParameter tag", tag.kind);

    let new_parameter_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown parameter tag"))?;

    let mut name = None;
    let mut kind = None;
    let mut location = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                kind = Some(process_type(unit, dwarf2_types, attr, info.e)?);
            }
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                if !block.is_empty() {
                    location = Some(process_variable_location(block, tag.data_endian)?);
                }
            }
            (AttributeKind::MwDwarf2Location, AttributeValue::Block(_block)) => {
                // TODO?
                // info!("MwDwarf2Location: {:?} in {:?}", block, tag);
            }
            (AttributeKind::ConstValueBlock2 | AttributeKind::ConstValueBlock4, _) => {
                // TODO?
                // info!("ConstValueBlock: {:?} in {:?}", block, tag);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = ref_fixup_subroutine_parameter_tag(info, unit, dwarf2_types, spec_tag)?;
                name = name.or(spec.name);
                kind = kind.or(Some(spec.kind));
                location = location.or(spec.location);
            }
            _ => bail!("Unhandled SubroutineParameter attribute {:?}", attr),
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled SubroutineParameter child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("SubroutineParameter without type: {:?}", tag))?;

    unit.get_mut(new_parameter_id)
        .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(kind.entry_id));

    Ok(SubroutineParameter { name, kind, location })
}

fn process_local_variable_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::LocalVariable, "{:?} is not a LocalVariable tag", tag.kind);

    let new_local_var_id = unit.add(parent, gimli::DW_TAG_variable);
    dwarf2_types.old_new_tag_map.insert(tag.key, new_local_var_id);

    let mut mangled_name = None;
    let mut name = None;
    let mut location = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {}
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                if !block.is_empty() {
                    location = Some(process_variable_location(block, tag.data_endian)?);
                }
            }
            (AttributeKind::MwDwarf2Location, AttributeValue::Block(_block)) => {
                // TODO?
                // info!("MwDwarf2Location: {:?} in {:?}", block, tag);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(_key)) => {}
            _ => {
                bail!("Unhandled LocalVariable attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled LocalVariable child {:?}", child.kind);
    }

    if let Some(ref name) = name {
        unit.get_mut(new_local_var_id).set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.clone().into_bytes()),
        );
    }
    if let Some(location) = location {
        unit.get_mut(new_local_var_id)
            .set(gimli::DW_AT_location, gimli::write::AttributeValue::Exprloc(location));
    }

    Ok(())
}

fn ref_fixup_local_variable_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<SubroutineVariable> {
    ensure!(tag.kind == TagKind::LocalVariable, "{:?} is not a LocalVariable tag", tag.kind);

    let new_parameter_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown local variable"))?;

    let mut mangled_name = None;
    let mut name = None;
    let mut kind = None;
    let mut location = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                kind = Some(process_type(unit, dwarf2_types, attr, info.e)?);
            }
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                if !block.is_empty() {
                    location = Some(process_variable_location(block, tag.data_endian)?);
                }
            }
            (AttributeKind::MwDwarf2Location, AttributeValue::Block(_block)) => {
                // TODO?
                // info!("MwDwarf2Location: {:?} in {:?}", block, tag);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = ref_fixup_local_variable_tag(info, unit, dwarf2_types, spec_tag)?;
                name = name.or(spec.name);
                kind = kind.or(Some(spec.kind));
                location = location.or(spec.location);
            }
            _ => {
                bail!("Unhandled LocalVariable attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled LocalVariable child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("LocalVariable without type: {:?}", tag))?;

    unit.get_mut(new_parameter_id)
        .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(kind.entry_id));

    Ok(SubroutineVariable { name, mangled_name, kind, location })
}

// TODO DWARF122
fn process_ptr_to_member_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<PtrToMemberType> {
    ensure!(tag.kind == TagKind::PtrToMemberType, "{:?} is not a PtrToMemberType tag", tag.kind);

    let mut kind = None;
    let mut containing_type = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                // TODO DWARF122 types
                // kind = Some(process_type(unit, dwarf2_types, attr, info.e)?);
            }
            (AttributeKind::ContainingType, &AttributeValue::Reference(key)) => {
                containing_type = Some(key)
            }
            _ => {
                bail!("Unhandled PtrToMemberType attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled PtrToMemberType child {:?}", child.kind);
    }

    let kind = kind.ok_or_else(|| anyhow!("PtrToMemberType without type: {:?}", tag))?;
    let containing_type = containing_type
        .ok_or_else(|| anyhow!("PtrToMemberType without containing type: {:?}", tag))?;
    Ok(PtrToMemberType { kind, containing_type })
}

pub fn ud_type(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<UserDefinedType> {
    match tag.kind {
        TagKind::ArrayType => {
            Ok(UserDefinedType::Array(process_array_tag(info, unit, dwarf2_types, tag)?))
        }
        TagKind::StructureType | TagKind::ClassType => Ok(UserDefinedType::Structure(
            process_structure_tag(info, unit, unit.root(), false, dwarf2_types, tag)?,
        )),
        TagKind::EnumerationType => Ok(UserDefinedType::Enumeration(process_enumeration_tag(
            info,
            unit,
            unit.root(),
            dwarf2_types,
            tag,
        )?)),
        TagKind::UnionType => Ok(UserDefinedType::Union(process_union_tag(
            info,
            unit,
            unit.root(),
            dwarf2_types,
            tag,
        )?)),
        TagKind::SubroutineType | TagKind::GlobalSubroutine | TagKind::Subroutine => {
            Ok(UserDefinedType::Subroutine(process_subroutine_tag(
                info,
                unit,
                unit.root(),
                dwarf2_types,
                tag,
            )?))
        }
        TagKind::PtrToMemberType => Ok(UserDefinedType::PtrToMember(process_ptr_to_member_tag(
            info,
            unit,
            dwarf2_types,
            tag,
        )?)),
        kind => Err(anyhow!("Unhandled user defined type {kind:?}")),
    }
}

pub fn process_modifiers(block: &[u8]) -> Result<Vec<Modifier>> {
    let mut out = Vec::with_capacity(block.len());
    for &b in block {
        out.push(Modifier::parse_int(b)?);
    }
    Ok(out)
}

pub fn process_type(
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    attr: &Attribute,
    e: Endian,
) -> Result<Type> {
    match (attr.kind, &attr.value) {
        (AttributeKind::FundType, &AttributeValue::Data2(type_id)) => {
            let fund_type = FundType::parse_int(type_id)
                .with_context(|| format!("Invalid fundamental type ID '{type_id:04X}'"))?;
            let entry_id = dwarf2_types
                .fundamental_map
                .get(&fund_type)
                .cloned()
                .ok_or_else(|| anyhow!("Unknown fundamental type {:?}", fund_type))?;
            Ok(Type { kind: TypeKind::Fundamental(fund_type), modifiers: vec![], entry_id })
        }
        (AttributeKind::ModFundType, AttributeValue::Block(ops)) => {
            let type_id = u16::from_bytes(ops[ops.len() - 2..].try_into()?, e);
            let fund_type = FundType::parse_int(type_id)
                .with_context(|| format!("Invalid fundamental type ID '{type_id:04X}'"))?;
            let modifiers = process_modifiers(&ops[..ops.len() - 2])?;
            let entry_id = dwarf2_types
                .fundamental_map
                .get(&fund_type)
                .cloned()
                .ok_or_else(|| anyhow!("Unknown fundamental type {:?}", fund_type))?;
            let modified_type_id =
                create_or_get_modified_type(unit, dwarf2_types, entry_id, &modifiers)?;
            Ok(Type {
                kind: TypeKind::Fundamental(fund_type),
                modifiers,
                entry_id: modified_type_id,
            })
        }
        (AttributeKind::UserDefType, &AttributeValue::Reference(key)) => {
            let entry_id = dwarf2_types
                .old_new_tag_map
                .get(&key)
                .cloned()
                .ok_or_else(|| anyhow!("Unknown user type."))?;
            Ok(Type { kind: TypeKind::UserDefined(key), modifiers: vec![], entry_id })
        }
        (AttributeKind::ModUDType, AttributeValue::Block(ops)) => {
            let ud_ref = u32::from_bytes(ops[ops.len() - 4..].try_into()?, e);
            let modifiers = process_modifiers(&ops[..ops.len() - 4])?;
            let entry_id = dwarf2_types
                .old_new_tag_map
                .get(&ud_ref)
                .cloned()
                .ok_or_else(|| anyhow!("Unknown user type.."))?;
            let modified_type_id =
                create_or_get_modified_type(unit, dwarf2_types, entry_id, &modifiers)?;
            Ok(Type { kind: TypeKind::UserDefined(ud_ref), modifiers, entry_id: modified_type_id })
        }
        _ => Err(anyhow!("Invalid type attribute {:?}", attr)),
    }
}

fn create_or_get_modified_type(
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    base_id: UnitEntryId,
    modifiers: &Vec<Modifier>,
) -> Result<UnitEntryId> {
    let mut modified_type_id = base_id;
    if modifiers.is_empty() {
        return Ok(modified_type_id);
    }
    // get the first element
    let mut checked_modifiers = Vec::new();
    // Create type as we go along the way with different modifiers and save them to our map
    // We go right to left
    // TODO we need this same logic for fundamental types
    // TODO? doing the lookup starting with all the modifiers would be faster
    for modifier in modifiers.iter().rev() {
        checked_modifiers.push(*modifier);
        match dwarf2_types.modified_type_id_map.entry((base_id, checked_modifiers.clone())) {
            hash_map::Entry::Vacant(v) => {
                // TODO DWARF122 helper function for these?
                match modifier {
                    Modifier::MwPointerTo => todo!(),
                    Modifier::PointerTo => {
                        // TODO what do we do inside structs and functions? put them into the root or should we set the parent "correctly"?
                        let entry_id = unit.add(unit.root(), gimli::DW_TAG_pointer_type);
                        // TODO unhardcode size?
                        unit.get_mut(entry_id)
                            .set(gimli::DW_AT_byte_size, unsigned_dwarf_value(4 as u8));
                        unit.get_mut(entry_id).set(
                            gimli::DW_AT_type,
                            gimli::write::AttributeValue::UnitRef(modified_type_id),
                        );
                        v.insert(entry_id);
                        modified_type_id = entry_id;
                    }
                    Modifier::ReferenceTo => {
                        let entry_id = unit.add(unit.root(), gimli::DW_TAG_reference_type);
                        unit.get_mut(entry_id)
                            .set(gimli::DW_AT_byte_size, unsigned_dwarf_value(4 as u8));
                        unit.get_mut(entry_id).set(
                            gimli::DW_AT_type,
                            gimli::write::AttributeValue::UnitRef(modified_type_id),
                        );
                        v.insert(entry_id);
                        modified_type_id = entry_id;
                    }
                    Modifier::Const => {
                        let entry_id = unit.add(unit.root(), gimli::DW_TAG_const_type);
                        unit.get_mut(entry_id).set(
                            gimli::DW_AT_type,
                            gimli::write::AttributeValue::UnitRef(modified_type_id),
                        );
                        v.insert(entry_id);
                        modified_type_id = entry_id;
                    }
                    Modifier::Volatile => {
                        let entry_id = unit.add(unit.root(), gimli::DW_TAG_volatile_type);
                        unit.get_mut(entry_id).set(
                            gimli::DW_AT_type,
                            gimli::write::AttributeValue::UnitRef(modified_type_id),
                        );
                        v.insert(entry_id);
                        modified_type_id = entry_id;
                    }
                }
            }
            hash_map::Entry::Occupied(v) => {
                modified_type_id = v.get().clone();
            }
        }
    }

    Ok(modified_type_id)
}

pub fn process_compile_unit(tag: &Tag) -> Result<CompileUnit> {
    ensure!(tag.kind == TagKind::CompileUnit, "{:?} is not a CompileUnit tag", tag.kind);

    let mut name = None;
    let mut producer = None;
    let mut comp_dir = None;
    let mut language = None;
    let mut start_address = None;
    let mut end_address = None;
    let mut gcc_srcfile_name_offset = None;
    let mut gcc_srcinfo_offset = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::Producer, AttributeValue::String(s)) => producer = Some(s.clone()),
            (AttributeKind::CompDir, AttributeValue::String(s)) => comp_dir = Some(s.clone()),
            (AttributeKind::Language, &AttributeValue::Data4(value)) => {
                language = Some(Language::try_from_primitive(value)?)
            }
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => start_address = Some(addr),
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => end_address = Some(addr),
            (AttributeKind::StmtList, AttributeValue::Data4(_value)) => {
                // TODO DWARF122 .line support
            }

            (AttributeKind::GccSfName, &AttributeValue::Data4(value)) => {
                gcc_srcfile_name_offset = Some(value)
            }
            (AttributeKind::GccSfInfo, &AttributeValue::Data4(value)) => {
                gcc_srcinfo_offset = Some(value)
            }
            _ => {
                bail!("Unhandled CompileUnit attribute {:?}", attr);
            }
        }
    }

    let name = name.ok_or_else(|| anyhow!("CompileUnit without Name: {:?}", tag))?;
    Ok(CompileUnit {
        name,
        producer,
        comp_dir,
        language,
        start_address,
        end_address,
        gcc_srcfile_name_offset,
        gcc_srcinfo_offset,
    })
}

pub fn process_overlay_branch(tag: &Tag) -> Result<OverlayBranch> {
    ensure!(tag.kind == TagKind::MwOverlayBranch, "{:?} is not an OverlayBranch tag", tag.kind);

    let mut name = None;
    let mut id = None;
    let mut start_address = None;
    let mut end_address = None;
    let mut compile_unit = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Member, AttributeValue::Reference(addr)) => compile_unit = Some(*addr),
            (AttributeKind::MwOverlayName, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwOverlayId, AttributeValue::Data4(value)) => id = Some(*value),
            (AttributeKind::LowPc, &AttributeValue::Address(addr)) => start_address = Some(addr),
            (AttributeKind::HighPc, &AttributeValue::Address(addr)) => end_address = Some(addr),
            (AttributeKind::Name, AttributeValue::String(_s)) => {
                // TODO
            }
            _ => bail!("Unhandled OverlayBranch attribute {:?}", attr),
        }
    }

    let name = name.ok_or_else(|| anyhow!("OverlayBranch without Name: {:?}", tag))?;
    let id = id.ok_or_else(|| anyhow!("OverlayBranch without Id: {:?}", tag))?;
    let start_address =
        start_address.ok_or_else(|| anyhow!("OverlayBranch without LowPc: {:?}", tag))?;
    let end_address =
        end_address.ok_or_else(|| anyhow!("OverlayBranch without HighPc: {:?}", tag))?;
    Ok(OverlayBranch { name, id, start_address, end_address, compile_unit })
}

pub fn process_cu_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<TagType> {
    match tag.kind {
        TagKind::Typedef => {
            Ok(TagType::Typedef(process_typedef_tag(info, unit, unit.root(), dwarf2_types, tag)?))
        }
        TagKind::GlobalVariable | TagKind::LocalVariable => {
            Ok(TagType::Variable(process_variable_tag(info, unit, unit.root(), dwarf2_types, tag)?))
        }
        TagKind::StructureType
        | TagKind::ArrayType
        | TagKind::EnumerationType
        | TagKind::UnionType
        | TagKind::ClassType
        | TagKind::SubroutineType
        | TagKind::GlobalSubroutine
        | TagKind::Subroutine
        | TagKind::PtrToMemberType => {
            Ok(TagType::UserDefined(Box::new(ud_type(info, unit, dwarf2_types, tag)?)))
        }
        kind => Err(anyhow!("Unhandled root tag type {:?}", kind)),
    }
}

pub fn ref_fixup_cu_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    match tag.kind {
        // TODO DWARF122 subroutine, ptrtomember
        TagKind::SubroutineType | TagKind::GlobalSubroutine | TagKind::Subroutine => {
            ref_fixup_subroutine_tag(info, unit, dwarf2_types, tag).map(|_tag| ())
        }
        TagKind::ArrayType => ref_fixup_array_tag(info, unit, dwarf2_types, tag),
        TagKind::Typedef => ref_fixup_typedef_tag(info, unit, dwarf2_types, tag).map(|_tag| ()),
        TagKind::UnionType => ref_fixup_union_tag(info, unit, dwarf2_types, tag),
        TagKind::GlobalVariable | TagKind::LocalVariable => {
            ref_fixup_variable_tag(info, unit, dwarf2_types, tag)
        }
        TagKind::ClassType | TagKind::StructureType => {
            ref_fixup_structure_tag(info, unit, dwarf2_types, tag)
        }
        _ => Ok(()),
    }
}

/// Logic to skip uninteresting tags
pub fn should_skip_tag(tag_type: &TagType, is_erased: bool) -> bool {
    match tag_type {
        TagType::Variable(_) => is_erased,
        TagType::Typedef(_) => false,
        TagType::UserDefined(t) => !t.is_definition(),
    }
}

fn process_typedef_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    ensure!(tag.kind == TagKind::Typedef, "{:?} is not a typedef tag", tag.kind);

    // Create it only if it doesn't exist (because of specification tags)
    let new_typedef_id = *dwarf2_types
        .old_new_tag_map
        .entry(tag.key)
        .or_insert_with(|| unit.add(parent, gimli::DW_TAG_typedef));

    let mut name = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {}
            (AttributeKind::Member, _) => {
                // can be ignored for now
            }
            (AttributeKind::Specification, &AttributeValue::Reference(_key)) => {}
            _ => {
                bail!("Unhandled Typedef attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Typedef child {:?}", child.kind);
    }

    let name = name.ok_or_else(|| anyhow!("Typedef without Name: {:?}", tag))?;

    unit.get_mut(new_typedef_id)
        .set(gimli::DW_AT_name, gimli::write::AttributeValue::String(name.clone().into_bytes()));

    Ok(())
}

// TODO DWARF122 call this in the fixup of subroutines and blocks
fn ref_fixup_typedef_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<TypedefTag> {
    ensure!(tag.kind == TagKind::Typedef, "{:?} is not a typedef tag", tag.kind);

    let mut name = None;
    let mut kind = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                kind = Some(process_type(unit, dwarf2_types, attr, info.e)?);
            }
            (AttributeKind::Specification, &AttributeValue::Reference(key)) => {
                let spec_tag = info
                    .tags
                    .get(&key)
                    .ok_or_else(|| anyhow!("Failed to locate specification tag {}", key))?;
                // Merge attributes from specification tag
                let spec = ref_fixup_typedef_tag(info, unit, dwarf2_types, spec_tag)?;
                name = name.or(Some(spec.name));
                kind = kind.or(Some(spec.kind));
            }
            _ => {}
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Typedef child {:?}", child.kind);
    }

    let name = name.ok_or_else(|| anyhow!("Typedef without Name: {:?}", tag))?;
    let kind = kind.ok_or_else(|| anyhow!("Typedef without Type: {:?}", tag))?;

    let new_typedef_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown typedef"))?;

    unit.get_mut(new_typedef_id)
        .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(kind.entry_id));

    Ok(TypedefTag { name, kind })
}

fn process_variable_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    parent: gimli::write::UnitEntryId,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<VariableTag> {
    let is_variable = match tag.kind {
        TagKind::GlobalVariable | TagKind::LocalVariable => true,
        TagKind::Typedef if info.producer == Producer::MWCC => true,
        _ => false,
    };

    ensure!(is_variable, "{:?} is not a variable tag", tag.kind);

    let mut name = None;
    let mut mangled_name = None;
    let mut address = None;
    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (AttributeKind::Sibling, _) => {}
            (AttributeKind::Name, AttributeValue::String(s)) => name = Some(s.clone()),
            (AttributeKind::MwMangled, AttributeValue::String(s)) => mangled_name = Some(s.clone()),
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {}
            (AttributeKind::Location, AttributeValue::Block(block)) => {
                address = Some(process_address(block, info.e)?)
            }
            (AttributeKind::Member, &AttributeValue::Reference(_key)) => {
                // Pointer to parent structure, ignore
            }
            _ => {
                bail!("Unhandled Variable attribute {:?}", attr);
            }
        }
    }

    if let Some(child) = tag.children(&info.tags).first() {
        bail!("Unhandled Variable child {:?}", child.kind);
    }

    // let kind = kind.ok_or_else(|| anyhow!("Variable without Type: {:?}", tag))?;
    let local = tag.kind == TagKind::LocalVariable;

    let global_id = unit.add(parent, gimli::DW_TAG_variable);
    dwarf2_types.old_new_tag_map.insert(tag.key, global_id);
    let global_var = unit.get_mut(global_id);
    if let Some(ref name) = name {
        global_var.set(
            gimli::DW_AT_name,
            gimli::write::AttributeValue::String(name.clone().into_bytes()),
        );
    }
    if let Some(address) = address {
        let mut expr = gimli::write::Expression::new();
        expr.op_addr(gimli::write::Address::Constant(address as u64));
        global_var.set(gimli::DW_AT_location, gimli::write::AttributeValue::Exprloc(expr));
    }

    Ok(VariableTag { name, mangled_name, address, local })
}

fn ref_fixup_variable_tag(
    info: &DwarfInfo,
    unit: &mut gimli::write::Unit,
    dwarf2_types: &mut Dwarf2Types,
    tag: &Tag,
) -> Result<()> {
    let is_variable = match tag.kind {
        TagKind::GlobalVariable | TagKind::LocalVariable => true,
        TagKind::Typedef if info.producer == Producer::MWCC => true,
        _ => false,
    };

    ensure!(is_variable, "{:?} is not a variable tag", tag.kind);

    let new_variable_id = dwarf2_types
        .old_new_tag_map
        .get(&tag.key)
        .cloned()
        .ok_or_else(|| anyhow!("Unknown struct"))?;

    let mut kind = None;

    for attr in &tag.attributes {
        match (attr.kind, &attr.value) {
            (
                AttributeKind::FundType
                | AttributeKind::ModFundType
                | AttributeKind::UserDefType
                | AttributeKind::ModUDType,
                _,
            ) => {
                kind = Some(process_type(unit, dwarf2_types, attr, info.e)?);
            }
            _ => {}
        }
    }

    if let Some(kind) = kind {
        unit.get_mut(new_variable_id)
            .set(gimli::DW_AT_type, gimli::write::AttributeValue::UnitRef(kind.entry_id));
    }

    Ok(())
}

const FUNDAMENTALS: [FundType; 19] = [
    FundType::Char,
    FundType::SignedChar,
    FundType::UnsignedChar,
    FundType::Short,
    FundType::SignedShort,
    FundType::UnsignedShort,
    FundType::Integer,
    FundType::SignedInteger,
    FundType::UnsignedInteger,
    FundType::Long,
    FundType::SignedLong,
    FundType::UnsignedLong,
    FundType::LongLong,
    FundType::SignedLongLong,
    FundType::UnsignedLongLong,
    FundType::Boolean,
    FundType::Float,
    FundType::DblPrecFloat,
    FundType::Void,
];

pub fn build_fundemantal_typemap(
    unit: &mut gimli::write::Unit,
) -> Result<BTreeMap<FundType, gimli::write::UnitEntryId>> {
    let mut fund_map: BTreeMap<FundType, gimli::write::UnitEntryId> = BTreeMap::new();
    for fund_type in FUNDAMENTALS {
        fund_map.insert(
            fund_type,
            create_fundamental_type(
                unit,
                fund_type.name()?,
                fund_type.size()?,
                fund_type.gimli_ate()?,
            ),
        );
    }

    Ok(fund_map)
}

pub fn create_void_pointer(unit: &mut gimli::write::Unit, dwarf2_types: &mut Dwarf2Types) {
    let void_id = dwarf2_types.fundamental_map.get(&FundType::Void).cloned().unwrap(); // shouldn't fail

    let void_pointer_id = unit.add(unit.root(), gimli::DW_TAG_pointer_type);
    // TODO unhardcode size?
    // void* doesn't point to anything in DWARF 2+
    unit.get_mut(void_pointer_id).set(gimli::DW_AT_byte_size, unsigned_dwarf_value(4 as u8));

    dwarf2_types.modified_type_id_map.insert((void_id, vec![Modifier::PointerTo]), void_pointer_id);
}

fn create_fundamental_type(
    unit: &mut gimli::write::Unit,
    name: &str,
    size: u32,
    encoding: gimli::DwAte,
) -> gimli::write::UnitEntryId {
    let fund_type = unit.add(unit.root(), gimli::DW_TAG_base_type);
    unit.get_mut(fund_type)
        .set(gimli::DW_AT_name, gimli::write::AttributeValue::String(name.as_bytes().to_vec()));
    unit.get_mut(fund_type).set(gimli::DW_AT_byte_size, unsigned_dwarf_value(size));
    unit.get_mut(fund_type)
        .set(gimli::DW_AT_encoding, gimli::write::AttributeValue::Encoding(encoding));
    fund_type
}

fn unsigned_dwarf_value<T: Into<u64>>(value: T) -> gimli::write::AttributeValue {
    let v: u64 = value.into();
    if v <= u8::MAX as u64 {
        gimli::write::AttributeValue::Data1(v as u8)
    } else if v <= u16::MAX as u64 {
        gimli::write::AttributeValue::Data2(v as u16)
    } else if v <= u32::MAX as u64 {
        gimli::write::AttributeValue::Data4(v as u32)
    } else {
        gimli::write::AttributeValue::Udata(v)
    }
}

fn signed_dwarf_value<T>(value: T) -> Result<gimli::write::AttributeValue>
where
    T: TryInto<u64>,
{
    let v: u64 = value.try_into().map_err(|_| anyhow!("Negative value"))?;
    return Ok(unsigned_dwarf_value(v));
}
