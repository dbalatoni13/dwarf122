use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroU32,
};

use anyhow::{bail, Result};
use gimli::write::{Expression, UnitEntryId};
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};

use crate::util::reader::Endian;

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum TagKind {
    Padding = 0x0000,
    ArrayType = 0x0001,
    ClassType = 0x0002,
    EntryPoint = 0x0003,
    EnumerationType = 0x0004,
    FormalParameter = 0x0005,
    GlobalSubroutine = 0x0006,
    GlobalVariable = 0x0007,
    Label = 0x000a,
    LexicalBlock = 0x000b,
    LocalVariable = 0x000c,
    Member = 0x000d,
    PointerType = 0x000f,
    ReferenceType = 0x0010,
    // aka SourceFile
    CompileUnit = 0x0011,
    StringType = 0x0012,
    StructureType = 0x0013,
    Subroutine = 0x0014,
    SubroutineType = 0x0015,
    Typedef = 0x0016,
    UnionType = 0x0017,
    UnspecifiedParameters = 0x0018,
    Variant = 0x0019,
    CommonBlock = 0x001a,
    CommonInclusion = 0x001b,
    Inheritance = 0x001c,
    InlinedSubroutine = 0x001d,
    Module = 0x001e,
    PtrToMemberType = 0x001f,
    SetType = 0x0020,
    SubrangeType = 0x0021,
    WithStmt = 0x0022,
    // User types
    MwOverlayBranch = 0x4080,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum FundType {
    WideChar = 0x0000, // Likely an MW bug
    Char = 0x0001,
    SignedChar = 0x0002,
    UnsignedChar = 0x0003,
    Short = 0x0004,
    SignedShort = 0x0005,
    UnsignedShort = 0x0006,
    Integer = 0x0007,
    SignedInteger = 0x0008,
    UnsignedInteger = 0x0009,
    Long = 0x000a,
    SignedLong = 0x000b,
    UnsignedLong = 0x000c,
    Pointer = 0x000d,
    Float = 0x000e,
    DblPrecFloat = 0x000f,
    ExtPrecFloat = 0x0010,
    Complex = 0x0011,
    DblPrecComplex = 0x0012,
    Void = 0x0014,
    Boolean = 0x0015,
    ExtPrecComplex = 0x0016,
    Label = 0x0017,
    // User types
    LongLong = 0x8008,
    SignedLongLong = 0x8108,
    UnsignedLongLong = 0x8208,
    Int128 = 0xa510,
    Vec2x32Float = 0xac00,
}

impl FundType {
    pub fn size(self) -> Result<u32> {
        Ok(match self {
            FundType::Char | FundType::SignedChar | FundType::UnsignedChar | FundType::Boolean => 1,
            FundType::WideChar
            | FundType::Short
            | FundType::SignedShort
            | FundType::UnsignedShort => 2,
            FundType::Integer | FundType::SignedInteger | FundType::UnsignedInteger => 4,
            FundType::Long
            | FundType::SignedLong
            | FundType::UnsignedLong
            | FundType::Pointer
            | FundType::Float => 4,
            FundType::DblPrecFloat
            | FundType::LongLong
            | FundType::SignedLongLong
            | FundType::UnsignedLongLong
            | FundType::Vec2x32Float => 8,
            FundType::Int128 => 16,
            FundType::Void => 0,
            FundType::ExtPrecFloat
            | FundType::Complex
            | FundType::DblPrecComplex
            | FundType::ExtPrecComplex
            | FundType::Label => bail!("Unhandled fundamental type {self:?}"),
        })
    }

    pub fn name(self) -> Result<&'static str> {
        Ok(match self {
            FundType::WideChar => "wchar_t",
            FundType::Char => "char",
            FundType::SignedChar => "signed char",
            FundType::UnsignedChar => "unsigned char",
            FundType::Short => "short",
            FundType::SignedShort => "signed short",
            FundType::UnsignedShort => "unsigned short",
            FundType::Integer => "int",
            FundType::SignedInteger => "signed int",
            FundType::UnsignedInteger => "unsigned int",
            FundType::Long => "long",
            FundType::SignedLong => "signed long",
            FundType::UnsignedLong => "unsigned long",
            FundType::Pointer => "void *",
            FundType::Float => "float",
            FundType::DblPrecFloat => "double",
            FundType::ExtPrecFloat => "long double",
            FundType::Void => "void",
            FundType::Boolean => "bool",
            FundType::Complex
            | FundType::DblPrecComplex
            | FundType::ExtPrecComplex
            | FundType::Label => bail!("Unhandled fundamental type {self:?}"),
            FundType::LongLong => "long long",
            FundType::SignedLongLong => "signed long long",
            FundType::UnsignedLongLong => "unsigned long long",
            FundType::Int128 => "__int128",
            FundType::Vec2x32Float => "__vec2x32float__",
        })
    }

    pub fn gimli_ate(self) -> Result<gimli::DwAte> {
        Ok(match self {
            FundType::WideChar => bail!("Unhandled fundamental type {self:?}"),
            FundType::Char => gimli::DW_ATE_signed_char,
            FundType::SignedChar => gimli::DW_ATE_signed_char,
            FundType::UnsignedChar => gimli::DW_ATE_unsigned_char,
            FundType::Short => gimli::DW_ATE_signed,
            FundType::SignedShort => gimli::DW_ATE_signed,
            FundType::UnsignedShort => gimli::DW_ATE_unsigned,
            FundType::Integer => gimli::DW_ATE_signed,
            FundType::SignedInteger => gimli::DW_ATE_signed,
            FundType::UnsignedInteger => gimli::DW_ATE_unsigned,
            FundType::Long => gimli::DW_ATE_signed,
            FundType::SignedLong => gimli::DW_ATE_signed,
            FundType::UnsignedLong => gimli::DW_ATE_unsigned,
            FundType::Pointer => bail!("Unhandled fundamental type {self:?}"),
            FundType::Float => gimli::DW_ATE_float,
            FundType::DblPrecFloat => gimli::DW_ATE_float,
            FundType::ExtPrecFloat => gimli::DW_ATE_float,
            FundType::Void => gimli::DW_ATE_address,
            FundType::Boolean => gimli::DW_ATE_boolean,
            FundType::Complex
            | FundType::DblPrecComplex
            | FundType::ExtPrecComplex
            | FundType::Label => bail!("Unhandled fundamental type {self:?}"),
            FundType::LongLong => gimli::DW_ATE_signed,
            FundType::SignedLongLong => gimli::DW_ATE_signed,
            FundType::UnsignedLongLong => gimli::DW_ATE_unsigned,
            FundType::Int128 => gimli::DW_ATE_signed,
            FundType::Vec2x32Float => bail!("Unhandled fundamental type {self:?}"),
        })
    }

    pub fn parse_int(value: u16) -> Result<Self, TryFromPrimitiveError<Self>> {
        if value >> 8 == 0x1 {
            // Can appear in erased tags
            Self::try_from(value & 0xFF)
        } else {
            Self::try_from(value)
        }
    }
}

#[derive(
    Debug, Eq, PartialEq, Ord, PartialOrd, Copy, Clone, IntoPrimitive, TryFromPrimitive, Hash,
)]
#[repr(u8)]
pub enum Modifier {
    MwPointerTo = 0x00, // Used in erased tags
    PointerTo = 0x01,
    ReferenceTo = 0x02,
    Const = 0x03,
    Volatile = 0x04,
    // User types
}

impl Modifier {
    pub fn parse_int(value: u8) -> Result<Self, TryFromPrimitiveError<Self>> {
        Self::try_from(value & 0x7F) // High bit can appear in erased tags
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum SubscriptFormat {
    FundTypeConstConst = 0x0,
    FundTypeConstLocation = 0x1,
    FundTypeLocationConst = 0x2,
    FundTypeLocationLocation = 0x3,
    UserTypeConstConst = 0x4,
    UserTypeConstLocation = 0x5,
    UserTypeLocationConst = 0x6,
    UserTypeLocationLocation = 0x7,
    ElementType = 0x8,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum LocationOp {
    Register = 0x01,
    BaseRegister = 0x02,
    Address = 0x03,
    Const = 0x04,
    Deref2 = 0x05,
    Deref4 = 0x06,
    Add = 0x07,
    // User types
    MwFpReg = 0x80,
    MwFpDReg = 0x81,
    MwDRef8 = 0x82,
}

pub const FORM_MASK: u16 = 0xF;

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum FormKind {
    Addr = 0x1,
    Ref = 0x2,
    Block2 = 0x3,
    Block4 = 0x4,
    Data2 = 0x5,
    Data4 = 0x6,
    Data8 = 0x7,
    String = 0x8,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum AttributeKind {
    Sibling = 0x0010 | (FormKind::Ref as u16),
    Location = 0x0020 | (FormKind::Block2 as u16),
    Name = 0x0030 | (FormKind::String as u16),
    FundType = 0x0050 | (FormKind::Data2 as u16),
    ModFundType = 0x0060 | (FormKind::Block2 as u16),
    UserDefType = 0x0070 | (FormKind::Ref as u16),
    ModUDType = 0x0080 | (FormKind::Block2 as u16),
    Ordering = 0x0090 | (FormKind::Data2 as u16),
    SubscrData = 0x00a0 | (FormKind::Block2 as u16),
    ByteSize = 0x00b0 | (FormKind::Data4 as u16),
    BitOffset = 0x00c0 | (FormKind::Data2 as u16),
    BitSize = 0x00d0 | (FormKind::Data4 as u16),
    ElementList = 0x00f0 | (FormKind::Block4 as u16),
    StmtList = 0x0100 | (FormKind::Data4 as u16),
    LowPc = 0x0110 | (FormKind::Addr as u16),
    HighPc = 0x0120 | (FormKind::Addr as u16),
    Language = 0x0130 | (FormKind::Data4 as u16),
    Member = 0x0140 | (FormKind::Ref as u16),
    Discr = 0x0150 | (FormKind::Ref as u16),
    DiscrValue = 0x0160 | (FormKind::Block2 as u16),
    StringLength = 0x0190 | (FormKind::Block2 as u16),
    CommonReference = 0x01a0 | (FormKind::Ref as u16),
    CompDir = 0x01b0 | (FormKind::String as u16),
    ConstValueString = 0x01c0 | (FormKind::String as u16),
    ConstValueData2 = 0x01c0 | (FormKind::Data2 as u16),
    ConstValueData4 = 0x01c0 | (FormKind::Data4 as u16),
    ConstValueData8 = 0x01c0 | (FormKind::Data8 as u16),
    ConstValueBlock2 = 0x01c0 | (FormKind::Block2 as u16),
    ConstValueBlock4 = 0x01c0 | (FormKind::Block4 as u16),
    ContainingType = 0x01d0 | (FormKind::Ref as u16),
    DefaultValueAddr = 0x01e0 | (FormKind::Addr as u16),
    DefaultValueData2 = 0x01e0 | (FormKind::Data2 as u16),
    DefaultValueData8 = 0x01e0 | (FormKind::Data8 as u16),
    DefaultValueString = 0x01e0 | (FormKind::String as u16),
    Friends = 0x01f0 | (FormKind::Block2 as u16),
    Inline = 0x0200 | (FormKind::String as u16),
    IsOptional = 0x0210 | (FormKind::String as u16),
    LowerBoundRef = 0x0220 | (FormKind::Ref as u16),
    LowerBoundData2 = 0x0220 | (FormKind::Data2 as u16),
    LowerBoundData4 = 0x0220 | (FormKind::Data4 as u16),
    LowerBoundData8 = 0x0220 | (FormKind::Data8 as u16),
    Program = 0x0230 | (FormKind::String as u16),
    Private = 0x0240 | (FormKind::String as u16),
    Producer = 0x0250 | (FormKind::String as u16),
    Protected = 0x0260 | (FormKind::String as u16),
    Prototyped = 0x0270 | (FormKind::String as u16),
    Public = 0x0280 | (FormKind::String as u16),
    PureVirtual = 0x0290 | (FormKind::String as u16),
    PureVirtualBlock2 = 0x0290 | (FormKind::Block2 as u16),
    ReturnAddr = 0x02a0 | (FormKind::Block2 as u16),
    Specification = 0x02b0 | (FormKind::Ref as u16),
    StartScope = 0x02c0 | (FormKind::Data4 as u16),
    StrideSize = 0x02e0 | (FormKind::Data4 as u16),
    UpperBoundRef = 0x02f0 | (FormKind::Ref as u16),
    UpperBoundData2 = 0x02f0 | (FormKind::Data2 as u16),
    UpperBoundData4 = 0x02f0 | (FormKind::Data4 as u16),
    UpperBoundData8 = 0x02f0 | (FormKind::Data8 as u16),
    Virtual = 0x0300 | (FormKind::String as u16),
    VirtualBlock2 = 0x0300 | (FormKind::Block2 as u16),
    LoUser = 0x2000,
    HiUser = 0x3ff0,
    // User types
    MwMangled = 0x2000 | (FormKind::String as u16),
    MwRestoreSp = 0x2010 | (FormKind::Block2 as u16),
    MwGlobalRef = 0x2020 | (FormKind::Ref as u16),
    MwGlobalRefByName = 0x2030 | (FormKind::String as u16),
    MwRestoreS0 = 0x2040 | (FormKind::Block2 as u16),
    MwRestoreS1 = 0x2050 | (FormKind::Block2 as u16),
    MwRestoreS2 = 0x2060 | (FormKind::Block2 as u16),
    MwRestoreS3 = 0x2070 | (FormKind::Block2 as u16),
    MwRestoreS4 = 0x2080 | (FormKind::Block2 as u16),
    MwRestoreS5 = 0x2090 | (FormKind::Block2 as u16),
    MwRestoreS6 = 0x20A0 | (FormKind::Block2 as u16),
    MwRestoreS7 = 0x20B0 | (FormKind::Block2 as u16),
    MwRestoreS8 = 0x20C0 | (FormKind::Block2 as u16),
    MwRestoreF20 = 0x20D0 | (FormKind::Block2 as u16),
    MwRestoreF21 = 0x20E0 | (FormKind::Block2 as u16),
    MwRestoreF22 = 0x20F0 | (FormKind::Block2 as u16),
    MwRestoreF23 = 0x2100 | (FormKind::Block2 as u16),
    MwRestoreF24 = 0x2110 | (FormKind::Block2 as u16),
    MwRestoreF25 = 0x2120 | (FormKind::Block2 as u16),
    MwRestoreF26 = 0x2130 | (FormKind::Block2 as u16),
    MwRestoreF27 = 0x2140 | (FormKind::Block2 as u16),
    MwRestoreF28 = 0x2150 | (FormKind::Block2 as u16),
    MwRestoreF29 = 0x2160 | (FormKind::Block2 as u16),
    MwRestoreF30 = 0x2170 | (FormKind::Block2 as u16),
    MwRestoreD20 = 0x2180 | (FormKind::Block2 as u16),
    MwRestoreD21 = 0x2190 | (FormKind::Block2 as u16),
    MwRestoreD22 = 0x21A0 | (FormKind::Block2 as u16),
    MwRestoreD23 = 0x21B0 | (FormKind::Block2 as u16),
    MwRestoreD24 = 0x21C0 | (FormKind::Block2 as u16),
    MwRestoreD25 = 0x21D0 | (FormKind::Block2 as u16),
    MwRestoreD26 = 0x2240 | (FormKind::Block2 as u16),
    MwRestoreD27 = 0x2250 | (FormKind::Block2 as u16),
    MwRestoreD28 = 0x2260 | (FormKind::Block2 as u16),
    MwRestoreD29 = 0x2270 | (FormKind::Block2 as u16),
    MwRestoreD30 = 0x2280 | (FormKind::Block2 as u16),
    MwOverlayId = 0x2290 | (FormKind::Data4 as u16),
    MwOverlayName = 0x22A0 | (FormKind::String as u16),
    MwGlobalRefsBlock = 0x2300 | (FormKind::Block2 as u16),
    MwLocalSpoffset = 0x2310 | (FormKind::Block4 as u16),
    MwMips16 = 0x2330 | (FormKind::String as u16),
    MwDwarf2Location = 0x2340 | (FormKind::Block2 as u16),
    GccSfName = 0x8000 | (FormKind::Data4 as u16), // GccSfName extension (offset into .debug_sfnames)
    GccSfInfo = 0x8010 | (FormKind::Data4 as u16), // GccSfInfo extension (offset into .debug_srcinfo)
    MwPrologueEnd = 0x8040 | (FormKind::Addr as u16),
    MwEpilogueStart = 0x8050 | (FormKind::Addr as u16),
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    Address(u32),
    Reference(u32),
    Data2(u16),
    Data4(u32),
    Data8(u64),
    Block(Vec<u8>),
    String(String),
}

#[derive(Debug, Clone)]
pub struct Attribute {
    pub kind: AttributeKind,
    pub value: AttributeValue,
}

#[derive(Debug, Clone)]
pub struct Tag {
    pub key: u32,
    pub kind: TagKind,
    pub is_erased: bool,      // Tag was deleted but has been reconstructed
    pub is_erased_root: bool, // Tag is erased and is the root of a tree of erased tags
    pub data_endian: Endian, // Endianness of the tag data (could be different from the address endianness for erased tags)
    pub attributes: Vec<Attribute>,
}

impl Tag {
    #[inline]
    pub fn attribute(&self, kind: AttributeKind) -> Option<&Attribute> {
        self.attributes.iter().find(|attr| attr.kind == kind)
    }

    #[inline]
    pub fn address_attribute(&self, kind: AttributeKind) -> Option<u32> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Address(addr), .. }) => Some(*addr),
            _ => None,
        }
    }

    #[inline]
    pub fn reference_attribute(&self, kind: AttributeKind) -> Option<u32> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Reference(addr), .. }) => Some(*addr),
            _ => None,
        }
    }

    #[inline]
    pub fn string_attribute(&self, kind: AttributeKind) -> Option<&String> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::String(str), .. }) => Some(str),
            _ => None,
        }
    }

    #[inline]
    pub fn block_attribute(&self, kind: AttributeKind) -> Option<&[u8]> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Block(vec), .. }) => Some(vec),
            _ => None,
        }
    }

    #[inline]
    pub fn data4_attribute(&self, kind: AttributeKind) -> Option<u32> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Data4(value), .. }) => Some(*value),
            _ => None,
        }
    }

    #[inline]
    pub fn data2_attribute(&self, kind: AttributeKind) -> Option<u16> {
        match self.attribute(kind) {
            Some(Attribute { value: AttributeValue::Data2(value), .. }) => Some(*value),
            _ => None,
        }
    }

    #[inline]
    pub fn type_attribute(&self) -> Option<&Attribute> {
        self.attributes.iter().find(|attr| {
            matches!(
                attr.kind,
                AttributeKind::FundType
                    | AttributeKind::ModFundType
                    | AttributeKind::UserDefType
                    | AttributeKind::ModUDType
            )
        })
    }

    pub fn children<'a>(&self, tags: &'a TagMap) -> Vec<&'a Tag> {
        let sibling = self.next_sibling(tags);
        let mut children = Vec::new();
        let mut child = match self.next_tag(tags, self.is_erased) {
            Some(child) => child,
            None => return children,
        };
        loop {
            if let Some(end) = sibling {
                if child.key == end.key {
                    break;
                }
            }
            if child.kind != TagKind::Padding {
                children.push(child);
            }
            match child.next_sibling(tags) {
                Some(next) => child = next,
                None => break,
            }
        }
        children
    }

    /// Returns the next sibling tag, if any
    pub fn next_sibling<'a>(&self, tags: &'a TagMap) -> Option<&'a Tag> {
        if let Some(key) = self.reference_attribute(AttributeKind::Sibling) {
            tags.get(&key)
        } else {
            self.next_tag(tags, self.is_erased)
        }
    }

    /// Returns the next tag sequentially, if any (skipping erased tags)
    pub fn next_tag<'a>(&self, tags: &'a TagMap, include_erased: bool) -> Option<&'a Tag> {
        tags.range(self.key + 1..)
            .find(|(_, tag)| include_erased || !tag.is_erased)
            .map(|(_, tag)| tag)
    }
}

pub type TagMap = BTreeMap<u32, Tag>;
pub struct Dwarf2Types {
    // TODO put unit in here
    pub fundamental_map: BTreeMap<FundType, gimli::write::UnitEntryId>,
    // DWARF 1 type -> DWARF 4
    pub old_new_tag_map: BTreeMap<u32, gimli::write::UnitEntryId>,
    // DWARF 4 DIE -> DWARF 4 pointer/volatile/const DIE
    pub modified_type_id_map:
        HashMap<(gimli::write::UnitEntryId, Vec<Modifier>), gimli::write::UnitEntryId>,
}
pub type TypedefMap = BTreeMap<u32, Vec<u32>>;

#[derive(Debug)]
pub struct DwarfInfo {
    pub e: Endian,
    pub tags: TagMap,
    pub producer: Producer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Producer {
    MWCC,
    GCC,
    OTHER,
}

#[derive(Debug, Clone)]
pub struct ArrayDimension {
    pub index_type: UnitEntryId,
    pub size: Option<NonZeroU32>,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum ArrayOrdering {
    RowMajor = 0,
    // ORD_row_major
    ColMajor = 1, // ORD_col_major
}

#[derive(Debug, Clone)]
pub struct ArrayType {
    pub element_type: Box<Type>,
    pub dimensions: Vec<ArrayDimension>,
}

#[derive(Debug, Clone)]
pub struct BitData {
    pub bit_size: u32,
    pub bit_offset: u16,
}

#[derive(Debug, Clone)]
pub struct StructureMember {
    pub name: Option<String>,
    pub offset: u32,
    pub bit: Option<BitData>,
    pub visibility: Visibility,
    pub byte_size: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureKind {
    Struct,
    Class,
}

#[derive(Debug, Clone)]
pub struct StructureType {
    pub kind: StructureKind,
    pub name: Option<String>,
    pub byte_size: Option<u32>,
    pub members: Vec<StructureMember>,
    pub static_members: Vec<VariableTag>,
    pub bases: Vec<StructureBase>,
    pub inner_types: Vec<UserDefinedType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Private,
    Protected,
    Public,
}

#[derive(Debug, Clone)]
pub struct StructureBase {
    pub name: Option<String>,
    pub offset: u32,
    pub visibility: Option<Visibility>,
    pub virtual_base: bool,
}

#[derive(Debug, Clone)]
pub struct EnumerationMember {
    pub name: String,
    pub value: i32,
}

#[derive(Debug, Clone)]
pub struct EnumerationType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<EnumerationMember>,
}

#[derive(Debug, Clone)]
pub struct UnionType {
    pub name: Option<String>,
    pub byte_size: u32,
    pub members: Vec<StructureMember>,
}

#[derive(Debug, Clone)]
pub struct SubroutineParameter {
    pub name: Option<String>,
    pub kind: Type,
    pub location: Option<Expression>,
}

#[derive(Debug, Clone)]
pub struct SubroutineVariable {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub kind: Type,
    pub location: Option<Expression>,
}

#[derive(Debug, Clone)]
pub struct SubroutineLabel {
    pub name: String,
    pub address: u32,
}

#[derive(Debug, Clone)]
pub struct SubroutineBlock {
    pub name: Option<String>,
    pub start_address: Option<u32>,
    pub end_address: Option<u32>,
    pub variables: Vec<SubroutineVariable>,
    pub blocks_and_inlines: Vec<SubroutineNode>,
    pub inner_types: Vec<UserDefinedType>,
}

#[derive(Debug, Clone)]
pub enum SubroutineNode {
    Block(SubroutineBlock),
    Inline(SubroutineType),
}

#[derive(Debug, Clone)]
pub struct MemberSubroutineDefType {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub return_type: Type,
    pub parameters: Vec<SubroutineParameter>,
    pub var_args: bool,
    pub prototyped: bool,
    pub member_of: Option<u32>,
    pub direct_member_of: Option<u32>,
    pub inline: bool,
    pub virtual_: bool,
    pub local: bool,
    pub start_address: Option<u32>,
    pub end_address: Option<u32>,
    pub const_: bool,
    pub static_member: bool,
    pub override_: bool,
    pub volatile_: bool,
}

#[derive(Debug, Clone)]
pub struct SubroutineType {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub return_type: Option<Type>,
    pub parameters: Vec<SubroutineParameter>,
    pub var_args: bool,
    pub prototyped: bool,
    pub references: Vec<u32>,
    pub member_of: Option<u32>,
    pub inline: bool,
    pub virtual_: bool,
}

#[derive(Debug, Clone)]
pub struct PtrToMemberType {
    pub kind: Type,
    pub containing_type: u32,
}

#[derive(Debug, Clone)]
pub enum UserDefinedType {
    Array(ArrayType),
    Structure(StructureType),
    Enumeration(EnumerationType),
    Union(UnionType),
    Subroutine(SubroutineType),
    PtrToMember(PtrToMemberType),
}

#[derive(Debug, Clone)]
pub struct VariableTag {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub address: Option<u32>,
    pub local: bool,
}

#[derive(Debug, Clone)]
pub struct TypedefTag {
    pub name: String,
    pub kind: Type,
}

#[derive(Debug, Clone)]
pub enum TagType {
    Variable(VariableTag),
    Typedef(()),
    UserDefined(Box<UserDefinedType>),
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
pub enum Language {
    C89 = 0x1,
    C = 0x2,
    Ada83 = 0x3,
    CPlusPlus = 0x4,
    Cobol74 = 0x5,
    Cobol85 = 0x6,
    Fortran77 = 0x7,
    Fortran90 = 0x8,
    Pascal83 = 0x9,
    Modula2 = 0xa,
    // MWCC asm extension, emitted by PS2 MWCC asm_r5900_elf.dll
    MwAsm = 0x8000,
}

impl From<Language> for gimli::DwLang {
    fn from(a: Language) -> gimli::DwLang {
        // these seem to be the same
        let value: u16 = a as u16;
        gimli::DwLang(value)
    }
}

#[derive(Debug, Clone)]
pub struct CompileUnit {
    pub name: String,
    pub producer: Option<String>,
    pub comp_dir: Option<String>,
    pub language: Option<Language>,
    pub start_address: Option<u32>,
    pub end_address: Option<u32>,
    pub gcc_srcfile_name_offset: Option<u32>,
    pub gcc_srcinfo_offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct OverlayBranch {
    pub name: String,
    pub id: u32,
    pub start_address: u32,
    pub end_address: u32,
    pub compile_unit: Option<u32>,
}

impl UserDefinedType {
    pub fn name(&self) -> Option<String> {
        match self {
            UserDefinedType::Array(_) | UserDefinedType::PtrToMember(_) => None,
            UserDefinedType::Structure(t) => t.name.clone(),
            UserDefinedType::Enumeration(t) => t.name.clone(),
            UserDefinedType::Union(t) => t.name.clone(),
            UserDefinedType::Subroutine(t) => t.name.clone(),
        }
    }

    pub fn is_definition(&self) -> bool {
        match self {
            UserDefinedType::Array(_) | UserDefinedType::PtrToMember(_) => false,
            UserDefinedType::Structure(t) => t.name.is_some(),
            UserDefinedType::Enumeration(t) => t.name.is_some(),
            UserDefinedType::Union(t) => t.name.is_some(),
            UserDefinedType::Subroutine(t) => t.name.is_some(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TypeKind {
    Fundamental(FundType),
    UserDefined(u32),
}

#[derive(Debug, Clone)]
pub struct Type {
    pub kind: TypeKind,
    pub modifiers: Vec<Modifier>,
    pub entry_id: UnitEntryId,
}
