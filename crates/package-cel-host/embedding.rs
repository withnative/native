//! Build-time data object only; no generated executable code or Rust source.
use object::{
    write::{Object, Symbol, SymbolSection},
    Architecture, BinaryFormat, Endianness, Object as _, ObjectSection as _, ObjectSymbol as _,
    SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
pub const SYMBOL: &str = "native_package_cel_guest_v2_verified_data_7e43a1";
pub const ALIGN: u64 = 16;
pub fn target(
    format: &str,
    arch: &str,
    endian: &str,
) -> Result<(BinaryFormat, Architecture, Endianness), String> {
    let format = match format {
        "linux" => BinaryFormat::Elf,
        "macos" => BinaryFormat::MachO,
        "windows" => BinaryFormat::Coff,
        _ => return Err("unsupported development guest object OS".into()),
    };
    let arch = match arch {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        _ => return Err("unsupported development guest object architecture".into()),
    };
    if endian != "little" {
        return Err("unsupported development guest object endianness".into());
    }
    Ok((format, arch, Endianness::Little))
}
pub fn encode(
    data: &[u8],
    config: (BinaryFormat, Architecture, Endianness),
) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("empty guest object data".into());
    }
    let mut object = Object::new(config.0, config.1, config.2);
    let section = object.add_section(
        if config.0 == BinaryFormat::MachO {
            b"__TEXT".to_vec()
        } else {
            Vec::new()
        },
        if config.0 == BinaryFormat::MachO {
            b"__native_cel".to_vec()
        } else {
            b".rodata.native_cel".to_vec()
        },
        SectionKind::ReadOnlyData,
    );
    let offset = object.append_section_data(section, data, ALIGN);
    object.add_symbol(Symbol {
        // object applies the target's global-prefix mangling exactly once.
        name: SYMBOL.as_bytes().to_vec(),
        value: offset,
        size: data.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
    let bytes = object.write().map_err(|e| e.to_string())?;
    verify(&bytes, data, config)?;
    Ok(bytes)
}
pub fn verify(
    bytes: &[u8],
    data: &[u8],
    config: (BinaryFormat, Architecture, Endianness),
) -> Result<(), String> {
    let object = object::File::parse(bytes).map_err(|e| e.to_string())?;
    if object.format() != config.0
        || object.architecture() != config.1
        || object.endianness() != config.2
    {
        return Err("object target mismatch".into());
    }
    let expected = if config.0 == BinaryFormat::MachO {
        format!("_{SYMBOL}")
    } else {
        SYMBOL.into()
    };
    let symbols: Vec<_> = object
        .symbols()
        .filter(|s| s.name().ok() == Some(expected.as_str()))
        .collect();
    if symbols.len() != 1 {
        return Err("object symbol inventory mismatch".into());
    }
    let symbol = &symbols[0];
    let section = object
        .section_by_index(symbol.section_index().ok_or("missing object section")?)
        .map_err(|e| e.to_string())?;
    // COFF/Mach-O do not encode individual data symbol sizes. Exact section extent,
    // sole data symbol, and zero offset establish the size there instead.
    if symbol.address() != 0
        || symbol.is_weak()
        || symbol.kind() != SymbolKind::Data
        || !symbol.is_global()
        || section.kind() != SectionKind::ReadOnlyData
        || section.align() < ALIGN
        || section.size() != data.len() as u64
        || section.data().map_err(|e| e.to_string())? != data
        || (config.0 == BinaryFormat::Elf && symbol.size() != data.len() as u64)
    {
        return Err("object data/length/alignment/symbol mismatch".into());
    }
    Ok(())
}
