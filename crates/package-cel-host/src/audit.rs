//! Inspect the actual trusted Rust guest; no source-string approximation.
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use wasmparser::{DataKind, KnownCustom, Name, Operator, Parser, Payload, ValType};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StackAudit {
    pub stack_pointer_global: u32,
    pub initial_stack_pointer: u32,
    pub lowest_active_data_offset: u32,
    pub active_data_segments: usize,
}

pub(crate) fn stack_first(bytes: &[u8]) -> Result<StackAudit> {
    let mut globals = Vec::new();
    let mut stack_index = None;
    let mut offsets = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let g = global?;
                    let mut op = g.init_expr.get_operators_reader();
                    let initial = match op.read()? {
                        Operator::I32Const { value } if value >= 0 => Some(value as u32),
                        _ => None,
                    };
                    globals.push((g.ty.content_type, g.ty.mutable, initial));
                }
            }
            Payload::CustomSection(reader) => {
                if let KnownCustom::Name(names) = reader.as_known() {
                    for section in names {
                        if let Name::Global(names) = section? {
                            for name in names {
                                let n = name?;
                                if n.name == "__stack_pointer" {
                                    ensure!(
                                        stack_index.replace(n.index).is_none(),
                                        "duplicate stack name"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    match data?.kind {
                        DataKind::Active {
                            memory_index: 0,
                            offset_expr,
                        } => {
                            let mut ops = offset_expr.get_operators_reader();
                            let Operator::I32Const { value } = ops.read()? else {
                                anyhow::bail!("nonconstant data offset");
                            };
                            ensure!(
                                value >= 0 && matches!(ops.read()?, Operator::End),
                                "data offset"
                            );
                            offsets.push(value as u32);
                        }
                        _ => anyhow::bail!("unexpected passive/other-memory data"),
                    }
                }
            }
            _ => {}
        }
    }
    let index = stack_index.context("actual __stack_pointer name unavailable")?;
    let (ty, mutable, initial) = globals.get(index as usize).context("stack global index")?;
    ensure!(
        *ty == ValType::I32 && *mutable && *initial == Some(1024 * 1024),
        "actual 1MiB stack pointer"
    );
    let lowest = *offsets
        .iter()
        .min()
        .context("active data layout unavailable")?;
    ensure!(lowest >= 1024 * 1024, "static data overlaps downward stack");
    Ok(StackAudit {
        stack_pointer_global: index,
        initial_stack_pointer: initial.unwrap(),
        lowest_active_data_offset: lowest,
        active_data_segments: offsets.len(),
    })
}
