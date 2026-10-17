mod dwarf;
mod expression;
mod units;

use crate::emit::{Emit, EmitContext};
use crate::{CustomSection, Module, RawCustomSection};
use gimli::*;

use self::dwarf::{AddressSearchPreference, ConvertContext, DEAD_CODE};
use self::expression::{CodeAddressConverter, CodeAddressGenerator};
use self::units::DebuggingInformationCursor;

/// The DWARF debug section in input WebAssembly binary.
#[derive(Debug, Default)]
pub struct ModuleDebugData {
    /// DWARF debug data
    pub dwarf: read::Dwarf<Vec<u8>>,
}

impl Module {
    pub(crate) fn parse_debug_sections(
        &mut self,
        mut debug_sections: Vec<RawCustomSection>,
    ) -> Result<()> {
        let load_section = |id: gimli::SectionId| -> Result<Vec<u8>> {
            Ok(
                match debug_sections
                    .iter_mut()
                    .find(|section| section.name() == id.name())
                {
                    Some(section) => std::mem::take(&mut section.data),
                    None => Vec::new(),
                },
            )
        };

        self.debug.dwarf = read::Dwarf::load(load_section)?;

        Ok(())
    }
}

impl Emit for ModuleDebugData {
    fn emit(&self, cx: &mut EmitContext) {
        let address_generator = CodeAddressGenerator::new(&cx.module.funcs);
        let address_converter = CodeAddressConverter::new(&cx.code_transform);

        let convert_address = |address, search_preference| -> Option<write::Address> {
            let address = address as usize;
            let code = address_generator.find_address(address, search_preference);
            let address = address_converter.find_address(code);

            address
                .map(|x| (x - cx.code_transform.code_section_start) as u64)
                .map(write::Address::Constant)
        };

        #[allow(deprecated)]
        let from_dwarf = cx
            .module
            .debug
            .dwarf
            .borrow(|sections| EndianSlice::new(sections.as_ref(), LittleEndian));

        let mut dwarf = write::Dwarf::from(&from_dwarf, &|address| {
            if address == 0 || address == DEAD_CODE {
                Some(write::Address::Constant(address))
            } else {
                convert_address(address, AddressSearchPreference::InclusiveFunctionEnd)
                    .or(Some(write::Address::Constant(DEAD_CODE)))
            }
        })
        .expect("cannot convert to writable dwarf");

        let units = {
            let mut from_unit_headers = from_dwarf.units();
            let mut units = Vec::new();

            while let Some(from_unit) = from_unit_headers.next().expect("") {
                let index = units.len();
                units.push((from_unit, dwarf.units.id(index)));
            }

            units
        };

        let mut convert_context = ConvertContext::new(
            &from_dwarf.debug_str,
            &from_dwarf.debug_line_str,
            &mut dwarf.strings,
            &mut dwarf.line_strings,
            &convert_address,
        );

        for (from_id, id) in units {
            let from_unit: Unit<EndianSlice<'_, LittleEndian>, usize> =
                from_dwarf.unit(from_id).expect("readable unit");
            let unit = dwarf.units.get_mut(id);

            let mut updates = Vec::new();
            {
                let mut from_entries = from_unit.entries();
                let mut entries = DebuggingInformationCursor::new(unit);
                while let (Ok(Some((_, from_entry))), Some(entry)) =
                    (from_entries.next_dfs(), entries.next_dfs())
                {
                    let mut attrs = from_entry.attrs();
                    while let Some(attr) = attrs.next().expect("readable attribute") {
                        if let Some(mut source_ranges) = from_dwarf
                            .attr_ranges(&from_unit, attr.value()).expect("readable ranges")
                        {
                            let mut ranges = vec![write::Range::BaseAddress {
                                address: write::Address::Constant(0),
                            }];
                            while let Some(range) = source_ranges.next().expect("readable range") {
                                for live in address_generator.live_ranges(range.begin as usize..range.end as usize) {
                                    let begin = convert_address(live.start as u64, AddressSearchPreference::ExclusiveFunctionEnd)
                                        .unwrap_or_else(|| panic!("live range start [{:#x}, {:#x}), DIE {:?}", live.start, live.end, from_entry.offset()));
                                    let end = convert_address(live.end as u64, AddressSearchPreference::InclusiveFunctionEnd)
                                        .unwrap_or_else(|| panic!("live range end [{:#x}, {:#x}), DIE {:?}", live.start, live.end, from_entry.offset()));
                                    ranges.push(write::Range::StartEnd { begin, end });
                                }
                            }
                            updates.push((entry.id(), attr.name(), write::RangeList(ranges)));
                        }
                    }
                }
            }
            unit.ranges = write::RangeListTable::default();
            for (entry, name, ranges) in updates {
                let id = unit.ranges.add(ranges);
                unit.get_mut(entry).set(name, write::AttributeValue::RangeListRef(id));
            }

            // perform high pc transformation of DWARF .debug_info
            {
                let mut from_entries = from_unit.entries();
                let mut entries = DebuggingInformationCursor::new(unit);

                convert_context.convert_high_pc(&mut from_entries, &mut entries);
            }

            // perform line program transformation
            if let Some(program) = convert_context.convert_unit_line_program(from_unit) {
                unit.line_program = program;
            }
        }

        let mut sections = write::Sections::new(write::EndianVec::new(gimli::LittleEndian));
        dwarf.write(&mut sections).expect("write failed");
        sections
            .for_each(
                |id: SectionId, data: &write::EndianVec<LittleEndian>| -> Result<()> {
                    if !data.slice().is_empty() {
                        cx.wasm_module.section(&wasm_encoder::CustomSection {
                            name: id.name().into(),
                            data: data.slice().into(),
                        });
                    }
                    Ok(())
                },
            )
            .expect("never");
    }
}
