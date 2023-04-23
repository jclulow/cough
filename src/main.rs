use std::io::Read;

use anyhow::{bail, Result};

#[derive(Debug)]
struct Sym {
    sectbase: u32,
    sectsize: u32,
    addr: u32,
    section: String,
    name: String,
    size: usize,
}

impl Sym {
    fn vaddr(&self, global_base: u32) -> u32 {
        global_base + self.sectbase + self.addr
    }
}

fn main() -> Result<()> {
    let Some(fp) = std::env::args().nth(1) else {
        bail!("which loader file?");
    };

    let Some(baddr) = std::env::args().nth(2) else {
        bail!("what base address?");
    };

    let global_base = if let Some(hex) = baddr.strip_prefix("0x") {
        u32::from_str_radix(&hex, 16)?
    } else {
        u32::from_str_radix(&baddr, 10)?
    };

    let mut f = std::fs::File::open(&fp)?;
    let mut data = Vec::new();
    let sz = f.read_to_end(&mut data)?;
    eprintln!("read {sz} bytes from {fp}");

    let pe = metagoblin::pe::PE::parse(&data)?;
    eprintln!("parsed ok");

    let st = pe.header.coff_header.symbols(&data)?;
    let strs = pe.header.coff_header.strings(&data)?;

    let mut symbols: Vec<Sym> = Default::default();

    /*
     * First, process everything that is _not_ a weak external.  These appear to
     * represent alternate names for symbols in our loader build.
     */
    for pass in 0..=1 {
        for (_, b, c) in st.iter() {
            let name = if let Some(name) = b {
                name.to_string()
            } else {
                let noff = c.name_offset().unwrap();
                let Some(name) = strs.get_at(noff.try_into().unwrap()) else {
                    bail!("missing string table thingy? {c:?}");
                };
                name.to_string()
            };

            if c.is_section_definition() || c.is_file() {
                continue;
            }

            if c.value == 0 {
                eprintln!("SKIP: {name:?} -> {c:?}");
                continue;
            }

            match pass {
                0 => {
                    if c.is_weak_external() {
                        continue;
                    }
                }
                1 => {
                    if !c.is_weak_external() {
                        continue;
                    }
                }
                _ => panic!(),
            }

            let ste = pe
                .sections
                .iter()
                .nth((c.section_number - 1).try_into().unwrap())
                .unwrap();
            let section = ste.name().unwrap().to_string();

            if name.ends_with(".localalias") {
                eprintln!("ignore odd local alias: {name:?}");
                continue;
            }

            let sym = Sym {
                addr: c.value,
                section,
                sectbase: ste.virtual_address,
                sectsize: ste.virtual_size,
                name,
                size: 0,
            };

            if c.is_weak_external() {
                if let Some(exist) =
                    symbols.iter().find(|s| s.vaddr(0) == sym.vaddr(0))
                {
                    eprintln!("weak external {sym:?} shadows {:?}", exist);
                    continue;
                }

                eprintln!("missing main symbol for {sym:?}");
            }

            if let Some(exist) =
                symbols.iter().find(|ext| ext.vaddr(0) == sym.vaddr(0))
            {
                bail!("duplicate symbol: {exist:?} <-> {sym:?}");
            }

            symbols.push(sym);
        }

        eprintln!();
    }

    symbols.sort_by(|a, b| a.vaddr(0).cmp(&b.vaddr(0)));
    for i in 0..symbols.len() {
        if i == symbols.len() - 1
            || symbols[i].section != symbols[i + 1].section
        {
            /*
             * Just go to the end of the section.
             */
            let sectend = symbols[i].sectbase + symbols[i].sectsize;
            symbols[i].size =
                (sectend - symbols[i].vaddr(0)).try_into().unwrap();
        } else {
            symbols[i].size = (symbols[i + 1].vaddr(0) - symbols[i].vaddr(0))
                .try_into()
                .unwrap();
        }
    }

    for s in symbols {
        let typ = if s.section == ".text" { "-f" } else { "-o" };

        println!(
            "0x{:08x}::nmadd {typ} -s 0x{:08x} {}",
            s.vaddr(global_base),
            s.size,
            s.name
        );
    }

    Ok(())
}
