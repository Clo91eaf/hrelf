use clap::Parser;
use elf::abi;
use elf::dynamic;
use elf::endian::AnyEndian;
use elf::relocation::Rela;
use elf::section::SectionHeader;
use elf::segment::ProgramHeader;
use elf::string_table::StringTable;
use elf::symbol::Symbol;
use elf::hash::GnuHashHeader;
use elf::to_str;
use elf::ElfBytes;

#[derive(Parser, Debug)]
#[command(
    author,
    about,
    version,
    long_about = "This is a tool for manipulating ELF files."
)]
struct Args {
    #[arg(short, long)]
    file: std::path::PathBuf,
}

#[rustfmt::skip]
fn parse_elf_header(ehdr: elf::file::FileHeader<AnyEndian>, ident: &[u8]) {
    println!("ELF Header:");
    println!("  Magic:    {:02x?}", ident);
    println!("  Class:                      {:?}", ehdr.class);
    println!("  Data:                       {:?}", ehdr.endianness);
    println!("  Version:                    {:?} (current)", ident[abi::EI_VERSION]);
    println!("  OS/ABI:                     {}", to_str::e_osabi_to_string(ehdr.osabi));
    println!("  ABI Version:                {:?}", ehdr.abiversion);
    println!("  Type:                       {}", to_str::e_type_to_human_str(ehdr.e_type).unwrap());
    println!("  Machine:                    {}", to_str::e_machine_to_human_str(ehdr.e_machine).unwrap());
    println!("  Version:                    0x{:x}", ehdr.version);
    println!("  Entry point address:        0x{:x}", ehdr.e_entry);
    println!("  Start of program headers:   {:?} (bytes into file)", ehdr.e_phoff);
    println!("  Start of section headers:   {:?} (bytes into file)", ehdr.e_shoff);
    println!("  Flags:                      0x{:x}", ehdr.e_flags);
    println!("  Size of this header:        {:?} (bytes into file)", ehdr.e_ehsize);
    println!("  Size of program headers:    {:?} (bytes into file)", ehdr.e_phentsize);
    println!("  Number of program headers:  {:?}", ehdr.e_phnum);
    println!("  Size of section headers:    {:?} (bytes into file)", ehdr.e_shentsize);
    println!("  Number of section headers:  {:?}", ehdr.e_shnum);
    println!("  Section header string table index: {:?}", ehdr.e_shstrndx);
    println!("");
}

fn parse_section_headers(shdrs: &Vec<SectionHeader>, strtab: &StringTable) {
    println!("Section Headers:");
    println!("  [Nr] Name               Type              Address            Offset");
    println!("       Size               EntSize           Flags  Link  Info  Align");
    for (i, shdr) in shdrs.iter().enumerate() {
        println!(
            "  [{:>2}] {:<19}{:<15}   {:016x}   {:08x}",
            i,
            strtab.get(shdr.sh_name as usize).unwrap(),
            to_str::sh_type_to_string(shdr.sh_type),
            shdr.sh_addr,
            shdr.sh_offset
        );
        println!(
            "       {:016x}   {:016x}  {:<6} {:<5} {:<5} {:<5}",
            shdr.sh_size,
            shdr.sh_entsize,
            shdr.sh_flags,
            shdr.sh_link,
            shdr.sh_info,
            shdr.sh_addralign,
        );
    }
    println!("");
}

fn parse_program_headers(phdrs: &Vec<ProgramHeader>) {
    println!("Program Headers:");
    println!("  Type            Offset           VirtAddr         PhysAddr");
    println!("                  FileSiz          MemSiz           Flags  Align");
    for phdr in phdrs {
        println!(
            "  {:<15} {:016x} {:016x} {:016x}",
            to_str::p_type_to_string(phdr.p_type),
            phdr.p_offset,
            phdr.p_vaddr,
            phdr.p_paddr
        );
        println!(
            "                  {:016x} {:016x} {:<6} {:<5}",
            phdr.p_filesz,
            phdr.p_memsz,
            to_str::p_flags_to_string(phdr.p_flags),
            phdr.p_align,
        );
    }
    println!("");
}

fn section_to_segment_mapping(
    shdrs: &Vec<SectionHeader>,
    phdrs: &Vec<ProgramHeader>,
    strtab: &StringTable,
) {
    println!(" Section to Segment mapping:");
    println!("  Segment Sections...");
    for (i, phdr) in phdrs.iter().enumerate() {
        let mut sections: Vec<String> = Vec::new();
        for shdr in shdrs {
            if shdr.sh_addr >= phdr.p_vaddr
                && shdr.sh_addr + shdr.sh_size <= phdr.p_vaddr + phdr.p_memsz
            {
                sections.push(strtab.get(shdr.sh_name as usize).unwrap().to_string());
            }
        }
        sections.retain(|s| !s.is_empty());
        println!("  {:02}      {}", i, sections.join(" "));
    }
    println!("");
}

fn parse_dynamic_section(dynamics: &Vec<dynamic::Dyn>, offset: u64) {
    println!(
        "Dynamic section at offset 0x{:x} contains {} entries:",
        offset,
        dynamics.len()
    );
    println!("  Tag        Type               Value");
    for dynamic in dynamics {
        println!(
            "  0x{:08x} {:<18} 0x{:x}",
            dynamic.d_tag,
            to_str::d_tag_to_str(dynamic.d_tag).unwrap(),
            dynamic.clone().d_val(),
        );
    }
    println!("");
}

fn parse_reloacation_dynamic_section(rels: &Vec<Rela>, offset: u64) {
    println!(
        "Relocation section '.rela.dyn' at offset 0x{:x} contains {} entry:",
        offset,
        rels.len()
    );
    println!("  Offset          Info                   Sym. Value    Sym. Name + Addend");
    for rel in rels {
        println!(
            "  {:016x} {:04x}{:08x} {:016x}",
            rel.r_offset, rel.r_sym, rel.r_type, rel.r_addend,
        );
    }
    println!("");
}

fn parse_reloacation_plt_section(rels: &Vec<Rela>, offset: u64) {
    println!(
        "Relocation section '.rela.plt' at offset 0x{:x} contains {} entry:",
        offset,
        rels.len()
    );
    println!("  Offset           Info         Addend");
    for rel in rels {
        println!(
            "  {:016x} {:04x}{:08x} {:016x}",
            rel.r_offset, rel.r_sym, rel.r_type, rel.r_addend,
        );
    }
    println!("");
}

fn parse_dynsym_table(dynsyms: &Vec<Symbol>, strtab: &StringTable) {
    println!("Symbol table '.dynsym' contains {} entries:", dynsyms.len());
    println!("   Num: Value            Size  Type       Bind       Vis         Ndx    Name");
    for (i, dynsym) in dynsyms.iter().enumerate() {
        println!(
            "   {:<3}: {:016x} {:<5} {:<10} {:<10} {:<11} {:<6} {}",
            i,
            dynsym.st_value,
            dynsym.st_size,
            to_str::st_symtype_to_string(dynsym.st_symtype()),
            to_str::st_bind_to_string(dynsym.st_bind()),
            to_str::st_vis_to_string(dynsym.st_vis()),
            dynsym.st_shndx,
            strtab.get(dynsym.st_name as usize).unwrap()
        );
    }
    println!("");
}

fn parse_symbol_table(symtabs: &Vec<Symbol>, strtab: &StringTable) {
    println!("Symbol table '.symtab' contains {} entries:", symtabs.len());
    println!("   Num: Value            Size  Type       Bind       Vis         Ndx    Name");
    for (i, symtab) in symtabs.iter().enumerate() {
        println!(
            "   {:<3}: {:016x} {:<5} {:<10} {:<10} {:<11} {:<6} {}",
            i,
            symtab.st_value,
            symtab.st_size,
            to_str::st_symtype_to_string(symtab.st_symtype()),
            to_str::st_bind_to_string(symtab.st_bind()),
            to_str::st_vis_to_string(symtab.st_vis()),
            symtab.st_shndx,
            strtab.get(symtab.st_name as usize).unwrap(),
        );
    }
}

fn parse_gnu_hash(gnu_hash: &GnuHashHeader) {
    println!("Histogram for `.gnu.hash` bucket list length (total of {} buckets):", gnu_hash.nbucket);
    println!(" Length  TableStart  NBloom  NShift");  
    println!(" {:<6}  {:<10}  {:<6}  {:<6}", 0, gnu_hash.table_start_idx, gnu_hash.nbloom, gnu_hash.nshift);
}

fn main() {
    let args = Args::parse();
    let file_data = std::fs::read(args.file).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
    let ident = slice.get(0..16).unwrap();
    let phdr: Vec<ProgramHeader> = file.segments().unwrap().iter().collect();
    // Get the section header table alongside its string table
    let (shdrs_opt, strtab_opt) = file
        .section_headers_with_strtab()
        .expect("shdrs offsets should be valid");
    let (shdrs, strtab) = (
        shdrs_opt.expect("Should have shdrs"),
        strtab_opt.expect("Should have strtab"),
    );
    let shdr = shdrs.iter().collect();
    let mut dynamic: Vec<dynamic::Dyn> = file
        .dynamic()
        .unwrap()
        .expect("Should have dynamic section")
        .iter()
        .collect();
    dynamic.truncate(dynamic.len() - 4);

    let dynamic_offset = shdrs
        .iter()
        .find(|shdr| shdr.sh_type == abi::SHT_DYNAMIC)
        .unwrap()
        .sh_offset;

    let rel_section = shdrs
        .iter()
        .filter(|shdr| shdr.sh_type == abi::SHT_RELA)
        .collect::<Vec<_>>();
    let rel = rel_section
        .iter()
        .map(|shdr| {
            let rels = file
                .section_data_as_relas(shdr)
                .expect("Should have relocations");
            rels.collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let rel_offset = shdrs
        .iter()
        .filter(|shdr| shdr.sh_type == abi::SHT_RELA)
        .collect::<Vec<_>>();
    let common_data = file.find_common_data().unwrap();
    let symtab = common_data.symtab.unwrap();
    let symtab_strs = common_data.symtab_strs.unwrap();
    let dynsyms = common_data.dynsyms.unwrap();
    let dynsyms_strs = common_data.dynsyms_strs.unwrap();
    let gnu_hash = common_data.gnu_hash.unwrap();
        
    parse_elf_header(file.ehdr, ident);
    parse_section_headers(&shdr, &strtab);
    parse_program_headers(&phdr);
    section_to_segment_mapping(&shdr, &phdr, &strtab);
    parse_dynamic_section(&dynamic, dynamic_offset);
    parse_reloacation_dynamic_section(&rel[0], rel_offset[0].sh_offset);
    parse_reloacation_plt_section(&rel[1], rel_offset[1].sh_offset);
    parse_dynsym_table(&dynsyms.iter().collect(), &dynsyms_strs);
    parse_symbol_table(&symtab.iter().collect(), &symtab_strs);
    parse_gnu_hash(&gnu_hash.hdr);
}
