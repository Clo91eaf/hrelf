use clap::Parser;
use elf::abi;
use elf::dynamic;
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::segment::ProgramHeader;
use elf::string_table::StringTable;
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
    println!("Dynamic section at offset 0x{:x} contains {} entries:", offset, dynamics.len());
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

    parse_elf_header(file.ehdr, ident);
    parse_section_headers(&shdr, &strtab);
    parse_program_headers(&phdr);
    section_to_segment_mapping(&shdr, &phdr, &strtab);
    parse_dynamic_section(&dynamic, dynamic_offset);
}
