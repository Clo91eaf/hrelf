use clap::Parser;
use elf::abi::EI_VERSION;
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::segment::ProgramHeader;
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
    println!("  Version:                    {:?} (current)", ident[EI_VERSION]);
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
}

fn parse_section_headers(shdrs: Vec<SectionHeader>) {
    println!("Section Headers:");
    println!("  [Nr] Name              Type              Address            Offset");
    println!("       Size              EntSize           Flags  Link  Info  Align");
    for (i, shdr) in shdrs.iter().enumerate() {
        println!(
            "  [{:>2}] {:<17} {:<15}   {:016x}   {:08x}",
            i,
            shdr.sh_name,
            to_str::sh_type_to_string(shdr.sh_type),
            shdr.sh_addr,
            shdr.sh_offset
        );
        println!(
            "       {:016x}  {:016x}  {:<6} {:<5} {:<5} {:<5}",
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

fn parse_program_headers(phdrs: Vec<ProgramHeader>) {
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

fn main() {
    let args = Args::parse();
    let file_data = std::fs::read(args.file).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
    let ident = slice.get(0..16).unwrap();
    let shdr: Vec<SectionHeader> = file.section_headers().unwrap().iter().collect();
    let phdr: Vec<ProgramHeader> = file.segments().unwrap().iter().collect();
    parse_elf_header(file.ehdr, ident);
    parse_section_headers(shdr);
    parse_program_headers(phdr);
}
