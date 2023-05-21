use clap::Parser;
use elf::abi::EI_VERSION;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use elf::to_str;

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

fn parse_elf_header(ehdr: elf::file::FileHeader<AnyEndian>, ident: &[u8]) {
    println!("ELF Header:");
    println!("  Magic: {:0x?}", ident);
    println!("  Class: {:?}", ehdr.class);
    println!("  Data: {:?}", ehdr.endianness);
    println!("  Version: {:?}", ident[EI_VERSION]);
    println!("  OS/ABI: {}", to_str::e_osabi_to_string(ehdr.osabi));
    println!("  ABI Version: {:?}", ehdr.abiversion);
    println!("  Type: {}", to_str::e_type_to_human_str(ehdr.e_type).unwrap());
    println!("  Machine: {}", to_str::e_machine_to_human_str(ehdr.e_machine).unwrap());
    println!("  Version: 0x{:x}", ehdr.version);
    println!("  Entry point address: 0x{:x}", ehdr.e_entry);
    println!("  Start of program headers: {:?}", ehdr.e_phoff);
    println!("  Start of section headers: {:?}", ehdr.e_shoff);
    println!("  Flags: 0x{:x}", ehdr.e_flags);
    println!("  Size of this header: {:?}", ehdr.e_ehsize);
    println!("  Size of program headers: {:?}", ehdr.e_phentsize);
    println!("  Number of program headers: {:?}", ehdr.e_phnum);
    println!("  Size of section headers: {:?}", ehdr.e_shentsize);
    println!("  Number of section headers: {:?}", ehdr.e_shnum);
    println!("  Section header string table index: {:?}", ehdr.e_shstrndx);
}

fn main() {
    let args = Args::parse();
    let file_data = std::fs::read(args.file).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).unwrap();
    let ident = slice.get(0..16).unwrap();
    parse_elf_header(file.ehdr, ident);
    println!("Common sections: {:?}", file.ehdr);
}
