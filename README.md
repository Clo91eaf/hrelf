# hrelf💻 (HDU Readelf)

`hrelf` is a command-line tool that provides similar functionality to Linux's `readelf` program. It can parse an ELF binary and print out information about its headers, sections, symbols, and relocations.

## Installation📦

To use `hrelf`, you need to have Rust installed on your system. You can download and install Rust from the official website: https://www.rust-lang.org/tools/install

Once you have Rust installed, you can install `hrelf` using `cargo`, Rust's package manager:

```sh
$ cargo install hrelf
```

This will download the source code, compile it, and install the binary in your system's default binary directory (`$HOME/.cargo/bin/` by default).

## Usage⚙️

To use `hrelf`, simply run the following command:

```sh
$ hrelf -f <file>
```

Replace `<file>` with the path to the ELF binary you want to analyze. `hrelf` will then print out information about the binary's headers, sections, symbols, and relocations.

For a full list of options, run:

```sh
$ hrelf --help
```

## License📜

`hrelf` is licensed under the MIT license. See `LICENSE` for more details.

## Contributing🤝

If you would like to contribute to `hrelf`, please open an issue or pull request on [GitHub](https://github.com/your-github-username/hrelf). 

Thank you for considering contributing to this project!
