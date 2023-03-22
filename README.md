# scare - Simple Configurable Assembly REPL && Emulator

`scare` is a multi-arch assembly REPL and emulator for your command line.

There aren't many modern assembly REPLs out there. The ones that do exist are either opaque webapps, or are tied to specific architecture/platform. `scare` was built for people who want to test, experiment, or otherwise play with assembly code. All assembled code is run in an emulator, which executes only the code you give it. The multi-architecture design for the underlying `scarelib` library is meant to be modular, allowing for new architectures to be added quickly. 

Version 0.3.0 is the first public release of `scare`.

Core Features
- Write assembly in a REPL environment
- Load or save programs you've written
- Step backwards in your program
- Export your assembled code as small binaries for testing

Currently Supported Architectures
- x86
- x64
- arm32
- arm64

Requirements
- python3
- keystone-engine
- unicorn
- capstone

# Usage

Invoke scare from the command line with the desired architecture. This will create a REPL instance with the default settings.
```
python3 scare.py -a x64
```

Help file
```
[x64]400000> /
scare Help

/ /? /help                        -- Open help menu
/x /exit /q /quit                 -- Quit the program

/back n                           -- Go back n number of lines
/dis {0xaddress|$register} NUM    -- Disassemble NUM bytes from 0xaddress or $register
/export FILETYPE FILENAME         -- Export machine code as FILETYPE to the FILENAME
                                     FILETYPE List:
                                     - bin
                                     - elf64
                                     - pe32
/info                             -- Info about the emulator state
/l /list                          -- List the current program
/load file.asm                    -- Load listing from file.asm (overwrites current program)
/read {0xaddress|$register} NUM   -- Read NUM bytes from 0xaddress or $register
/reset                            -- Reset the emulator to a clean state
/run                              -- Run the current program
/save file.asm                    -- Save assembly output to file.asm

[[: Config Commands :]] (Use /c or /config)
NOTE: Run /reset if you are changing emu/* options, otherwise the emulator may not start!

/c               -- Print all config options
/c emu/arch      -- Print Arch Value
/c emu/arch x64  -- Set Arch to x64
/c x86/xmm 1     -- Enable x86/xmm
```

Going backwards in the assembly listing
```
mov eax, 0x5555
mov ebx, 0xaaaa
xor eax, ebx
/l
/back 2
mov ecx, 0xbbbb
add eax, ecx
```

Loading a file, saving a file
```
/load examples/test.asm
/l
/run
/read 0x400ff0 32
pop rdx
/save test2.asm
```

Export as binary, here you should get an elf64 called `exit55.elf` that exits when run.
```
mov eax, 0x3c
mov edi, 55
syscall
/export elf64 exit55.elf
```

Using config options

```
not rax
/c x86/xmm 1
movq xmm4, rax
movaps xmm5, xmm4
```

# Gallery

Decoding shellcode:
![screenshot of the tool in a terminal](https://user-images.githubusercontent.com/26436276/226787427-0b6827a6-1c13-40f7-9bc0-ee235740d780.png)

Exporting code to an elf64 and running it:
![screenshot of exporting code and running as an elf64](https://user-images.githubusercontent.com/26436276/226787469-eb7c6d7d-2481-447b-b2fc-4390f643cc61.png)

# Contributing

There are many things that would be awesome to add in the future: more architectures (both well-known and obscure), more cpu modes, better environment emulation, hot swapping between emu/asm/dis libraries etc. Getting the emulator, assembler, and disassembler to play nicely is not always straightforward. 

Some features may not be supported due to requiring decisions to be made on the configuration of the emulator. The goal of this project is to be a generic REPL and emulator solution for a target arch. As a result, the development roadmap is going to be "adding stuff that people bring up", while keeping it easy to use and develop.

If you have ideas, feel free to make a PR.

If you find a bug, feel free to file an issue.

Thank you and have fun!

~ netspooky

Shout out to the haunted crew
