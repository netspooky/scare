# scare

I haven't properly shared this yet because it's not finished. It's here for testing purposes. Use at your own risk.

This is a little assembly repl and emulator for fun. The primary usecase is to enable you to quickly see what some assembly code does. It's not meant to be a serious emulation solution.

Currently only targeting x64, planning to add more architectures (mainly arm and riscv). This version is probably buggy and has a bunch of edge cases to address.

Don't 4get 2 have fun :)

Requirements
- keystone-engine
- unicorn
- capstone

# Usage

Command line flags
```
～ python3 scare.py -h
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
└──────┐│       ┌──────││       │      │
│      ││       │      ││       │──────┘
└──────┘└──────┘└──────┘└       └──────┘
Simple Configurable Asm REPL && Emulator
                [v0.2.0]

usage: scare.py [-h] [-a ARCH] [-f INFILE] [--base BASEADDR] [--stack STACKADDR]
                [--memsize MEMSIZE]

options:
  -h, --help         show this help message and exit
  -a ARCH            Target architecture
  -f INFILE          File to read
  --base BASEADDR    Base Address (default: 0x400000)
  --stack STACKADDR  Stack Address (default: 0x401000)
  --memsize MEMSIZE  Emulator Memory Size (default: 0x200000 [2MB])
```

Help file
```
[x64]400000> /

Help File

/ /? /help                        -- Open help menu
/x /exit /q /quit                 -- Quit the program
/info                             -- Info about the emulator state
/l /list                          -- List the current program
/run                              -- Run the current program
/reset                            -- Reset the emulator to a clean state
/back n                           -- Go back n number of lines
/load file.asm                    -- Load listing from file.asm (overwrites current program)
/save file.asm                    -- Save assembly output to file.asm
/export FILETYPE FILENAME         -- Export machine code as FILETYPE to the FILENAME
                                     FILETYPE List:
                                     - bin
                                     - elf64
                                     - pe32
/read {0xaddress|$register} NUM   -- Read NUM bytes from 0xaddress or $register
/dis {0xaddress|$register} NUM    -- Disassemble NUM bytes from 0xaddress or $register

Config Commands (Use /c or /config)
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

![screenshot of the tool in a terminal](https://user-images.githubusercontent.com/26436276/225798291-dac2741c-d553-4b4f-82ec-b1a680a16436.png)

