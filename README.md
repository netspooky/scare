# scare

This is a little assembly repl and emulator for fun. The primary usecase is to enable you to quickly see what some assembly code does. It's not meant to be a serious emulation solution.

Currently only targeting x64, planning to add more architectures (mainly arm and riscv). This version is probably buggy and has a bunch of edge cases to address.

Don't 4get 2 have fun :)

Requirements
- keystone-engine
- unicorn

# Usage

Run: `python3 scare.py`

Help file
```
[x64]400000> /
scare help

USAGE

Type assembly code into the repl, line by line.

COMMANDS

/ /? /help           -- Open help menu
/x /exit /q /quit    -- Quit the program
/l /list             -- List the current program
/back n              -- Go back n number of lines
/save file.asm       -- Save current listing to file
/load file.asm       -- Load listing from file (overwrites current program)
/run                 -- Runs the program
/read 0xaddress size -- Read (size) amount of bytes from (0xaddress) [EXPERIMENTAL]

CONFIG

/c or /config  -- Show configurable options
/c OPTION on   -- Turn config option on
/c OPTION off  -- Turn config option off
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

Using config options

```
not rax
/config x86 xmm on
movq xmm4, rax
movaps xmm5, xmm4
```

# Gallery

<img width="930" alt="screenshot of using scare" src="https://user-images.githubusercontent.com/26436276/223963337-b018740d-d1ac-4344-b664-a9ed5756f2f3.png">



