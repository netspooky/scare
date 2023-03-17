#!/usr/bin/python
from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from keystone import *

splash = """\x1b[38;5;213m\
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐\x1b[38;5;219m
└──────┐│       ┌──────││       │      │\x1b[38;5;225m
│      ││       │      ││       │──────┘\x1b[38;5;231m
└──────┘└──────┘└──────┘└       └──────┘\x1b[0m
Simple Configurable Asm REPL && Emulator 
                [v0.2.1]
"""

helpfile = """
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
"""

cGReg = "\x1b[38;5;154m" # General Purpose Register Value Color
cZero = "\x1b[38;5;244m" # Grey for 0's
cRegN = "\x1b[38;5;50m"  # Color for register names
cEnd  = "\x1b[0m"        # For the end of lines
cSPtr = "\x1b[38;5;226m" # Stack Pointer Color
cIP   = "\x1b[38;5;219m" # Instruction Pointer color
# Listing Colors
cLnNum = "\x1b[48;5;55m"
cLnPipe = "\x1b[38;5;196m"
cAsmList = "\x1b[38;5;51m"

def configPrint(sConfig):
    print("Current Config Options")
    for cK, cV in sConfig.items():
        print(f"{cK} = {cV}")

### Helper Functions ###########################################################
# dHex - Dump Hex
# inBytes = byte array to dump
# baseAddr = the base address
def dHex(inBytes,baseAddr):
    offs = 0
    while offs < len(inBytes):
        bHex = ""
        bAsc = ""
        bChunk = inBytes[offs:offs+16]
        for b in bChunk:
            bAsc += chr(b) if chr(b).isprintable() and b < 0x7f else '.'
            bHex += "{:02x} ".format(b)
        sp = " "*(48-len(bHex))
        print("{:08x}: {}{} {}".format(baseAddr + offs, bHex, sp, bAsc))
        offs = offs + 16

# loadAsm - Load assembly listing from a file
def loadAsm(fname):
    with open(fname,"r") as f:
        out = f.read().splitlines()
        f.close()
    print(f"Loaded {fname}")
    return out

# saveAsm - Save assembly listing to a file
def saveAsm(inCode, fname):
    out = "\n".join(inCode)
    out += "\n"
    with open(fname,"w") as f:
        f.write(out)
        f.close()
    print(f"Saved {fname}")

# exportBin - Export binary to a file
def exportBin(inCode, fileType, fArch, fname):
    if fileType == "bin":
        outBin = inCode
    elif fileType == "elf64":
        if fArch == "x64":
            eMach = b"\x3e\x00"
        elif fArch == "arm64":
            eMach = b"\xb7\x00"
        else:
            print("Unsupported Arch!")
            return
        b =  b"" # ELF64 Template based on https://n0.lol/test.asm
        b += b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"   # 00000000 .ELF............
        b += b"\x02\x00"+eMach+b"\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00" # 00000010 ..>.....x.@.....
        b += b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"   # 00000020 @...............
        b += b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00"   # 00000030 ....@.8.........
        b += b"\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"   # 00000040 ................
        b += b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"   # 00000050 ..@.......@.....
        b += b"\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"   # 00000060 ................
        b += b"\x00\x02\x00\x00\x00\x00\x00\x00"                                   # 00000070 ........
        outBin = b
        outBin += inCode
    elif fileType == "pe32":
        if fArch == "x64":
            eMach = b"\x4c\x01"
        elif fArch == "x86":
            eMach = b"\x4c\x01"
        else:
            print("Unsupported Arch!")
            return
        b =  b"" # Tiny PE32 Template based on https://github.com/netspooky/kimagure/blob/main/pe32template.asm
        b += b"\x4d\x5a\x00\x01\x50\x45\x00\x00"+eMach+b"\x00\x00\x00\x00\x00\x00" # 00000000 MZ..PE..L.......
        b += b"\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00\x03\x01\x0b\x01\x00\x00"   # 00000010 ........`.......
        b += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7c\x00\x00\x00"   # 00000020 ............|...
        b += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x04\x00\x00\x00"   # 00000030 ..........@.....
        b += b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00"   # 00000040 ................
        b += b"\x00\x00\x00\x00\x80\x00\x00\x00\x7c\x00\x00\x00\x00\x00\x00\x00"   # 00000050 ........|.......
        b += b"\x02\x00\x00\x04\x00\x00\x10\x00\x00\x10\x00\x00\x00\x00\x10\x00"   # 00000060 ................
        b += b"\x00"*12                                                            # 00000070 ............
    else:
        return
    with open(fname,"wb") as f:
        f.write(outBin)
        f.close()
    print(f"Exported code to {fname}")

def ksAssemble(ks_arch_name, CODE):
    try:
        if ks_arch_name == "x64":
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
        elif ks_arch_name == "x86":
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        elif ks_arch_name == "arm64":
            ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        else:
            print("Invalid Arch!")
        mc, num = ks.asm(CODE)
        return bytes(mc)

    except KsError as e:
        eChk = f"{e}"
        if "KS_ERR_ASM_SYMBOL_REDEFINED" in eChk:
            return # Returning because this will happen if a label is appended
        else:
            print("ERROR: %s" %e)
            return

def printListing(ks_arch_name,asmInput,addr):
    if len(asmInput) == 0:
        print("No instructions!")
        return
    asmString = "; ".join(asmInput)
    lineMax = 0
    for l in asmInput:
        lineMax = len(l) if len(l) > lineMax else lineMax
    asmAssembled = ksAssemble(ks_arch_name, "; ".join(asmInput))
    codeOffs = 0
    lineNum = 1
    # Predicting that in longer code with short jumps, this append trick will result in incorrect assembly if outside the range of a short jump
    for i in asmInput:
        asmStringLen = len(asmAssembled)
        tempAsmString = asmString +" ; " + i
        assembledAsm = ksAssemble(ks_arch_name, tempAsmString)
        if assembledAsm is not None:
            assembledAsmLen = len(assembledAsm) - asmStringLen # Disgusting hack to get the full length
        else:
            assembledAsmLen = 0
        asmBytes = asmAssembled[codeOffs:codeOffs+assembledAsmLen]
        spacing = " "*(lineMax - len(i))
        print(f"{cLnNum}{lineNum:03d}{cEnd}{cLnPipe}│{cEnd} {cAsmList}{i}\x1b[0m {spacing}\x1b[38;5;244m; {addr:04X}: \x1b[38;5;227m{asmBytes.hex()}\x1b[0m")
        addr = addr+assembledAsmLen
        codeOffs = codeOffs+assembledAsmLen
        lineNum = lineNum + 1

### Register Output Stuff ######################################################
rNames = {
    "arm64" : {
        "x0" : UC_ARM64_REG_X0,
        "x1" : UC_ARM64_REG_X1,
        "x2" : UC_ARM64_REG_X2,
        "x3" : UC_ARM64_REG_X3,
        "x4" : UC_ARM64_REG_X4,
        "x5" : UC_ARM64_REG_X5,
        "x6" : UC_ARM64_REG_X6,
        "x7" : UC_ARM64_REG_X7,
        "x8" : UC_ARM64_REG_X8,
        "x9" : UC_ARM64_REG_X9,
        "x10": UC_ARM64_REG_X10,
        "x11": UC_ARM64_REG_X11,
        "x12": UC_ARM64_REG_X12,
        "x13": UC_ARM64_REG_X13,
        "x14": UC_ARM64_REG_X14,
        "x15": UC_ARM64_REG_X15,
        "x16": UC_ARM64_REG_X16,
        "x17": UC_ARM64_REG_X17,
        "x18": UC_ARM64_REG_X18,
        "x19": UC_ARM64_REG_X19,
        "x20": UC_ARM64_REG_X20,
        "x21": UC_ARM64_REG_X21,
        "x22": UC_ARM64_REG_X22,
        "x23": UC_ARM64_REG_X23,
        "x24": UC_ARM64_REG_X24,
        "x25": UC_ARM64_REG_X25,
        "x26": UC_ARM64_REG_X26,
        "x27": UC_ARM64_REG_X27,
        "x28": UC_ARM64_REG_X28,
        "x29": UC_ARM64_REG_X29,
        "x30": UC_ARM64_REG_X30,
        "sp":  UC_ARM64_REG_SP,
        "pc":  UC_ARM64_REG_PC,
    },
    "x86": {
        "eax": UC_X86_REG_EAX,
        "ebx": UC_X86_REG_EBX,
        "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX,
        "esi": UC_X86_REG_ESI,
        "edi": UC_X86_REG_EDI,
        "eip": UC_X86_REG_EIP,
        "esp": UC_X86_REG_ESP,
        "ebp": UC_X86_REG_EBP,
        "eflags": UC_X86_REG_EFLAGS,
    },
    "x64": {
        "rax": UC_X86_REG_RAX,
        "rbx": UC_X86_REG_RBX,
        "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX,
        "rsi": UC_X86_REG_RSI,
        "rdi": UC_X86_REG_RDI,
        "rip": UC_X86_REG_RIP,
        "rsp": UC_X86_REG_RSP,
        "rbp": UC_X86_REG_RBP,
        "r8":  UC_X86_REG_R8,
        "r9":  UC_X86_REG_R9,
        "r10": UC_X86_REG_R10,
        "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12,
        "r13": UC_X86_REG_R13,
        "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15,
        "rflags": UC_X86_REG_EFLAGS,
    },
    "xmm": {
        "xmm0":  UC_X86_REG_XMM0,
        "xmm1":  UC_X86_REG_XMM1,
        "xmm2":  UC_X86_REG_XMM2,
        "xmm3":  UC_X86_REG_XMM3,
        "xmm4":  UC_X86_REG_XMM4,
        "xmm5":  UC_X86_REG_XMM5,
        "xmm6":  UC_X86_REG_XMM6,
        "xmm7":  UC_X86_REG_XMM7,
        "xmm8":  UC_X86_REG_XMM8,
        "xmm9":  UC_X86_REG_XMM9,
        "xmm10": UC_X86_REG_XMM10,
        "xmm11": UC_X86_REG_XMM11,
        "xmm12": UC_X86_REG_XMM12,
        "xmm13": UC_X86_REG_XMM13,
        "xmm14": UC_X86_REG_XMM14,
        "xmm15": UC_X86_REG_XMM15,
        "xmm16": UC_X86_REG_XMM16,
        "xmm17": UC_X86_REG_XMM17,
        "xmm18": UC_X86_REG_XMM18,
        "xmm19": UC_X86_REG_XMM19,
        "xmm20": UC_X86_REG_XMM20,
        "xmm21": UC_X86_REG_XMM21,
        "xmm22": UC_X86_REG_XMM22,
        "xmm23": UC_X86_REG_XMM23,
        "xmm24": UC_X86_REG_XMM24,
        "xmm25": UC_X86_REG_XMM25,
        "xmm26": UC_X86_REG_XMM26,
        "xmm27": UC_X86_REG_XMM27,
        "xmm28": UC_X86_REG_XMM28,
        "xmm29": UC_X86_REG_XMM29,
        "xmm30": UC_X86_REG_XMM30,
        "xmm31": UC_X86_REG_XMM31,
    },
}

# printRegsHandler - Wrapper to print all configured registers for a given arch.
# mu = emulator object
# archname = The architecture name
# sConfig = The scare config 
def printRegsHandler(mu, archname, sConfig):
    if archname == "x64":
        printRegs_x64(mu, sConfig)
    elif archname == "x86":
        printRegs_x86(mu, sConfig)
    elif archname == "arm64":
        printRegs_arm64(mu, sConfig)
    else:
        print(f"Invalid Arch ({arch})!")

# regFmt - Format register for output
# mu = Emulator Object
# regType = Type of register for custom styling
#     0 - General Purpose
#     1 - Instruction Pointer
#     2 - Stack Pointer
# regSize = The size of the register in bits
# regName = The emulator specific constant, resolved using rNames dict
def regFmt(mu, regType, regSize, regName):
    outRegVal = mu.reg_read(regName)
    if regType == 0:
        outRegColor = cGReg if outRegVal > 0 else cZero
    elif regType == 1:
        outRegColor = cIP
    elif regType == 2:
        outRegColor = cSPtr
    else:
        print(f"Unknown Register Type {regType}")
        return
    if regSize == 8:
        outRegValFmt = f"{outRegVal:02x}"
    elif regSize == 16:
        outRegValFmt = f"{outRegVal:04x}"
    elif regSize == 32:
        outRegValFmt = f"{outRegVal:08x}"
    elif regSize == 64:
        outRegValFmt = f"{outRegVal:016x}"
    elif regSize == 128:
        outRegValFmt = f"{outRegVal:032x}"
    else:
        print("Unknown Register Size!")
        return
    outRegText = f"{outRegColor}{outRegValFmt}{cEnd}"
    return outRegText

def printRegs_arm64(mu, sConfig):
    print(f"{cRegN} x0: {regFmt(mu,0,64,rNames['arm64']['x0' ])} {cRegN} pc: {regFmt(mu,1,64,rNames['arm64']['pc'] )} {cRegN} sp: {regFmt(mu,2,64,rNames['arm64']['sp'] )} ")
    print(f"{cRegN} x1: {regFmt(mu,0,64,rNames['arm64']['x1' ])} {cRegN}x11: {regFmt(mu,0,64,rNames['arm64']['x11'])} {cRegN}x21: {regFmt(mu,0,64,rNames['arm64']['x21'])}")
    print(f"{cRegN} x2: {regFmt(mu,0,64,rNames['arm64']['x2' ])} {cRegN}x12: {regFmt(mu,0,64,rNames['arm64']['x12'])} {cRegN}x22: {regFmt(mu,0,64,rNames['arm64']['x22'])}")
    print(f"{cRegN} x3: {regFmt(mu,0,64,rNames['arm64']['x3' ])} {cRegN}x13: {regFmt(mu,0,64,rNames['arm64']['x13'])} {cRegN}x23: {regFmt(mu,0,64,rNames['arm64']['x23'])}")
    print(f"{cRegN} x4: {regFmt(mu,0,64,rNames['arm64']['x4' ])} {cRegN}x14: {regFmt(mu,0,64,rNames['arm64']['x14'])} {cRegN}x24: {regFmt(mu,0,64,rNames['arm64']['x24'])}")
    print(f"{cRegN} x5: {regFmt(mu,0,64,rNames['arm64']['x5' ])} {cRegN}x15: {regFmt(mu,0,64,rNames['arm64']['x15'])} {cRegN}x25: {regFmt(mu,0,64,rNames['arm64']['x25'])}")
    print(f"{cRegN} x6: {regFmt(mu,0,64,rNames['arm64']['x6' ])} {cRegN}x16: {regFmt(mu,0,64,rNames['arm64']['x16'])} {cRegN}x26: {regFmt(mu,0,64,rNames['arm64']['x26'])}")
    print(f"{cRegN} x7: {regFmt(mu,0,64,rNames['arm64']['x7' ])} {cRegN}x17: {regFmt(mu,0,64,rNames['arm64']['x17'])} {cRegN}x27: {regFmt(mu,0,64,rNames['arm64']['x27'])}")
    print(f"{cRegN} x8: {regFmt(mu,0,64,rNames['arm64']['x8' ])} {cRegN}x18: {regFmt(mu,0,64,rNames['arm64']['x18'])} {cRegN}x28: {regFmt(mu,0,64,rNames['arm64']['x28'])}")
    print(f"{cRegN} x9: {regFmt(mu,0,64,rNames['arm64']['x9' ])} {cRegN}x19: {regFmt(mu,0,64,rNames['arm64']['x19'])} {cRegN}x29: {regFmt(mu,0,64,rNames['arm64']['x29'])}")
    print(f"{cRegN}x10: {regFmt(mu,0,64,rNames['arm64']['x10'])} {cRegN}x20: {regFmt(mu,0,64,rNames['arm64']['x20'])} {cRegN}x30: {regFmt(mu,0,64,rNames['arm64']['x30'])}")
    print(cEnd,end="")

def printRegs_XMM(mu, sConfig):
    print(f"{cRegN} xmm0: {regFmt(mu,0,128,rNames['xmm']['xmm0'] )} {cRegN}xmm16: {regFmt(mu,0,128,rNames['xmm']['xmm16'])}")
    print(f"{cRegN} xmm1: {regFmt(mu,0,128,rNames['xmm']['xmm1'] )} {cRegN}xmm17: {regFmt(mu,0,128,rNames['xmm']['xmm17'])}")
    print(f"{cRegN} xmm2: {regFmt(mu,0,128,rNames['xmm']['xmm2'] )} {cRegN}xmm18: {regFmt(mu,0,128,rNames['xmm']['xmm18'])}")
    print(f"{cRegN} xmm3: {regFmt(mu,0,128,rNames['xmm']['xmm3'] )} {cRegN}xmm19: {regFmt(mu,0,128,rNames['xmm']['xmm19'])}")
    print(f"{cRegN} xmm4: {regFmt(mu,0,128,rNames['xmm']['xmm4'] )} {cRegN}xmm20: {regFmt(mu,0,128,rNames['xmm']['xmm20'])}")
    print(f"{cRegN} xmm5: {regFmt(mu,0,128,rNames['xmm']['xmm5'] )} {cRegN}xmm21: {regFmt(mu,0,128,rNames['xmm']['xmm21'])}")
    print(f"{cRegN} xmm6: {regFmt(mu,0,128,rNames['xmm']['xmm6'] )} {cRegN}xmm22: {regFmt(mu,0,128,rNames['xmm']['xmm22'])}")
    print(f"{cRegN} xmm7: {regFmt(mu,0,128,rNames['xmm']['xmm7'] )} {cRegN}xmm23: {regFmt(mu,0,128,rNames['xmm']['xmm23'])}")
    print(f"{cRegN} xmm8: {regFmt(mu,0,128,rNames['xmm']['xmm8'] )} {cRegN}xmm24: {regFmt(mu,0,128,rNames['xmm']['xmm24'])}")
    print(f"{cRegN} xmm9: {regFmt(mu,0,128,rNames['xmm']['xmm9'] )} {cRegN}xmm25: {regFmt(mu,0,128,rNames['xmm']['xmm25'])}")
    print(f"{cRegN}xmm10: {regFmt(mu,0,128,rNames['xmm']['xmm10'])} {cRegN}xmm26: {regFmt(mu,0,128,rNames['xmm']['xmm26'])}")
    print(f"{cRegN}xmm11: {regFmt(mu,0,128,rNames['xmm']['xmm11'])} {cRegN}xmm27: {regFmt(mu,0,128,rNames['xmm']['xmm27'])}")
    print(f"{cRegN}xmm12: {regFmt(mu,0,128,rNames['xmm']['xmm12'])} {cRegN}xmm28: {regFmt(mu,0,128,rNames['xmm']['xmm28'])}")
    print(f"{cRegN}xmm13: {regFmt(mu,0,128,rNames['xmm']['xmm13'])} {cRegN}xmm29: {regFmt(mu,0,128,rNames['xmm']['xmm29'])}")
    print(f"{cRegN}xmm14: {regFmt(mu,0,128,rNames['xmm']['xmm14'])} {cRegN}xmm30: {regFmt(mu,0,128,rNames['xmm']['xmm30'])}")
    print(f"{cRegN}xmm15: {regFmt(mu,0,128,rNames['xmm']['xmm15'])} {cRegN}xmm31: {regFmt(mu,0,128,rNames['xmm']['xmm31'])}")

def printRegs_x64(mu, sConfig):
    print(f"{cRegN}rax: {regFmt(mu,0,64,rNames['x64']['rax'])} {cRegN}rip: {regFmt(mu,1,64,rNames['x64']['rip'])} {cRegN}r11: {regFmt(mu,0,64,rNames['x64']['r11'])}")
    print(f"{cRegN}rbx: {regFmt(mu,0,64,rNames['x64']['rbx'])} {cRegN}rsp: {regFmt(mu,2,64,rNames['x64']['rsp'])} {cRegN}r12: {regFmt(mu,0,64,rNames['x64']['r12'])}")
    print(f"{cRegN}rcx: {regFmt(mu,0,64,rNames['x64']['rcx'])} {cRegN}rbp: {regFmt(mu,0,64,rNames['x64']['rbp'])} {cRegN}r13: {regFmt(mu,0,64,rNames['x64']['r13'])}")
    print(f"{cRegN}rdx: {regFmt(mu,0,64,rNames['x64']['rdx'])} {cRegN} r8: {regFmt(mu,0,64,rNames['x64']['r8'] )} {cRegN}r14: {regFmt(mu,0,64,rNames['x64']['r14'])}")
    print(f"{cRegN}rsi: {regFmt(mu,0,64,rNames['x64']['rsi'])} {cRegN} r9: {regFmt(mu,0,64,rNames['x64']['r9'] )} {cRegN}r15: {regFmt(mu,0,64,rNames['x64']['r15'])}")
    print(f"{cRegN}rdi: {regFmt(mu,0,64,rNames['x64']['rdi'])} {cRegN}r10: {regFmt(mu,0,64,rNames['x64']['r10'])} {cRegN}rfl: {regFmt(mu,0,64,rNames['x64']['rflags'])}")
    print(cEnd,end="")
    if sConfig["x86/xmm"]:
        printRegs_XMM(mu, sConfig)

def printRegs_x86(mu, sConfig):
    print(f"{cRegN}eax: {regFmt(mu,0,32,rNames['x86']['eax'])}")
    print(f"{cRegN}ecx: {regFmt(mu,0,32,rNames['x86']['ecx'])}")
    print(f"{cRegN}edx: {regFmt(mu,0,32,rNames['x86']['edx'])}")
    print(f"{cRegN}ebx: {regFmt(mu,0,32,rNames['x86']['ebx'])}")
    print(f"{cRegN}esp: {regFmt(mu,2,32,rNames['x86']['esp'])}")
    print(f"{cRegN}ebp: {regFmt(mu,0,32,rNames['x86']['ebp'])}")
    print(f"{cRegN}esi: {regFmt(mu,0,32,rNames['x86']['esi'])}")
    print(f"{cRegN}edi: {regFmt(mu,0,32,rNames['x86']['edi'])}")
    print(f"{cRegN}eip: {regFmt(mu,1,32,rNames['x86']['eip'])}")
    print(f"{cRegN}efl: {regFmt(mu,0,32,rNames['x86']['eflags'])}")
    print(cEnd,end="")
    if sConfig["x86/xmm"]:
        printRegs_XMM(mu, sConfig)
