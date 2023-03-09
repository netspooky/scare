#!/usr/bin/python

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from keystone import *
import time
import sys

splash = """\
┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
└──────┐│       ┌──────││       │      │
│      ││       │      ││       │──────┘
└──────┘└──────┘└──────┘└       └──────┘
Simple Configurable Asm REPL && Emulator 
                [v0.1.0]

Type / for help
"""

helpfile = """scare help

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
"""

sConfig = {
    "emu" : {
        "baseaddr": 0x400000,
        "stackaddr": 0x401000,
    },
    "x86": {
        #"debug": False, # Debug registers, not supported yet
        "xmm": False,
        #"ymm": False, # Not supported yet
        #"zmm": False, # Not supported yet
    }
}

regColor   = "\x1b[38;5;189m"
emptyColor = "\x1b[38;5;244m"
regnColor  = "\x1b[38;5;50m"

regz = {} # Structure to hold all the register states here and return them.
asmLines = [] # Holds all the lines of assembly
baseaddr = sConfig["emu"]["baseaddr"]
addr = baseaddr
running = 0 # Track when the emulator has run
## Commands
quitcmds = ["/exit", "/x", "/quit", "/q"]
listcmds = ["/list", "/l"]
configcmds = ["/config", "/c"]
helpcmds = ["/", "/help", "/?", "/h"]
CmdContinue = "!!C"

def dHex(inBytes,baddr):
    offs = 0
    while offs < len(inBytes):
        bHex = ""
        bAsc = ""
        bChunk = inBytes[offs:offs+16]
        for b in bChunk:
            bAsc += chr(b) if chr(b).isprintable() else '.'
            bHex += "{:02X} ".format(b)
        sp = " "*(48-len(bHex))
        print("{:08X}: {}{} {}".format(baddr + offs, bHex, sp, bAsc))
        offs = offs + 16

def ksAssemble(CODE):
    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        mc, num = ks.asm(CODE)
        return bytes(mc)

    except KsError as e:
        eChk = f"{e}"
        if "KS_ERR_ASM_SYMBOL_REDEFINED" in eChk:
            return # Returning because this will happen if a label is appended
        else:
            print("ERROR: %s" %e)
            return

def printXMM(mu):
    regz["xmm0"]  = mu.reg_read(UC_X86_REG_XMM0)
    regz["xmm1"]  = mu.reg_read(UC_X86_REG_XMM1)
    regz["xmm2"]  = mu.reg_read(UC_X86_REG_XMM2)
    regz["xmm3"]  = mu.reg_read(UC_X86_REG_XMM3)
    regz["xmm4"]  = mu.reg_read(UC_X86_REG_XMM4)
    regz["xmm5"]  = mu.reg_read(UC_X86_REG_XMM5)
    regz["xmm6"]  = mu.reg_read(UC_X86_REG_XMM6)
    regz["xmm7"]  = mu.reg_read(UC_X86_REG_XMM7)
    regz["xmm8"]  = mu.reg_read(UC_X86_REG_XMM8)
    regz["xmm9"]  = mu.reg_read(UC_X86_REG_XMM9)
    regz["xmm10"] = mu.reg_read(UC_X86_REG_XMM10)
    regz["xmm11"] = mu.reg_read(UC_X86_REG_XMM11)
    regz["xmm12"] = mu.reg_read(UC_X86_REG_XMM12)
    regz["xmm13"] = mu.reg_read(UC_X86_REG_XMM13)
    regz["xmm14"] = mu.reg_read(UC_X86_REG_XMM14)
    regz["xmm15"] = mu.reg_read(UC_X86_REG_XMM15)
    regz["xmm16"] = mu.reg_read(UC_X86_REG_XMM16)
    regz["xmm17"] = mu.reg_read(UC_X86_REG_XMM17)
    regz["xmm18"] = mu.reg_read(UC_X86_REG_XMM18)
    regz["xmm19"] = mu.reg_read(UC_X86_REG_XMM19)
    regz["xmm20"] = mu.reg_read(UC_X86_REG_XMM20)
    regz["xmm21"] = mu.reg_read(UC_X86_REG_XMM21)
    regz["xmm22"] = mu.reg_read(UC_X86_REG_XMM22)
    regz["xmm23"] = mu.reg_read(UC_X86_REG_XMM23)
    regz["xmm24"] = mu.reg_read(UC_X86_REG_XMM24)
    regz["xmm25"] = mu.reg_read(UC_X86_REG_XMM25)
    regz["xmm26"] = mu.reg_read(UC_X86_REG_XMM26)
    regz["xmm27"] = mu.reg_read(UC_X86_REG_XMM27)
    regz["xmm28"] = mu.reg_read(UC_X86_REG_XMM28)
    regz["xmm29"] = mu.reg_read(UC_X86_REG_XMM29)
    regz["xmm30"] = mu.reg_read(UC_X86_REG_XMM30)
    regz["xmm31"] = mu.reg_read(UC_X86_REG_XMM31)

    rXMM0c = regColor if regz["xmm0"] > 0 else emptyColor
    rXMM1c = regColor if regz["xmm1"] > 0 else emptyColor
    rXMM2c = regColor if regz["xmm2"] > 0 else emptyColor
    rXMM3c = regColor if regz["xmm3"] > 0 else emptyColor
    rXMM4c = regColor if regz["xmm4"] > 0 else emptyColor
    rXMM5c = regColor if regz["xmm5"] > 0 else emptyColor
    rXMM6c = regColor if regz["xmm6"] > 0 else emptyColor
    rXMM7c = regColor if regz["xmm7"] > 0 else emptyColor
    rXMM8c = regColor if regz["xmm8"] > 0 else emptyColor
    rXMM9c = regColor if regz["xmm9"] > 0 else emptyColor
    rXMM10c = regColor if regz["xmm10"] > 0 else emptyColor
    rXMM11c = regColor if regz["xmm11"] > 0 else emptyColor
    rXMM12c = regColor if regz["xmm12"] > 0 else emptyColor
    rXMM13c = regColor if regz["xmm13"] > 0 else emptyColor
    rXMM14c = regColor if regz["xmm14"] > 0 else emptyColor
    rXMM15c = regColor if regz["xmm15"] > 0 else emptyColor
    rXMM16c = regColor if regz["xmm16"] > 0 else emptyColor
    rXMM17c = regColor if regz["xmm17"] > 0 else emptyColor
    rXMM18c = regColor if regz["xmm18"] > 0 else emptyColor
    rXMM19c = regColor if regz["xmm19"] > 0 else emptyColor
    rXMM20c = regColor if regz["xmm20"] > 0 else emptyColor
    rXMM21c = regColor if regz["xmm21"] > 0 else emptyColor
    rXMM22c = regColor if regz["xmm22"] > 0 else emptyColor
    rXMM23c = regColor if regz["xmm23"] > 0 else emptyColor
    rXMM24c = regColor if regz["xmm24"] > 0 else emptyColor
    rXMM25c = regColor if regz["xmm25"] > 0 else emptyColor
    rXMM26c = regColor if regz["xmm26"] > 0 else emptyColor
    rXMM27c = regColor if regz["xmm27"] > 0 else emptyColor
    rXMM28c = regColor if regz["xmm28"] > 0 else emptyColor
    rXMM29c = regColor if regz["xmm29"] > 0 else emptyColor
    rXMM30c = regColor if regz["xmm30"] > 0 else emptyColor
    rXMM31c = regColor if regz["xmm31"] > 0 else emptyColor

    print(f'{regnColor} xmm0: {rXMM0c}{regz["xmm0" ]:032x}\x1b[0m {regnColor}xmm16: {rXMM16c}{regz["xmm16"]:032x}\x1b[0m')
    print(f'{regnColor} xmm1: {rXMM1c}{regz["xmm1" ]:032x}\x1b[0m {regnColor}xmm17: {rXMM17c}{regz["xmm17"]:032x}\x1b[0m')
    print(f'{regnColor} xmm2: {rXMM2c}{regz["xmm2" ]:032x}\x1b[0m {regnColor}xmm18: {rXMM18c}{regz["xmm18"]:032x}\x1b[0m')
    print(f'{regnColor} xmm3: {rXMM3c}{regz["xmm3" ]:032x}\x1b[0m {regnColor}xmm19: {rXMM19c}{regz["xmm19"]:032x}\x1b[0m')
    print(f'{regnColor} xmm4: {rXMM4c}{regz["xmm4" ]:032x}\x1b[0m {regnColor}xmm20: {rXMM20c}{regz["xmm20"]:032x}\x1b[0m')
    print(f'{regnColor} xmm5: {rXMM5c}{regz["xmm5" ]:032x}\x1b[0m {regnColor}xmm21: {rXMM21c}{regz["xmm21"]:032x}\x1b[0m')
    print(f'{regnColor} xmm6: {rXMM6c}{regz["xmm6" ]:032x}\x1b[0m {regnColor}xmm22: {rXMM22c}{regz["xmm22"]:032x}\x1b[0m')
    print(f'{regnColor} xmm7: {rXMM7c}{regz["xmm7" ]:032x}\x1b[0m {regnColor}xmm23: {rXMM23c}{regz["xmm23"]:032x}\x1b[0m')
    print(f'{regnColor} xmm8: {rXMM8c}{regz["xmm8" ]:032x}\x1b[0m {regnColor}xmm24: {rXMM24c}{regz["xmm24"]:032x}\x1b[0m')
    print(f'{regnColor} xmm9: {rXMM9c}{regz["xmm9" ]:032x}\x1b[0m {regnColor}xmm25: {rXMM25c}{regz["xmm25"]:032x}\x1b[0m')
    print(f'{regnColor}xmm10: {rXMM10c}{regz["xmm10"]:032x}\x1b[0m {regnColor}xmm26: {rXMM26c}{regz["xmm26"]:032x}\x1b[0m')
    print(f'{regnColor}xmm11: {rXMM11c}{regz["xmm11"]:032x}\x1b[0m {regnColor}xmm27: {rXMM27c}{regz["xmm27"]:032x}\x1b[0m')
    print(f'{regnColor}xmm12: {rXMM12c}{regz["xmm12"]:032x}\x1b[0m {regnColor}xmm28: {rXMM28c}{regz["xmm28"]:032x}\x1b[0m')
    print(f'{regnColor}xmm13: {rXMM13c}{regz["xmm13"]:032x}\x1b[0m {regnColor}xmm29: {rXMM29c}{regz["xmm29"]:032x}\x1b[0m')
    print(f'{regnColor}xmm14: {rXMM14c}{regz["xmm14"]:032x}\x1b[0m {regnColor}xmm30: {rXMM30c}{regz["xmm30"]:032x}\x1b[0m')
    print(f'{regnColor}xmm15: {rXMM15c}{regz["xmm15"]:032x}\x1b[0m {regnColor}xmm31: {rXMM31c}{regz["xmm31"]:032x}\x1b[0m')

def runUC_x64(X86_CODE64, mu):
    ADDRESS = sConfig["emu"]["baseaddr"]
    STACK_BEGIN = sConfig["emu"]["stackaddr"]
    try:
        #mu = Uc(UC_ARCH_X86, UC_MODE_64) # Moving this out of here for a global emulator state
        ucmemsz = 2 * 1024 * 1024 # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)
        mu.mem_write(ADDRESS, X86_CODE64) # map the code
        mu.reg_write(UC_X86_REG_RSP, STACK_BEGIN) # initialize registers
        mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE64)) # start emulator

        regz["rax"] = mu.reg_read(UC_X86_REG_RAX)
        regz["rbx"] = mu.reg_read(UC_X86_REG_RBX)
        regz["rcx"] = mu.reg_read(UC_X86_REG_RCX)
        regz["rdx"] = mu.reg_read(UC_X86_REG_RDX)
        regz["rsi"] = mu.reg_read(UC_X86_REG_RSI)
        regz["rdi"] = mu.reg_read(UC_X86_REG_RDI)
        regz["rip"] = mu.reg_read(UC_X86_REG_RIP)
        regz["rsp"] = mu.reg_read(UC_X86_REG_RSP)
        regz["rbp"] = mu.reg_read(UC_X86_REG_RBP)
        regz["r8"]  = mu.reg_read(UC_X86_REG_R8)
        regz["r9"]  = mu.reg_read(UC_X86_REG_R9)
        regz["r10"] = mu.reg_read(UC_X86_REG_R10)
        regz["r11"] = mu.reg_read(UC_X86_REG_R11)
        regz["r12"] = mu.reg_read(UC_X86_REG_R12)
        regz["r13"] = mu.reg_read(UC_X86_REG_R13)
        regz["r14"] = mu.reg_read(UC_X86_REG_R14)
        regz["r15"] = mu.reg_read(UC_X86_REG_R15)
        regz["flags"] = mu.reg_read(UC_X86_REG_EFLAGS)
        rRAXc = regColor if regz["rax"] > 0 else emptyColor
        rRBXc = regColor if regz["rbx"] > 0 else emptyColor
        rRCXc = regColor if regz["rcx"] > 0 else emptyColor
        rRDXc = regColor if regz["rdx"] > 0 else emptyColor
        rRBPc = regColor if regz["rbp"] > 0 else emptyColor
        rRSIc = regColor if regz["rsi"] > 0 else emptyColor
        rRDIc = regColor if regz["rdi"] > 0 else emptyColor
        rR08c = regColor if regz["r8"]  > 0 else emptyColor
        rR09c = regColor if regz["r9"]  > 0 else emptyColor
        rR10c = regColor if regz["r10"] > 0 else emptyColor
        rR11c = regColor if regz["r11"] > 0 else emptyColor
        rR12c = regColor if regz["r12"] > 0 else emptyColor
        rR13c = regColor if regz["r13"] > 0 else emptyColor
        rR14c = regColor if regz["r14"] > 0 else emptyColor
        rR15c = regColor if regz["r15"] > 0 else emptyColor
        rRSPc = "\x1b[38;5;214m" 
        rRIPc = "\x1b[38;5;197m" 
        rEFLAGSc = regColor if regz["flags"] > 0 else emptyColor

        print(f"{regnColor}rax: {rRAXc}{regz['rax']:016x}\x1b[0m {regnColor}rip: {rRIPc}{regz['rip']:016x}\x1b[0m {regnColor}r11: {rR11c}{regz['r11']:016x}\x1b[0m")
        print(f"{regnColor}rbx: {rRBXc}{regz['rbx']:016x}\x1b[0m {regnColor}rsp: {rRSPc}{regz['rsp']:016x}\x1b[0m {regnColor}r12: {rR12c}{regz['r12']:016x}\x1b[0m")
        print(f"{regnColor}rcx: {rRCXc}{regz['rcx']:016x}\x1b[0m {regnColor}rbp: {rRBPc}{regz['rbp']:016x}\x1b[0m {regnColor}r13: {rR13c}{regz['r13']:016x}\x1b[0m")
        print(f"{regnColor}rdx: {rRDXc}{regz['rdx']:016x}\x1b[0m {regnColor} r8: {rR08c}{regz['r8']:016x}\x1b[0m {regnColor}r14: {rR14c}{regz['r14']:016x}\x1b[0m")
        print(f"{regnColor}rsi: {rRSIc}{regz['rsi']:016x}\x1b[0m {regnColor} r9: {rR09c}{regz['r9']:016x}\x1b[0m {regnColor}r15: {rR15c}{regz['r15']:016x}\x1b[0m")
        print(f"{regnColor}rdi: {rRDIc}{regz['rdi']:016x}\x1b[0m {regnColor}r10: {rR10c}{regz['r10']:016x}\x1b[0m flg: {regz['flags']:016x}\x1b[0m")
        if sConfig["x86"]["xmm"]:
            printXMM(mu)
        return 0

    except UcError as e:
        print("ERROR: %s" % e)
        return 1

def saveOutput(inCode, fname):
    out = "\n".join(inCode)
    out += "\n"
    with open(fname,"w") as f:
        f.write(out)
        f.close()
    print(f"Saved {fname}")

def loadAsm(fname):
    with open(fname,"r") as f:
        out = f.read().splitlines()
        f.close()
    print(f"Loaded {fname}")
    return out

def printListing(asmInput,addr):
    if len(asmInput) == 0:
        print("No instructions!")
        return
    asmString = "; ".join(asmInput)
    lineMax = 0
    for l in asmInput:
        lineMax = len(l) if len(l) > lineMax else lineMax
    asmAssembled = ksAssemble("; ".join(asmInput))
    codeOffs = 0
    lineNum = 1
    # Predicting that in longer code with short jumps, this append trick will result in incorrect assembly if outside the range of a short jump
    for i in asmInput:
        asmStringLen = len(asmAssembled)
        tempAsmString = asmString +" ; " + i
        assembledAsm = ksAssemble(tempAsmString)
        if assembledAsm is not None:
            assembledAsmLen = len(assembledAsm) - asmStringLen # Disgusting hack to get the full length
        else:
            assembledAsmLen = 0
        asmBytes = asmAssembled[codeOffs:codeOffs+assembledAsmLen]
        spacing = " "*(lineMax - len(i))
        print(f"{lineNum:02d}│ \x1b[38;5;158m{i}\x1b[0m {spacing}\x1b[38;5;244m; {addr:04X}: \x1b[38;5;227m{asmBytes.hex()}\x1b[0m")
        addr = addr+assembledAsmLen
        codeOffs = codeOffs+assembledAsmLen
        lineNum = lineNum + 1

def configPrint():
    print("Toggle config options, example: /config x86 xmm on")
    for cX in sConfig.keys():
        if cX == "emu":
            continue # Skip for now
        for cK, cV in sConfig[cX].items():
            print(f"{cX}/{cK} = {cV}")

def parseCmd(cmd, mu):
    global asmLines
    if cmd[0] == "/":
        cmdTok = cmd.split()
        cmdTokLen = len(cmdTok)
        if cmdTok[0] in quitcmds:
            sys.exit()
        if cmdTok[0] in helpcmds:
            print(helpfile)
            return CmdContinue
        if cmdTok[0] == "/back":
            backn = int(cmdTok[1])
            if backn <= len(asmLines):
                asmLines = asmLines[:-backn]
                print(f"Moved back {backn} lines to line {len(asmLines)}")
            else:
                print(f"Too far back! You're currently on line {len(asmLines)}")
            return CmdContinue
        if cmdTok[0] == "/save":
            if cmdTokLen > 1:
                saveOutput(asmLines,cmdTok[1])
            else:
                print("Please specify a filename!")
            return CmdContinue
        if cmdTok[0] == "/load":
            if cmdTokLen > 1:
                asmLines = loadAsm(cmdTok[1])
                addr = baseaddr
            else:
                print("Please specify a filename!")
            return CmdContinue
        if cmdTok[0] in configcmds:
            if cmdTokLen > 3:
                cCategory = cmdTok[1]
                cParam  = cmdTok[2]
                cOption = cmdTok[3]
                if cOption == "on":
                    sConfig[cCategory][cParam] = True
                elif cOption == "off":
                    sConfig[cCategory][cParam] = False
                print(f"Set {cCategory}/{cParam} to {cOption}")
            else:
                configPrint()
            return CmdContinue
        if cmdTok[0] == "/run":
            return ""
        if cmdTok[0] in listcmds:
            printListing(asmLines,baseaddr)
            return CmdContinue
        if cmdTok[0] == "/read":
            if cmdTokLen == 3:
                try:
                    memout = mu.mem_read(int(cmdTok[1],16), int(cmdTok[2]))
                    dHex(memout, int(cmdTok[1],16))
                except Exception as e:
                    print(e)
            else:
                print("Usage: /read 0xaddress size")
            return CmdContinue
    return cmd

if __name__ == '__main__':
    mu_obj = Uc(UC_ARCH_X86, UC_MODE_64) # Initial emulator context
    print(splash)
    while True:
        try:
            cmd = input(f"[\x1b[38;5;231mx64\x1b[0m]\x1b[38;5;197m{addr:02x}\x1b[0m> ")
            cmd = parseCmd(cmd, mu_obj)
            if cmd == CmdContinue:
                continue
            if len(cmd) > 0:
                asmLines.append(cmd)
            if len(asmLines) > 0:
                asmJoined = "; ".join(asmLines)
                asmAssembled = ksAssemble(asmJoined)
                if asmAssembled is not None:
                    mu_obj = Uc(UC_ARCH_X86, UC_MODE_64) # Reinitialize for now, need a better way to manage the state
                    runUC_x64(asmAssembled, mu_obj)
                    addr = regz["rip"]
                else:
                    print("Type / for the help menu")
                    asmLines.pop()
        except EOFError:
            break
