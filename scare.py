#!/usr/bin/python

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from keystone import *
import capstone
import time
import sys
import readline
import argparse
import scarelib

parser = argparse.ArgumentParser(description="")
parser.add_argument('-a', dest='arch', help='Target architecture')
parser.add_argument('-f', dest='inFile', help='File to read')
parser.add_argument('--base', type=lambda x: int(x,0), dest='baseaddr', help='Base Address (default: 0x400000)')
parser.add_argument('--stack', type=lambda x: int(x,0), dest='stackaddr', help='Stack Address (default: 0x401000)')
parser.add_argument('--memsize', dest='memsize', help='Emulator Memory Size (default: 0x200000 [2MB])')

supportedArches = ["arm64", "x64"]

sConfig = {
    "emu/baseaddr" : 0x400000,
    "emu/stackaddr": 0x401000,
    "emu/memsize":   0x200000,
    "emu/arch" : "NoArch",
    "x86/xmm": 0,
}

class scaremu:
    def __init__(self, mu_arch):
        self.arch = 255
        self.mode = 255
        self.stack_reg = 255
        self.arch_name = mu_arch.lower()
        if self.arch_name == "x64":
            self.arch = UC_ARCH_X86
            self.mode = UC_MODE_64
            self.stack_reg = UC_X86_REG_RSP
            self.ip_reg = UC_X86_REG_RIP
        elif self.arch_name == "arm64":
            self.arch = UC_ARCH_ARM64
            self.mode = UC_MODE_ARM
            self.stack_reg = UC_ARM64_REG_SP
            self.ip_reg = UC_ARM64_REG_PC
        else:
            print("Unsupported Arch")
            return
        self.base_addr = sConfig["emu/baseaddr"]
        self.stack_addr = sConfig["emu/stackaddr"]
        self.asm_code = [] # Holds the source code
        self.machine_code = b"" # The machine code
        self.mu_ctx = Uc(self.arch, self.mode)# This is the emulator object
        self.mu_state = "INIT" # The states are INIT, RUN, ERR
        self.mu_memsize = sConfig["emu/memsize"]
    def asm(self,asm_code):
        try:
            if self.arch_name == "x64":
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
            elif self.arch_name == "arm64":
                ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            else:
                print("Invalid Arch!")
            self.asm_code = asm_code
            asmJoined = "; ".join(self.asm_code)
            mc, num = ks.asm(asmJoined)
            self.machine_code = bytes(mc)
            return 0
        except KsError as e:
            print(f"[[: Asm Error :]] {e}")
            return 1
    def run(self):
        runStatus = 1
        try:
            if self.mu_state == "RUN":
                self.mu_ctx.emu_stop()
                self.mu_state = "INIT" # Switch back to initialized
            if self.mu_state == "INIT":
                self.mu_ctx = Uc(self.arch, self.mode)
                self.mu_ctx.mem_map(self.base_addr, self.mu_memsize)
                self.mu_ctx.mem_write(self.base_addr, self.machine_code) # map the code
                self.mu_ctx.reg_write(self.stack_reg, self.stack_addr) # Initialize Stack
                eStart = self.mu_ctx.emu_start(self.base_addr, self.base_addr + len(self.machine_code)) # start emulator
                self.mu_state = "RUN"
                return self.mu_ctx.reg_read(self.ip_reg), 0
        except UcError as e:
            print("\x1b[48;5;196mERROR:\x1b[0m %s" % e)
            return self.mu_ctx.reg_read(self.ip_reg), 1
    def stop(self):
        self.mu_ctx.emu_stop()
        self.mu_state = "INIT" # Switch back to initialized
    def printRegs(self):
        scarelib.printRegsHandler(self.mu_ctx, self.arch_name, sConfig)
        return
    def readReg(self, regname):
        try:
            reg_val = scarelib.rNames[self.arch_name][regname]
            if reg_val:
                reg_out = self.mu_ctx.reg_read(reg_val)
                return reg_out
        except:
            print("Invalid Register")
    def readMem(self, memaddr, size):
        memout = self.mu_ctx.mem_read(memaddr, size)
        scarelib.dHex(memout, memaddr)
    def info(self):
        print(f"┌ \x1b[38;5;220m   arch_name:\x1b[0m {self.arch_name}")
        print(f"│ \x1b[38;5;220m   base_addr:\x1b[0m {self.base_addr:08x}")
        print(f"│ \x1b[38;5;220m  stack_addr:\x1b[0m {self.stack_addr:08x}")
        print(f"│ \x1b[38;5;220m    mem_size:\x1b[0m {self.mu_memsize:08x}")
        print(f"│ \x1b[38;5;220m    asm_code:\x1b[0m {self.asm_code}")
        print(f"│ \x1b[38;5;220mmachine_code:\x1b[0m {self.machine_code.hex()}")
        print(f"└ \x1b[38;5;220m    mu_state:\x1b[0m {self.mu_state}")
    def dis(self, memaddr, size):
        if self.arch_name == "x64":
            csArch = capstone.CS_ARCH_X86
            csMode = capstone.CS_MODE_64
        elif self.arch_name == "arm64":
            csArch = capstone.CS_ARCH_ARM64
            csMode = capstone.CS_MODE_ARM
        else:
            print("Unsupported arch!")
            return
        instructionList = []
        try:
            scareDis = capstone.Cs(csArch, csMode)
            memout = self.mu_ctx.mem_read(memaddr, size)
            for insn in scareDis.disasm(memout, memaddr):
                instructionList.append(f"{insn.mnemonic} {insn.op_str}")
            return instructionList
        except Exception as e:
            print(e)
            return instructionList

## Commands
cmdQuit = ["/exit", "/x", "/quit", "/q"]
cmdHelp = ["/", "/help", "/?", "/h"]
cmdConf = ["/config", "/c"]
cmdPList= ["/list", "/l"]

# parseCmd
# Commands must start with / to be parsed
# If 0 is returned, the main command loop will not try to assemble the input
# If 1 is returned, then the main command loop should try to assemble the input
# If 2 is returned, the main command loop should not append the current command and just assemble and run
# If 3 is returned, reinitialize the scaremu
def parseCmd(cmd, smu):
    shouldAssemble = 1 # If 1 is returned, then the 
    if len(cmd) > 0:
      if cmd[0] == "/":
        shouldAssemble = 0
        cmdList = cmd.split()
        cmdListLen = len(cmdList)

        if cmdList[0] in cmdQuit:
            sys.exit()

        if cmdList[0] in cmdHelp:
            print(scarelib.helpfile)

        if cmdList[0] in cmdConf:
            if cmdListLen == 3:
                try:
                    cfgOptName = cmdList[1]
                    cfgOptVal = cmdList[2]
                    if cfgOptName in sConfig.keys():
                        print(f"{cfgOptName}->{cfgOptVal}")
                        # TODO: Keep better track of config option types
                        if cfgOptName == "emu/arch":
                            if cfgOptVal in supportedArches:
                                sConfig[cfgOptName] = cfgOptVal
                            else:
                                print(f"Invalid arch! Supported arches: {supportedArches}")
                        else:
                            sConfig[cfgOptName] = int(cfgOptVal, 16) # Only support hex rn
                    else:
                        print("Invalid config opt name!")
                except:
                    print("Error in /config")
            elif cmdListLen == 2:
                try:
                    cfgOptName = cmdList[1]
                    if cfgOptName in sConfig.keys():
                        print(f"{cfgOptName} = {sConfig[cfgOptName]}")
                except:
                    print("Error in /config")
            else:
                scarelib.configPrint(sConfig)

        if cmdList[0] == "/info":
            if smu:
                smu.info()
            else:
                print("No emulator running!")

        if cmdList[0] == "/back":
            backAmount = int(cmdList[1])
            if backAmount <= len(smu.asm_code):
                smu.asm_code = smu.asm_code[:-backAmount]
                print(f"Moved back {backAmount} lines to line {len(smu.asm_code)}")
                shouldAssemble = 2 # Reassemble and run
            else:
                print(f"Too far back! You're currently on line {len(smu.asm_code)}")

        if cmdList[0] == "/load":
            if cmdListLen > 1:
                smu.asm_code = scarelib.loadAsm(cmdList[1])
                currentAddr = sConfig["emu/baseaddr"]
            else:
                print("Please specify a filename!")

        if cmdList[0] == "/save":
            if cmdListLen > 1:
                scarelib.saveAsm(smu.asm_code,cmdList[1])
            else:
                print("Please specify a filename!")

        if cmdList[0] == "/run":
            shouldAssemble = 2 # Reassemble and run

        if cmdList[0] == "/reset":
            shouldAssemble = 3 # Reinitialize 

        if cmdList[0] in cmdPList:
            scarelib.printListing(smu.arch_name, smu.asm_code,sConfig["emu/baseaddr"])

        if cmdList[0] == "/read":
            if cmdListLen == 3:
                try:
                    memout = 0
                    if cmdList[1][0:2] == "0x":
                        memout = smu.mu_ctx.mem_read(int(cmdList[1],16), int(cmdList[2]))
                    elif cmdList[1][0] == "$":
                        regTarget = cmdList[1].split("$")[1]
                        regValue = smu.readReg(regTarget)
                        if regValue is not None:
                            memout = smu.mu_ctx.mem_read(regValue, int(cmdList[2]))
                    if memout:
                        scarelib.dHex(memout, int(cmdList[2],16))
                    else:
                        print("Usage: /read {0xaddress|$register} size")
                except Exception as e:
                    print(e)
                    print("Usage: /read {0xaddress|$register} size")
            else:
                print("Usage: /read {0xaddress|$register} size")

        if cmdList[0] == "/dis":
            try:
                if cmdListLen == 3:
                    if cmdList[1][0:2] == "0x":
                        smu.dis(int(cmdList[1],16), int(cmdList[2]))
                    elif cmdList[1][0] == "$":
                        regTarget = cmdList[1].split("$")[1]
                        regValue = smu.readReg(regTarget)
                        if regValue is not None:
                            instructions4dis = smu.dis(regValue, int(cmdList[2]))
                            scarelib.printListing(smu.arch_name, instructions4dis, regValue)
                    else:
                        print("Usage: /dis {0xaddress|$register} size")
                else:
                    print("Usage: /dis {0xaddress|$register} size")
            except Exception as e:
                print(e)
                print("Usage: /dis {0xaddress|$register} size")

        if cmdList[0] == "/export":
            try:
                if cmdListLen == 3:
                    fArch = smu.arch_name
                    if cmdList[1] == "bin":
                        mcLen = len(smu.machine_code)
                        if mcLen > 0:
                            print(f"Exporting {mcLen} bytes of code as raw binary")
                            scarelib.exportBin(smu.machine_code, "bin", fArch, cmdList[2])
                        else:
                            print("No machine code to export!")
                    elif cmdList[1] == "elf64":
                        mcLen = len(smu.machine_code)
                        if mcLen > 0:
                            print(f"Exporting {mcLen} bytes of code as ELF64")
                            scarelib.exportBin(smu.machine_code, "elf64", fArch, cmdList[2])
                        else:
                            print("No machine code to export!")
                    else:
                        print("Invalid binary type!")
                else:
                    print("Usage: /export type filename")
            except Exception as e:
                print(f"Export Error: {e}")
    else:
        shouldAssemble = 0 # Don't do anything if there's no input

    return shouldAssemble

if __name__ == '__main__':
    print(scarelib.splash)
    args = parser.parse_args()
    print("Type / for help\n")
    inFile = args.inFile if args.inFile else ""
    currentArch = args.arch.lower() if args.arch else "NoArch"
    if args.stackaddr:
        sConfig["emu/stackaddr"] = args.stackaddr
    if args.baseaddr:
        sConfig["emu/baseaddr"] = args.baseaddr
    if args.memsize:
        sConfig["emu/memsize"] = args.memsize   
    if currentArch == "NoArch":
        print(f"Please select an architecture! Use `/c emu/arch ARCH`.\nSupported arches: {supportedArches}")
        smu = False
        currentAddr = sConfig["emu/baseaddr"]
    else:
        sConfig["emu/arch"] = currentArch
        smu = scaremu(currentArch)
        currentAddr = sConfig["emu/baseaddr"]
        if inFile:
            smu.asm_code = scarelib.loadAsm(inFile)
    while True:
        try:
            cmd = input(f"[\x1b[38;5;231m{currentArch}]{scarelib.cIP}{currentAddr:02x}\x1b[0m> ")
            shouldAsm = parseCmd(cmd, smu)
            if ( smu == False ) and (sConfig["emu/arch"] != "NoArch"): 
                smu = scaremu(sConfig["emu/arch"])
                currentArch = sConfig["emu/arch"]
                currentAddr = sConfig["emu/baseaddr"]
            if sConfig["emu/arch"] != currentArch:
                smu = scaremu(sConfig["emu/arch"])
                currentArch = sConfig["emu/arch"]
                currentAddr = sConfig["emu/baseaddr"]
            if shouldAsm == 3:
                smu = scaremu(sConfig["emu/arch"])
                currentArch = sConfig["emu/arch"]
                currentAddr = sConfig["emu/baseaddr"]
            if shouldAsm:
                if shouldAsm == 1:
                    smu.asm_code.append(cmd)
                if len(smu.asm_code) > 0:
                    asmStatus = smu.asm(smu.asm_code)
                    if asmStatus == 0:
                        currentAddr, runStatus = smu.run()
                        if runStatus == 0:
                            smu.printRegs()
                        else:
                            print("run() returned a non-zero value")
                    else:
                        smu.asm_code.pop() # Gets rid of the last line of assembly
                else:
                    currentAddr = sConfig["emu/baseaddr"]
        except EOFError:
            break
