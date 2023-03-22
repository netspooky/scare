#!/usr/bin/python
from __future__ import print_function
import time
import sys
import readline
import argparse
from scarelib import *

parser = argparse.ArgumentParser(description="")
parser.add_argument('-a', dest='arch', help='Target architecture')
parser.add_argument('-f', dest='inFile', help='File to read')
parser.add_argument('--base', type=lambda x: int(x,0), dest='baseaddr', help='Base Address (default: 0x400000)')
parser.add_argument('--stack', type=lambda x: int(x,0), dest='stackaddr', help='Stack Address (default: 0x401000)')
parser.add_argument('--memsize', dest='memsize', help='Emulator Memory Size (default: 0x200000 [2MB])')

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
    shouldAssemble = 1
    if len(cmd) > 0:
      if cmd[0] == "/":
        shouldAssemble = 0
        cmdList = cmd.split()
        cmdListLen = len(cmdList)

        if cmdList[0] in cmdQuit:
            sys.exit()

        if cmdList[0] in cmdHelp:
            print(helpfile)

        if cmdList[0] in cmdConf:
            if cmdListLen == 3:
                try:
                    cfgOptName = cmdList[1]
                    cfgOptVal = cmdList[2]
                    if cfgOptName in sConfig.keys():
                        print(f"{cfgOptName}->{cfgOptVal}")
                        # TODO: Keep better track of config option types
                        if cfgOptName == "emu/arch":
                            if cfgOptVal in archez.keys():
                                sConfig[cfgOptName] = cfgOptVal
                            else:
                                print(f"Invalid arch! Supported arches: {archez.keys()}")
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
                configPrint(sConfig)

        if cmdList[0] == "/info":
            if smu:
                smu.info()
            else:
                print("No emulator running!")

        if cmdList[0] == "/regs":
            if smu:
                smu.printRegs()
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
                smu.asm_code = loadAsm(cmdList[1])
                currentAddr = sConfig["emu/baseaddr"]
            else:
                print("Please specify a filename!")

        if cmdList[0] == "/save":
            if cmdListLen > 1:
                saveAsm(smu.asm_code,cmdList[1])
            else:
                print("Please specify a filename!")

        if cmdList[0] == "/run":
            shouldAssemble = 2 # Reassemble and run

        if cmdList[0] == "/reset":
            shouldAssemble = 3 # Reinitialize 

        if cmdList[0] in cmdPList:
            printListing(smu, smu.asm_code)

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
                        dHex(memout, int(cmdList[2],16))
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
                            printListing(smu, instructions4dis)
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
                            exportBin(smu.machine_code, "bin", fArch, cmdList[2])
                        else:
                            print("No machine code to export!")
                    elif cmdList[1] == "elf64":
                        mcLen = len(smu.machine_code)
                        if mcLen > 0:
                            print(f"Exporting {mcLen} bytes of code as ELF64")
                            exportBin(smu.machine_code, "elf64", fArch, cmdList[2])
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
    printSplash("cerulean")
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
        print(f"Please select an architecture! Use `/c emu/arch ARCH`.\nSupported arches: {archez.keys()}")
        smu = False
        currentAddr = sConfig["emu/baseaddr"]
    else:
        sConfig["emu/arch"] = currentArch
        smu = scaremu(currentArch)
        currentAddr = sConfig["emu/baseaddr"]
        if inFile:
            smu.asm_code = loadAsm(inFile)
    while True:
        try:
            cmd = input(f"[{cArchP}{currentArch}]{cIP}{currentAddr:02x}{cEnd}> ")
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
