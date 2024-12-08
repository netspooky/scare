sConfig = {
    "emu/baseaddr" : 0x400000,
    "emu/stackaddr": 0x401000,
    "emu/memsize":   0x200000,
    "emu/arch" : "NoArch",
    "x86/xmm": 0,
    "ppc/fpr": 0,
}

#### Colors

# General Colors
cEnd  = "\x1b[0m"        # For the end of lines
cErr  = "\x1b[48;5;196m\x1b[38;5;231m" # Error Highlight
cInfo = "\x1b[38;5;220m" # For the /info command

# Register Print colors
cGReg = "\x1b[38;5;154m" # General Purpose Register Value Color
cZero = "\x1b[38;5;244m" # Grey for 0's
cRegN = "\x1b[38;5;50m"  # Color for register names
cSPtr = "\x1b[38;5;226m" # Stack Pointer Color
cIP   = "\x1b[38;5;219m" # Instruction Pointer color

# Listing Colors (for /l command)
cLnNum   = "\x1b[48;5;55m" # Line number
cLnPipe  = "\x1b[38;5;196m" # Line number divider
cAsmList = "\x1b[38;5;51m" # Color of the assembly code
cComment = "\x1b[38;5;244m" # For comments
cBytes   = "\x1b[38;5;227m" # For bytes at the end of the comment

# Logo Styling
cLogo1 = "\x1b[38;5;213m"
cLogo2 = "\x1b[38;5;219m"
cLogo3 = "\x1b[38;5;225m"
cLogo4 = "\x1b[38;5;231m"

# Prompt Styling
cArchP = "\x1b[38;5;231m" # For the arch name

