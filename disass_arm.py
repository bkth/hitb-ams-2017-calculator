from capstone import *

md = Cs(CS_ARCH_ARM, CS_MODE_ARM)

def print_disass(c):
    for i in md.disasm(c, 0x0):
        print hex(i.address), i.mnemonic, i.op_str

print_disass("\xf8\x0f\x9f\xe5") #first dword
print_disass("\xfc\x1f\x9f\xe5") #load 1
print_disass("\x01\x00\x80\xe0") # +
print_disass("\x01\x00\x40\xe0") # -
print_disass("\x91\x00\x00\xe0") # *
print_disass("\x01\x00\x80\xe1") # |
print_disass("\x01\x00\x00\xe0") # &
print_disass("\x1e\xff\x2f\xe1") # last dword

