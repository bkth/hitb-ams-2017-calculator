#!/usr/bin/python

import re
import struct
import dis
import sys

from ctypes import (
    cast, CFUNCTYPE, c_long, sizeof, addressof,
    create_string_buffer, pythonapi
)

code_bin = ""
data_bin = ""

PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC = 0, 1, 2, 4
MAP_FIXED, MAP_ANONYMOUS, MAP_SHARED = 0x10, 0x20, 0x1

JADDR = 0x13370000

CODE_SIZE = 0x1000
DATA_SIZE = 0x1000

mprotect = pythonapi.mprotect
mmap = pythonapi.mmap

def banner():
    banner_txt = """
          _____________________
         |  _________________  |
         | |           1337. | |
         | |_________________| |
         |  ___ ___ ___   ___  |
         | | 7 | 8 | 9 | | + | |
         | |___|___|___| |___| |
         | | 4 | 5 | 6 | | - | |
         | |___|___|___| |___| |
         | | 1 | 2 | 3 | | x | |
         | |___|___|___| |___| |
         | | . | 0 | = | | / | |
         | |___|___|___| |___| |
         |_____________________|

 < HITB INSTRUMENTS ADVANCED CALCULATOR >

    """

    print banner_txt

def fatal(s):
    print "ERROR: " + s
    exit(-1)

def p32(v):
    return struct.pack("<L", v)

def pads(v, l, c):
    if len(v) % l == 0:
        return v

    return v + (c * (l - (len(v) % l)))

def code_append(v):
    global code_bin
    if len(code_bin) < CODE_SIZE:
        code_bin += p32(v)
    else:
        print 'code not appending anymore'

def data_append(v):
    global data_bin
    #print 'data appending ', hex(v), ' will return ', ''.join(c.encode('hex') for c in u32(v))

    if len(data_bin) < DATA_SIZE:
        data_bin += p32(v)
    else:
        print 'data not appending anymore'

def make_load(reg, data_offs):
    load_offs = data_offs - 8
    load_offs = load_offs + len(data_bin)
    load_offs = load_offs - len(code_bin)
    ret =  0xe59f0000 | (reg << 12) | load_offs
    return ret

banner()

sys.stdout.write("INPUT  > ")
sys.stdout.flush()
inp = sys.stdin.readline()
inp = re.sub('\s+', ' ', inp).strip()

tokens = inp.split(' ')

if not tokens[0].isdigit():
    fatal("expected numeric constant, got '%s'" % (tokens[0]))

code_append(make_load(0, CODE_SIZE))
data_append(int(tokens[0], 0))
data_append(0xffffffff)

tokens = tokens[1:]

if (len(tokens) % 2) != 0:
    fatal("invalid number of tokens remaining (%d)" % (len(tokens)))

ops_opcode = {
    '+': 0xe0800001,
    '-': 0xe0400001,
    '*': 0xe0000091,
    '|': 0xe1800001,
    '&': 0xe0000001,
}

print 'token len %d', len(tokens)

for i in xrange(0, len(tokens), 2):
    op = tokens[i]
    num = tokens[i+1]
    print i,
    if not num.isdigit():
        fatal("expected numeric constant, got '%s'" % (num))

    if op not in ops_opcode.keys():
        fatal("expected valid operator, got '%s'" % (op))

    if i > 1000:
        print len(code_bin)

    code_append(make_load(1, CODE_SIZE))
    code_append(ops_opcode[op])
    data_append(int(num, 0))
    data_append(0xffffffff)

code_append(0xe12fff1e)

full_bin = (
    pads(code_bin, CODE_SIZE, "\xff") +
    pads(data_bin, DATA_SIZE, "\xff")
)

pagesize = pythonapi.getpagesize()
cbuffer = create_string_buffer(full_bin)
addr = addressof(cbuffer)
size = sizeof(cbuffer)
mask = pagesize - 1

map_prot = PROT_READ | PROT_WRITE | PROT_EXEC
map_flags = MAP_FIXED | MAP_ANONYMOUS | MAP_SHARED
print 'calling mmap'
if mmap(JADDR, CODE_SIZE + DATA_SIZE + 0x1000, map_prot, map_flags, 0, 0) < 0:
    fatal("mmap failed!")

print 'calling mmap done'
print 'addr is', hex(addr)
pythonapi.memcpy(JADDR, addr, CODE_SIZE + DATA_SIZE)
raw_input('break')
pythonapi.syscall(0xf0002, JADDR, JADDR + CODE_SIZE + DATA_SIZE, 0)
print 'done syscall'
print ''.join(c.encode('hex') for c in code_bin) 
fptr = cast(JADDR, CFUNCTYPE(c_long))
print "RESULT > " + repr(fptr())
