---
title: picoCTF 2021 - Stonk Market (pwn)
date: 2021-03-31
slug: /writeups/picoctf-2021-stonk-market
excerpt: Tricky format string exploitation
author: Darin Mao
---

Stonk Market was a binary exploitation challenge from picoCTF 2021. Despite the relatively low point value (180 points), it was actually quite tricky.

# Description
> I've learned my lesson, no more reading my API key into memory. Now there's no useful information you can leak! `nc mercury.picoctf.net 12784`

Files:
- [vuln](https://mercury.picoctf.net/static/845f9026b3ed714a87fdf98fb9c79203/vuln)
- [vuln.c](https://mercury.picoctf.net/static/845f9026b3ed714a87fdf98fb9c79203/vuln.c)
- [Makefile](https://mercury.picoctf.net/static/845f9026b3ed714a87fdf98fb9c79203/Makefile)

# Analysis
Since source is provided, reverse engineering is straightforward. We are allowed to buy stonks or view our portfolio. The latter option simply prints some information and exits immediately, so it is not interesting to us. However, in the `buy_stonks` function, 300 bytes are read into a buffer on the heap and passed as the first argument to `printf`:

```c
char *user_buf = malloc(300 + 1);
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```

Since we have full control of the format string, this is a trivial format string vulnerability. The rest of the code is just for flavor and does nothing useful, and unfortunately does not contain any more vulnerabilities.

```
[*] '/home/darin/ctfs/picoCTF/pwn/stonk/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The binary is compiled with no PIE, which will be useful later.

# Restrictions
This challenge differs from a typical introductory format string challenge because it reads user input into a *heap* buffer rather than a *stack* buffer. This is significant because it means we can not directly control arguments to `printf`—recall that for x86_64, arguments after the first six are passed on the stack. If our input was on the stack instead, we could write some pointers to use with the `%n` format specifier to gain arbitrary write.

Therefore, if we would like to write to memory, we are constrained to only pointers that are already on the stack. Since function locals are stored on the stack, and function stack frames move up the stack, we can use local pointers for functions that were called before `buy_stonks` as well as `buy_stonks` itself. This leaves us with few options—the only function called before `buy_stonks` is `main`, so we have access to these variables:

`buy_stonks`:
- `int money`
- `int shares`
- `Stonk *temp`
- `char *user_buf`

`main`:
- `Portfolio *p`
- `int resp`

Another difficulty this challenge presents is the fact that we only get one call to `printf`. This rules out a lot of more typical format string attacks because they require at least two steps—one to leak an address and another to do a write. Fortunately, since the binary itself calls `system("date")` and is not compiled with PIE, we have access to `system@plt`.

One may be tempted to try the technique used in [hxp CTF 2020 "still-printf"](https://ctftime.org/task/14382), where a stack pointer is partially overwritten to point to the stack location of a return address (with a 1/4096 chance of success), after which the return address could be overwritten. Unfortunately, this technique relies heavily on environment and is therefore impossible in this case (hxp CTF provided the entire deploy setup including Dockerfile so it could be debugged locally). The technique to use a stack pointer to overwrite an address on the stack is, however, useful to us.

# Attack Plan
Notice that in `free_portfolio`, many pointers are freed:

```c
void free_portfolio(Portfolio *p) {
    Stonk *current = p->head;
    Stonk *next = NULL;
    while (current) {
        next = current->next;
        free(current);
        current = next;
    }
    free(p);
}
```

Also recall that we have access to these pointers on the stack! At the call to `printf`, `Stonk *temp` in `buy_stonks` points to the last stonk generated, and `Portfolio *p` in `main` points to the portfolio. Since `printf` can write at most 4 bytes to these locations, we could write `sh\0` to the beginning of any of these memory locations. Then, all we would need to do is somehow make `free` call `system` instead.

Since the binary uses partial RELRO, we just need to find a way to overwrite the GOT. We already know the target location (`free@got`) and the value we want to write (`system@plt`), and since there is no PIE these addresses are all 3 bytes only (if the binary had PIE then they would be 6 bytes instead, making it impossible to write an entire address with `printf`). The issue is that there are obviously no pointers to `free@got` on the stack, so we will have to create one.

picoCTF is unique because it provides competitors with a web shell with high-speed access to the challenge servers. This means that some techniques that would be impossible in other CTFs because they require printing large amounts of data are actually feasible in this case. Recall that the `%n` format specifier writes the number of bytes printed so far to a memory location, so in order to write an entire 4 byte value we need to print that many characters, which could be many megabytes for addresses. If we just run our solve script on the web shell, then this is not out of the question.

The stack contains many pointers to the stack. We can take advantage of this to write a value of our choice to the stack, then use that address to do an arbitrary write. I chose to use the saved `rbp`, because it is at a consistent offset regardless of environment and always points to a small value on the stack, so we can overwrite it entirely with `printf`.

A quick side note: on my computer (Ubuntu 20.04 with glibc 2.31), the saved `rbp` points to a `NULL`. However, by leaking the return address of `__libc_start_main` and using the [libc database](https://libc.blukat.me/), we find that the server is running glibc 2.27. Downloading this version of libc and the corresponding ld reveals that the saved `rbp` actually points to `__libc_csu_init`. In either case, the value is less than 4 bytes long so we can still overwrite the entire thing with `%n`.

# Exploit

With some careful counting and trial and error, we can find the argument numbers for the values we care about:

- saved `rbp` is 12
- location that saved `rbp` points to is 20
- `Portfolio *p` is 18

Note that upon encountering the first format specifier with a `$` specifying argument position, `printf` will go through the format string and save every argument. This means that if we use a `$` while writing our target address to the stack, then `printf` will save the old value and it will have no effect. Therefore, we can not use `$` until this address is written.

We'll start our format string with:

```
%c%c%c%c%c%c%c%c%c%c%6299662c%n
```

This will write a total of `0x602018` (`free@got`) bytes, then write this value to the memory location pointed to by the 12th argument, which is the saved `rbp`. Now, the 20th argument points to `free@got`. We continue with:

```
%216c%20$hhn
```

This prints 216 more characters for a total of `0x6020f0`, then writes a single byte (`hhn`) to the memory location pointed to by the 20th argument, which is the `free@got` pointer we wrote previously. Note that since `free` has not yet been called, its GOT pointer still points to the PLT. Thus, it is sufficient to only write the lowest byte `0xf0`. Before this write, the value of the pointer is `0x4006c6`, and after it is `0x4006f0`, which is the address of `system@plt`.

We finish with:

```
%10504067c%18$n
```

This prints even more characters for a total of `0x01006873`. Interpreted as a string, this is `sh\0\1`. We write this to the memory location pointed to by the 18th argument, which is the portfolio.

Putting it all together, this is the final format string:

```
%c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%18$n
```

If we send this as our API token, then wait a few seconds for all of the padding spaces to be printed, we'll get a shell.

# Flag
```
picoCTF{explo1t_m1t1gashuns_7838034c}
```
