---
title: DamCTF 2020 - guess (pwn)
date: 2020-10-12
slug: /writeups/damctf-2020-guess
excerpt: This is my writeup for the challenge "guess" in the pwn category from OSUSEC's DamCTF 2020.
author: Darin Mao
---

This is my writeup for the challenge `guess` in the pwn category from OSUSEC's DamCTF 2020.

<!-- end -->

# Problem Description
You've proven yourself a master of DamCTF. Now put your newly learned skills to work by guessing the flag in its entirety!

`nc chals.damctf.xyz 32766`

## Files
- [guess](https://damctf-rctf-oacl.storage.googleapis.com/uploads/d404b74981663828dbf5725d01a633b18e1d6c935d75047675dae3d115addcab/guess)
- [libc.so.6](https://damctf-rctf-oacl.storage.googleapis.com/uploads/f0ad9639b2530741046e06c96270b25da2339b6c15a7ae46de8fb021b3c4f529/libc.so.6)

# Solution
Connecting to the challenge server presents us with a prompt:
```
If you're so good at CTF, why don't you just guess the flag?
I'll give you ten tries.
```
This appears to be a standard guess-the-flag challenge with no extra tricks. I suppose after so many unexpectedly guessy challenges, the organizers of DamCTF decided to just be straight up about it.

So how do we guess the flag? First we note that the flag likely includes something about guessing, and that we would never guess the flag in a million years. The reasoning for this is that the phrase "never in a million years" is quite a common English phrase, and is also approximately the length of a flag.

This still produces a rather short flag, though. After some thought, we prepend some laughing to extend the length of the flag to a more appropriate size (69 bytes). Lastly, since flags commonly replace letters with similar-appearing numbers in what is referred to as "leetspeak", we do this as well.

With all this in mind, we guess the following:
```
If you're so good at CTF, why don't you just guess the flag?
I'll give you ten tries.
dam{bwHAHAhAH@ha-yOu'l1-N3veR-9UeS$-th15-NOt_1n_4-mi11i0n_YeaR5!!1!}
Correct!
```

Doing this gives us a shell, and we can look at the files in the current directory.
```
ls -laF
total 24
drwxr-xr-x 1 root root 4096 Oct 11 20:06 ./
drwxr-xr-x 1 root root 4096 Oct 11 20:06 ../
-rw-rw-r-- 1 root root   69 Oct 11 20:04 flag
-rwxr-xr-x 1 root root 8936 Oct 11 20:05 guess*
```

We can see that there is a file with a size of 69 called flag that likely contains our flag. Reading this file gives the flag.

```
find / -name "flag" -exec cat {} \; 2>/dev/null
dam{bwHAHAhAH@ha-yOu'l1-N3veR-9UeS$-th15-NOt_1n_4-mi11i0n_YeaR5!!1!}
```

# Flag
```
dam{bwHAHAhAH@ha-yOu'l1-N3veR-9UeS$-th15-NOt_1n_4-mi11i0n_YeaR5!!1!}
```

# Final Remarks
This was a pretty good challenge, and it really put my guessing ability to the test. I have only two complaints:

1. 10 attempts is far too many - for experienced guessers like me, 1 attempt was more than enough.
2. The flag should have been 1 byte longer so that we would not have to add the newline at the end to get to 69 bytes.
