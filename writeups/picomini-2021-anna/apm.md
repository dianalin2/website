---
title: picoMini by redpwn 2021 - advanced-potion-making (forensics)
date: 2021-05-11
slug: /writeups/picomini-redpwn-apm
excerpt: Fixing a corrupt PNG file
author: Anna Hsu
---
# Description
> Ron just found his own copy of advanced potion making, but its been corrupted by some kind of spell. Help him recover it!

# Solution
Ah, forensics. The challenge-provided `advanced-potion-making` has no file extension, but it's probably a good bet to say it's a corrupted PNG file. `file advanced-potion-making` returned `advanced-potion-making: data` (unlikely to work, but it's worth a shot and certainly "obligatory" for forensics challenges).

If a file is corrupted, it can be fixed with a hex editor such as [HexEd.it](https://hexed.it/). For a PNG file to be valid, it requires a PNG file signature and critical chunks of data. In the hex editor, we can change the incorrect parts of the chunks.

![a glimpse of the contents of the corrupted file](./hexedit.png)

After address `0x0000009E`, most of the content is repeated and not going to be critical (save the IEND), so the bulk of our work is going to be higher up.

The PNG file header is supposed to be the first part of every PNG file and it indicates that it is a PNG file, and not anything else. It consumes the first 8 addresses with `89 50 4E 47 0D 0A 1A 0A`. The corrupted file looks somewhat similar, but not quite, so I manually fix it to agree.

We need to check the [four most important chunks](https://www.w3.org/TR/PNG-Chunks.html) to make sure they're correct: IHDR, PLTE (which ends up being optional), IDAT, and IEND. Since each PNG needs these and I didn't know their values off the top of my head, I opened a valid PNG side-by-side in the hex editor and compared their hex values. The IDHR, IDAT, and IEND looked correct.

I thought I was done and I saved my image here, but it wouldn't open. Going back to my comparison between a random valid PNG and my corrupted file, I realized that the hex values of addresses `0x00000009` to `0x0000000B` were incorrect. After changing them to `00 00 0D` to match my valid PNG, I saved it and opened it to see a red image.

So we're not done yet. Ugh.

However, when I see red (or really any solid color), I try using [stegsolve](https://github.com/zardus/ctf-tools/blob/master/stegsolve/install). I flipped through a bunch of options until `Red plane 0`, and we have our flag!

The hardest part of CTF really is reading the flag. For some reason, I thought the `1` was an `l` at first!

![why was this so hard to read aaaaaaaaaaaaaaaaa](./flag.png)

# Flag
```
picoCTF{w1z4rdry}
```