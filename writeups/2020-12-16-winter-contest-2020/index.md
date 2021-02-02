---
title: TJCSC Winter Contest 2020
date: 2020-12-16
slug: /writeups/tjcsc-winter-2020
excerpt: Solutions to selected problems from the 2020 Winter Contest
author: Darin Mao, Saigautam Bonam, and Autin Mitra
---

Solutions to selected problems from the 2020 Winter Contest <!-- end -->

# gwt
> Introducing Ginkoid Web Tokens, the revolutionary new way to authenticate on the web! We have a [demo app](https://gwt-app.winter-challenge.tjcsec.club/) running, and there's a flag for our lord and savior `ginkoid` himself.

- [app.py](https://winter.tjcsec.club/uploads/eb7913c65d410462b61c9200cac6b1f2320276999f91c9baca22ae09066697ab/app.py)

This problem is what happens when I go "hmm, how can I include a bunch of different topics _and_ meme ginkoid at the same time??"

## Inspection

As always, we should start by looking at the site itself. There's a single login button, which takes us to a different site (gwt-sso), where we can make an account. Trying the login again presents us with a very OAuth-like (but not actually OAuth!!) screen, and then we get a simple `Hello, username` message with a token in the query parameters. From the challenge description, it is clear that we need to become `ginkoid`, but attempting to register as `ginkoid` does not work.

![rip ginkoid](./ripgink.png)

The provided source is for the demo app, and is fairly short. It is a simple Flask app with only a single route, but there is some extra code for verifying tokens.

## Analysis of Token Verification

First we can grab a real token to see what it looks like.
```
eyJ1aWQiOiA0LCAidXNlcm5hbWUiOiAia2ZiIiwgImlhdCI6IDE2MDc2MTQ2MTV9~OMG~GINKOID~1jRsPrREEBm63KE4iabgW6VdVjRy6_RwQ--qDf0cVLFdL-Vp3su6oA9IptbpA-y8zVjVw_3cGxoRSpSc6gB-Ihexr0NLtWfDCXMxqFGpUXRWA3nezY75uBbeIGRbafghwFfzfIhRH_XPVpQqMhlIjw6TpN4z72B6aX76zbhdghLeksjkD9lCHQA7SzGYd1t9NyJBRDHG_lwhvn1Z3nZV2KiTeo86chn_9oRngwiaPgiQmeEsYVE1w3m7xZailhe2i1G8yAYXBZXQiiipEnNAD6PujVeE4rZ_KqjIDOJTL-YomkkcQsIXEGZkDV2Z-6Z8kPHliFrFg1ga-fhaP3AXppnx1mRH5dHy3PQSgFbAj-AgcuMJQ3ZuUk-bdndkujC8NLCXhmstIT_9VO_WLQ2Re4ebfS-os4wTobEMPVvT46BqIpAXGFc7J0Ln6Dwr-BbFaX8895eY5JEywWdJ3IPECXjymFkDapqKyUp_pIpfx4icikm6mdZUY-AQdFkyqrXRfwgrxxBQDunUdhk9j1G-uSfZTQgUC1TNwQdLeW-e-_OgWNUOQx535s8BtxHBsh6IF2eGDDV_YyrVedY7iADo9gfTRnJZoFkwCWf8NC0BkimZhz9XdXu-N80fvc3Dt1Hp46u6nBjjo19nXLO9Aqgk_U6N8otLyGRYTAyYrs_eDA==
```

The first thing `verify_token` does is split the token with `~OMG~GINKOID~` then base64 decode each half (`data` and `sig`). We can do this too, and we get the following:

```
{"uid": 4, "username": "kfb", "iat": 1607614615}
```
```
Ö4l>´D..ºÜ¡8.¦à[¥]V4rëôpCïª
...more bytes...
```

So `data` is just JSON, and `sig` is some bytes. Next, the code calls `get_pubkey`, which fetches `https://gwt-sso.winter-challenge.tjcsec.club/pubkey` and base64 decodes some numbers `n` and `e`. We can do the same.

```
>>> get_pubkey()
(9135179405892393137819502430299116616699269395274772199049691222281624589012088857490213845197725855488215246527441649827211053689667418891906309915867653335322113071628691292267867320876045187263626680709571063676436282292076183779952184846896479974731176194412579891889442673903648307243226429751274791099962187541550977837788494879406903764097394966554517265965190807000681173006562499111321579310444330581506380088562706973448459893775343301499529229376413276375157009881503203510051374178178678028260889345152961639470198384912710804382567845691663280804811714850889625690667375956178807268219642637757715226977707863005891992336554952698865230659296184925470522667486559148678255539314624132972122017813720282091569752250653844028344210990764069172870740301702958599679351211097009177846329324537968996425250512676826952995569185759277632827082405992724750467505341265435459742307413118445935304494239244157797538849525866100521697655523799557049337505333953873094996431057902308757647729351095897920446342975867782745606296040480225206450560591706625965387177751881525719348419957656834906060636250130159571182610262267494096687220954570944927137245689210244846298210264297668949889664469606426169546613224133181097835469609, 853139901418066068299423395141948843666184797346024741065429211308035234128334983502047813156629991030602700968303048834081344270130785041114816333990175104793745381147187052776704037443505619327794236007865347372622361632782246386305826184237697070768829669238790111087597981407850705567410386713907128815608169616277408058983225814958304986172951164149256526930406159132663653062159198568012392566521716253017208151139318897617652954199722566449727261521756553318556028476944014176227897899772929817695072368593548122902778486816075651978293654104745729838286145816355016064904925595183484492580370515758098894051260696311660131305197190052556049007832997235969572377732979939261402413581450992460180746981959639896717768202578311866242653058000525443365645461269331459301383707795062648416125503898144292985608448487151875957048718382397149014118667589580620525568218198317911924383521473942283769612878453155158474125070201654653312732975168409310440440615541933602034870793762745229645068146202949685464540994991904461482455917282473126582977968720687214137580660034254370801873931998712579882461520011925133001288253978033516019761669299852065629772084437422376101785650355871003194175367476842571285701707558704545698749609)
```

Next, `sig` is converted to a number and raised to the `e`th power mod `n`. This result is compared to the SHA256 digest of `data`. Thus, the token verification is a simplified, custom implementation of RS256. The encoding is similar to a JWT, but there is no header and instead of a `.` separating each section there is `~OMG~GINKOID~`.

## Token Payload
The `data` returned by `verify_token` is decoded with `get_user`. After JSON decoding, it makes sure the elapsed time from the `iat` field is between 0 and 60. Then, it returns the `uid` and `username` fields, which are sent back to the Flask route handler. Therefore, our goal is to fabricate this token:

```python
data = {
  'uid': 1,               # irrelevant
  'username': 'ginkoid',  # impersonate ginkoid
  'iat': int(time()),     # appropriate timestamp
}
```

## Breaking RSA
The value of `e` is slightly concerning, since it is not much smaller than `n` so the private exponent `d` is probably small. We can apply the Boneh Durfee attack using something like [defund/coppersmith](https://github.com/defund/coppersmith).

```python
bounds = (floor(N^.25), 2^2048)
R = Integers(e)
P.<k, s> = PolynomialRing(R)
f = 2*k*((N+1)//2 - s) + 1
K, S = small_roots(f, bounds)[0]

d = (2*Integer(K)*((N+1)//2 - Integer(S)) + 1) // e
```

This recovers the private key.

## Final Token Construction
Now we have all the pieces to create our own token. Our signature is `pow(sha256(data), d, n)` base64 encoded. I'm using sage here so there's some extra `int()`.

```python
data = {
  'uid': int(1),
  'username': 'ginkoid',
  'iat': int(time()),
}
data = json.dumps(data).encode()
h = hashlib.sha256()
h.update(data)
m = bytes_to_int(h.digest())
sig = power_mod(m, d, N)
sig = int_to_bytes(sig)
token = f'{base64.urlsafe_b64encode(data).decode()}~OMG~GINKOID~{base64.urlsafe_b64encode(sig).decode()}'
```

Here's a valid token, though by the time you read this it will have expired.
```
eyJ1aWQiOiAxLCAidXNlcm5hbWUiOiAiZ2lua29pZCIsICJpYXQiOiAxNjA3NjE3NDA0fQ==~OMG~GINKOID~AjOt6BDbgjqrJjHV0O_7US-pca3mIoGqWIxLO4zk8rqFJ62nKcH2Pie4OjKMUKywo3ZqRp8EgLEqqDkVn1ijKtmmpTjSywXdSz30AZyjvIh9-7Ie9Lc2y2mcgDs2C7IoxFPGRU2dbZ31oRekYd9_tkAM4FpzGQY3wF0uX9RlVzeu7E6V2FjAIXj1pu89FdRsl2HoXAImF4JL8n2d6-2v1B7R27Nr53LuVvg-nt70GWAcjDeWzkJlkaUEKS8FoSkOjucQlEoovKMfcL03BQ9enltVvJlTszFLBDcb7og-iinFI65buPI_cROgeRzTK6CwzAwFNTgU11upYhoi2D0q8_p4_SJWCSN42j3fKhBUh1vQqCpr0GsyfykBD3qfyTMUsneYL7_2SWmO4FIiqSIYz-TP75-gg0kTlsHhqtp4BYVy8rvTOG8A0jKog6FpknccmfrUn4nAqjMeI0DX3POI9aghQIL1_M2md9IvbZpNE3QEGB-JpO4rWC9Cfge-re940GKcht_7phdWX9VFIaloFHPA_DxzJLpKBI9PiBHYQzv5UFsuOffSQXfPZ4_9UKLtgx2uBIRA_GrWTBurQKu2ES7s83JzTdSEOjI1iMqCT3Uw3aLq7n7F7y_owXjk_E35WYlIeSL2x6GoIPBDSao7nkRiCPjEzdfj0qBYF6KhmnE=
```
```
{"uid": 1, "username": "ginkoid", "iat": 1607617404}
```

## Flag
```
flag{w4it_th1s_i5nt_o4uth...h0m3_r0ll3d_ev3ryth1n9_wtmoo}
```

Indeed, it was a simplified, custom implementation of:
- OAuth
- JWT
- RS256

# seegink
> See gink!
>
> `nc winter-challenge.tjcsec.club 30001`

- [libc-2.29.so](https://winter.tjcsec.club/uploads/d7ab015f68cd23c410d57af6552deb54bcb16ff64177c8f2c671902915b75110/libc-2.29.so)
- [seegink](https://winter.tjcsec.club/uploads/1ed68f2d5d16c21f0af4cda79ab9ec74a5ec84142bbef9696a8bea9ed98f2dae/seegink)

When Rob tells me to write baby FSOP for the memes, I do it.

## Inspection
The presence of provided libc is a pretty good indicator that this is a pwn challenge, but we will make sure of this as we go. First we run the program to get a sense of what it does. In order to preserve the beauty of the ANSI ginkoid, I will attach a screenshot rather than the typical copy paste.

![omg ginkoid](./omggink.png)

At some point you may try the number `1` and find that it produces a different ginkoid, but guessing this at this point is not required. `checksec` gives the following:

```
[*] '/home/darin/ctfs/csc-winter-2020/bonus/seegink/seegink'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Thus, we are probably not looking at a basic stack-overflow type challenge.

## Reversing
I use Ghidra for this because I lack the monetary resources to purchase a more capable piece of software. First, we can follow `entry` and then the first argument to `__libc_start_main`, which is `main`. I like to rename this to `main` right off the bat.

The first function called makes a bunch of calls to `alarm` and `setbuf`. This is a typical setup in CTF challenges, in order to set a time limit and to make sure I/O is not lost in the buffer. We can rename this function to `setup`, but what the rest of the function does is unclear. There seems to be two similar blocks of code, and each one calls `malloc` and writes some data into it. Ghidra's decompilation is a bit messy here, so we'll look at the disassembly instead.

![data copying](./seegink/copy.png)

What this does is `malloc(0x1002)`, save the pointer to `0x105050`, write `0xac7` to the top two bytes of the buffer, and copy a string from `0x102008` into the memory starting right after the `0xac7` at `buffer+2`. The second block does the same thing, but writes the pointer to `0x105058` instead, and copies a different number and string.

If this is unclear to you, feel free to spend some more time on it. You may also want to try dynamic analysis—since no input has been taken up to this point, the results of this function should be deterministic, so you can just look at it in a debugger after it has run.

![heap chunks after setup function](./seegink/aftersetup.png)

The first chunk here is the `tcache_perthread_struct`, and the last one is the top chunk. The two in the middle with size `0x1010` are the chunks `setup` just allocated, and we can see the `0xac7` (in little endian) followed by a long string. The keen-eyed may recognize the long string as a series of ANSI escape codes, but we will find this out later. For now, we should define a struct like this:

![struct definition](./seegink/struct.png)

We don't really know what comes after `buffer`, but if we see any weird references to the middle of this member we can fix it later. Renaming and retyping the variables and the array at `0x105050` cleans up `main` considerably.

![main after retyping](./seegink/retype.png)

Returning back to the `main` function, we see it call another function at `0x1013f0`. This one is much simpler—all it does is read `0x20` bytes into a buffer, then call `strtol` on the buffer and return. However, if the parsed number is bigger than 1, it will end the process immediately. We can rename this function to `get_number`.

The rest of `main` is simple. It will `write` to stdout the `buffer` of the struct we selected with `get_number`, using the `number` member as the length (this is the `0xac7` from above). Then, it reads up to `0x1000` bytes into the same buffer and then writes `strlen(struct->buffer)` into `number`. Therefore, the long string copied into each buffer is the ANSI ginkoid that is printed when we input `0` or `1`.

## Vulnerability
The key vulnerability here is that `get_number` uses `strtol`, which returns signed longs.

```
NAME
       strtol, strtoll, strtoq - convert a string to a long integer

SYNOPSIS
       #include <stdlib.h>

       long int strtol(const char *nptr, char **endptr, int base);
```

This means we can input negative numbers. Sure enough, inputting `-1` gives a Segmentation Fault. Moreover, since this index is relative to a global array, the indices we use here are not affected by PIE, because even though the address of the binary is randomized, the relative positions of things are not.

What this allows us to do is select any pointer before the global array and use it as the pointer to the struct. A quick look in Ghidra reveals that there is not much before the array. The GOT *is* before the array, but Full RELRO means overwriting this is not possible (not that it would be any different if there was no RELRO, because trying to use the GOT pointer as a pointer to data would end up pointing to the code bytes of a function, which is useless). The only thing that remains is the stdio pointers.

![stdio pointers before our array](./seegink/stdio.png)

Some quick math (or just counting) gives us index `-6` for `stdout`. If we input this into the program we get a whole bunch of garbage bytes (including many libc addresses). In addition, we also then have the ability to write into `stdout+2`. This is all that we need to do to solve the challenge.

```
$ ./seegink | xxd
00000000: 5365 6520 7468 6520 6769 6e6b 6f69 643a  See the ginkoid:
-6
00000010: 200a adfb 0000 0000 2337 efcb c97f 0000   .......#7......
00000020: 2337 efcb c97f 0000 2337 efcb c97f 0000  #7......#7......
00000030: 2337 efcb c97f 0000 2337 efcb c97f 0000  #7......#7......
00000040: 2337 efcb c97f 0000 2337 efcb c97f 0000  #7......#7......
00000050: 2437 efcb c97f 0000 0000 0000 0000 0000  $7..............
```

## FSOP
Having full control of an stdio struct means we can use File Structure Oriented Programming, or FSOP. Feel free to do some research on your own if you are unfamiliar with the technique. The gist is that we can abuse the FILE struct to make a function call to anywhere. We are using `stdout` here, because the first libio function called after our write is `puts`, which obviously outputs to `stdout`.

FSOP in earlier glibc versions was simple, as you could simply point the vtable to anywhere. However, glibc 2.24 introduced a vtable check that would abort the program if the vtable did not point to the vtable section. The typical bypass for this up to glibc 2.27 was to use a function already in the vtable section like `_IO_str_overflow`, which interprets part of the FILE struct as a function pointer that we can control. Unfortunately, we are given glibc 2.29, so this specific technique does not work.

Some research brings us to [this Chinese blog post](https://darkeyer.github.io/2020/08/17/FSOP%E5%9C%A8glibc2.29%E4%B8%AD%E7%9A%84%E5%88%A9%E7%94%A8/) that describes a similar technique for glibc 2.29. Here is a translated paragraph that includes the information we need:

> It can be seen that in 2.27, the functionality of what is now `free` and `malloc` was determined by function pointers within `fp`, so we could call an arbitrary function through constructing the appropriate `fp` structure.
> However, in 2.29, these have been replaced with `free` and `malloc`, making this technique impossible.
> After some searching, I found that `_IO_wfile_jumps` still contains many functions that reference function pointers, of which `_IO_wfile_sync` is easy to use.

A quick look at the [glibc source](https://elixir.bootlin.com/glibc/glibc-2.29/source/libio/wfileops.c#L481) reveals that the function pointer is called pretty early, so this technique actually turns out to be easier than the 2.27 technique. All we have to do is satisfy this condition:

```c
fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end != 0
```

Then, the `_codecvt` member must point to some memory that starts with `b'/bin/sh\x00'` and has the address of `system` 4\*8 bytes from the start. As is typical with FSOP, we also need to point `_lock` to some null value (I generally use `_IO_stdfile_1_lock`).

The last thing we need to sort out is the vtable pointer. The first function call after `read` is `puts` (actually it's the *only* function call, because `_exit` will exit the process immediately without running any of the usual exit code), which calls `_IO_xsputn_t` at offset `0x30` from the vtable. We want to call `_IO_wfile_sync` at `_IO_wfile_jumps+0x58`, so we will set the vtable to `_IO_wfile_jumps+0x58-0x30`.

## Solving
First, we send `-6` as the index and grab one of the libc addresses. We can use this to find the base address of libc, after which we can carry out the FSOP attack.

Since we only get one write, the implementation is a bit tricky. Luckily, most of the struct members are irrelevant, so we can overlap all three of the structs.

![final payload layout](./seegink/final.png)



The left-most block is the final payload, and the members that each element corresponds to is highlighted in color. All the empty rows are null.

Remember that we are reading starting at offset 2, so we will need to cut the first two bytes off the beginning. The last thing we need to watch out for is the final `strlen`. Fortunately, the first byte we write is a null, so `strlen` returns 0 and writes a 0 to `_flags`, which is what we need.


## Flag
```
flag{stdout_m0r3_l1ke_stdsice_2e2c312e24316b3f2c35}
```

# admin-plz-v3

> Are these admins ever gonna stop?
> https://admin-plz-v3.winter-challenge.tjcsec.club/

Written by saisree

A continuation of the admin-plz series of challenges. If you hated it, well, here's good news: it's the last one. Or is it?

## Inspection

Looking at the site, we see a login form appear with a nice transition. Looking first at the source code, nothing seems to pop out immediately; just some CSS with a form sending a POST request to the url `/login`.

If we enter in a random username or password, we are greeted with the message "Wrong username or password."

From the challenge `admin-plz-v2`, we might guess that this login page contains a SQL Injection vulnerability. Let's try a standard trick where we input the username as `admin` and the password as `' OR '1'='1`:

![SQLi filter](./admin/filter.jpg)

Looks like there's some filtration here. Let's try substituting `||` for `OR`. Same result.

We could try different techniques to bypass the filters, but it seems like the admins did a decent job with that, so we are a little stuck.

Let's look at some other aspects of the site to see if we find anything. Looking at the network requests, nothing seems odd—just the POST request to the server. If we look at the cookies, however, there's something interesting: a cookie called `encoding`. This is its value:

```
YldRMUlHSjFkQ0J0WVd0bElITjFjbVVnZEc4Z1pHVnNaWFJsSUhSb2FYTWdiR0YwWlhJaElTRT0=
```

Looks like base64! Let's decode it:

```
bWQ1IGJ1dCBtYWtlIHN1cmUgdG8gZGVsZXRlIHRoaXMgbGF0ZXIhISE=
```

Looks like base64! Let's decode it again!

```
md5 but make sure to delete this later!!!
```

Clearly, the admins forgot to clean up.

## Exploitation

So we know that the password is encrypted with md5 hash and is then checked to the database column, so we cannot inject any SQL code into it. This means our exploit has to reside only in the username field. Usually, the way around this is to comment out that part of the query, but the filtration in place doesn't seem to allow that. After trying the comment characters `/*`, `#`, and `{`, it doesn't look like we're getting past this filter.

To come across the correct exploit, you may need to do some research. A way to find the right idea is to research bypassing a password hash. Most answers suggest commenting out the rest of the query, but that won't work here. If you keep going, you will find the following [cheat sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) that details several SQLi techniques. Scrolling down to `Bypassing second MD5 hash check login screens`, we find this:

![MD5 bypass](./admin/md5bypass.jpg)

This might be interesting to you, if you've never used union-based SQL injection in such situations. But this could work, as it doesn't contain the keyword `OR`, which we know already to be filtered. Trying this out...

![SQLi filter again](./admin/filter.jpg)

Substituting `&&` for `AND` gives the same result. Our last try: maybe we can try to change the capitalization of the words `UNION`, `ALL`, and `SELECT` to see if anything changes. Additionally, since the keyword `AND` is filtered, let's just remove the condition `AND 1=0` to try things out:

Username:

```
admin' uNION aLL sELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```

Password:

```
1234
```

![an error instead of filter block](./admin/error.jpg)

**Gasp**. So it appears we got past the filter with that, so the admins forgot to check for case in their filtration for those three keywords. Now we just have to figure out how to make this `UNION` query not error. Since we have an error response available (although not specific errors), we can simply test out various queries.

In the first SELECT query, we know we will have either two values or all values returned from the query, as the options are `SELECT * FROM {{table}}` or `SELECT username, password FROM {{table}}`. In our second SELECT query, we just need to provide the username column as ``'admin'`` and insert a random string for `password` so that it will not consider the second half of the original query. We still don't know two things: the name of the table, and the amount of columns in the table. As is common with UNION-based SQLi, we can guess!

A common table name is `users`, so let's use that. Finally, checking the error messages, we can figure out that there are two columns in the table. So, our final exploit is the following. The second query simply returns no results, so that we can limit the results to the first query `SELECT username, password FROM users WHERE username = 'admin'`.

Username:
```
admin' uNION aLL sELECT 'fdsa', 'fdsafdsa' fROM 'users' wHERE 'fdsa' = '
```

Password:
```
anystring
```

**Note**: The `fdsa' = '` is to satisfy the delimiter quote character at the end of the query, and to satisfy syntax for the rest of the query: `AND 'password' = md5(pass)` which is implied from the fact that the password is encrypted.

## Editor's Note

The solution path presented here is quite convoluted. When test solving, I did not even notice the MD5 cookie and did not do much of what is described here. A working payload for the username field is listed below.

```
admin' union select 1,1 from users where '
```

## Flag

```
flag{n0_chAnc3_e0180017a92018917265af44b92b8616}
```

# hacker-maze

> Good luck on the HackerMaze Any% Speedrun!
> `nc winter-challenge.tjcsec.club 30004`
>
Written by saisree

Not sure what the 100% category for this would be.

## Inspection

So this part is pretty short. If we connect to the service, we are greeted with this:

```
$ nc winter-challenge.tjcsec.club 30004

Any% HackerMaze Speedrun
R means right, U means up, L means left, D means down.
You start at S, and your goal is E.
Enter in a solution to the maze below:
#########################################
S.#.#.#.#.#...#.#.#.#...#.#.#...#.#.#...#
#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#
#.#.#.#...#.#.#.#.#...#.#.....#.#.....#.#
#.#.#.#.#.###.#.#.#.#.#.#.#.#.###.#.#.###
#.....#.#.#.#.#.#.#.#.#.#.#.#.....#.#...#
#.#.#.###.#.#.#.#.###.#.###.#.#.#.#.#.#.#
#.#.#.#.#.....#.#.#.#.#.#.#.#.#.#.#.#.#.E
#####.#.#.#.#.#.#.#.#.###.#.###.#.#.#.#.#
#.......#.#.#.#.#.#.#.#.......#.#.#.#.#.#
#.#.#.#.#####.#.#.#.#.#.#.#.#.#.#######.#
#.#.#.#...#.#.#.#.#.....#.#.#.#.#.#.#.#.#
#####.#.#.#.#.#.#.#.#.#.#########.#.#.###
#...#.#.#...#.#.#.#.#.#.................#
#.#.#####.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#
#.#.......#.........#.#.#.#.#.#.#.#.#.#.#
###.#.#.#.#.#.#.#.#.#####.###.###.###.###
#.#.#.#.#.#.#.#.#.#.#...#...#.#.....#...#
#.###.#.#.#.#.#.###.#.#.#.#.#.#.#.#.#.#.#
#.....#.#.#.#.#.#.....#.#.#.#.#.#.#.#.#.#
#########################################
Use this format: RDLURDLURDLU
You have three seconds, starting now.
Enter your answer:
```
If we don't enter anything in three seconds, we get
```
Too slow!
```
If we enter something in, we get
```
Incorrect path.
```
Our objective is to send in a path consisting of Left, Right, Up, and Down movements to reach the `E` (exit) from `S` (start). Since there's no way we could do this in three seconds, we're going to have to script this.

## Scripting (Python)

### Reading in the Maze
In order to solve the maze, we have to read it into our script from the output of the service. We can use pwntools for this:

```python
from pwn import *
connection = remote('hacker-maze.winter-challenge.tjcsec.club', 30002)
text = str(connection.recvuntil("Enter your answer: "))
lines = text.split("\\n")
```
This gives us a list with all of the lines received until the line `Enter your answer: ` We can extract the maze by concatenating the lines which contain the character `#`. This is easiest, as not all lines begin with the character `#`; some begin with `S` or `E`.
```python
maze = ''
for line in lines:
    if "#" in line:
        maze += line
```
Now we have our maze, stored as a one-line string. We can compute the length of this string, which gives us 861. This means the dimensions of the maze are 21 x 41, not counting the walls on our the outer edges.

### Solving the Maze

A very handy algorithm that works great for mazes is the [Breadth-first Search algorithm](https://en.wikipedia.org/wiki/Breadth-first_search), or BFS. Generally speaking, BFS is a graph-traversal algorithm. A maze is an example of a graph, as the edges of nodes are simply directions—R, L, U, D—while nodes can be just the index of an empty space.

To implement the BFS algorithm, we first need a method to generate the children nodes for each node. For example, here's an empty space A:

```
#..#
##A# --> A + 41, A - 41
#..#
```
We add and subtract 41 as it is the width of the maze, and our maze is stored as a string. Likewise, L and R movements would be -1 and +1 respectively.

Here is a method that generates the correct nodes:
```python
def children(index, board):
    directions = {"R": 1, "L": -1, "U": -41, "D": 41}
    allowed = ["R", "L", "U", "D"]
    if index >= 821:
        allowed.remove("D")
        allowed.remove("R")
        allowed.remove("L")
    elif index <= 40:
        allowed.remove("U")
        allowed.remove("R")
        allowed.remove("L")
    else:
        if board[index - 1] == "#":
            allowed.remove("L")
        if board[index + 1] == "#":
            allowed.remove("R")
        if board[index - 41] == "#":
            allowed.remove("U")
        if board[index + 41] == "#":
            allowed.remove("D")

    result = []
    for x in allowed:
        result.append(index + directions[x])
    return result
```
There are two special cases that are handled by `index >= 821` and `index <= 40`: if the index refers to `S` or the `E` and are in the first or last row of the board, the only direction possible is to go up or down. This is to prevent any indexing errors.

Finally, we can write our BFS algorithm. However, since we need to submit the solve _path_, we need to make some modifications to use BFS to solve the maze. I won't share the implementation to this, as the pseudocode to BFS is pretty clear, and I encourage you to try this yourself! In order to return the path, you can store the history of movements between nodes as you traverse them. That way, when you reach the `E`, you can reverse your steps using the edges by going backwards through the data structure.

Once the BFS is implemented, we can send our solution back to the service:
```python
solution = get_solution(maze)
connection.sendline(solution)
print(connection.recvline())
print(connection.recvline())
```
And we are done!

## Flag
```
flag{m4z3_M4S13R_Hack3R}
```

# quadrupedal-locomotive

> We've been working on these new robots, and are getting ready to release them to users! You can reserve your own if you have access to the flag! However, we've made these flags really hard to find, and I doubt you'll find it.
https://quadrupedal-locomotive.winter-challenge.tjcsec.club/

A fun little easy problem for beginners to enjoy!

## Inspection

Looking at the site, we are greeted with a GIF of a dancing robot, with a button saying "Reserve a robot, only for one flag." If we click on the button, we get a dialog saying, "stop botting and find the flag".

![home page](./quad.png)

It seems that there are a lot of references to robots... hmmmm...

## Exploitation

What's a nice little thing that can leak us extra information about a site, and has something to do with robots? That's right, ``robots.txt``!

For those of you who are not aware, ``robots.txt`` is a little file hosted on domains that tells search engine crawlers (like Google's) to not query certain pages.

In the case of this problem, ``robots.txt`` looks like this:

```
User-agent: *
Disallow: /internalblog/
```

What this basically tells us is that web crawlers, with any user agent (``*``\), to not index the page at ``/internalblog/``. Well, we can visit it just fine.

Go to https://quadrupedal-locomotive.winter-challenge.tjcsec.club/internalblog/

Upon opening this page, it seems that we have found the flag!

## Flag

```
flag{rob0t_txt_inf0_l3ak}
```

# open-source

> I created this website to upload different examples of open source projects. ? However, I've forgotten my password, and need to get the flag from my dashboard.
>
> I can't even tell you how my code works, since I forgot to push to git.
>
>My username is "admin".
https://open-source.winter-challenge.tjcsec.club/

A nice, intermediate two-step problem. Not too hard, not too easy.

## Inspection

We are greeted by a site with a bunch of links that just redirect to open-source software websites.

![home page](./opensource/home.png)


If we click on the "User Console" button, we get redirected to a login form. On this login form, we can login with any username & password combo, as long as the username is not ``admin``.

Upon logging in, we notice that there's a key ``jwt`` containing a JWT token (duh\). Let's take a look at what this looks like:

### Raw
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXJuYW1lIiwiaWF0IjoxNjA4MDkwNDU0LCJleHAiOjE2MDgwOTc2NTR9.HSRi3uEGLhOdYkNmxJKhLsp4kAa4jOHWIvRO-MMcEqk
```

**Header**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
**Payload**
```json
{
  "username": "username",
  "iat": 1608090454,
  "exp": 1608097654
}
```

As the problem states, we must login as admin to retreive the flag. Somehow, we've gotta forge a valid token, such that the ``username`` parameter in the payload is ``admin``.

## Inspection, Part 2

Common JWT attacks, such as ``alg: none`` will not work (that'd be simple), and bruteforcing the secret key is unnecessary (trust me, it'd take many, many years to brute force). So how are we supposed to grab the secret key to create valid tokens? Well, the answer has been hiding in plain sight.

Throughout the whole site, we get references to different open-source Linux Distributions and Web Frameworks. Furthermore, the banner contains text saying, "``Git Source coming Soon!``". These references, combined with the knowledge that a git repo may have been initialized, may indicate that the developer (me) has left a ``.git`` source leak.

Going to https://open-source.winter-challenge.tjcsec.club/.git/ 404's, so does that mean that this is a dead end? No! What if we look for a file used by git?

https://open-source.winter-challenge.tjcsec.club/.git/HEAD presents us with a file! Looks like there is a git information leak after all!

## Exploitation

Since https://open-source.winter-challenge.tjcsec.club/.git/ 404's, using ``git clone`` will not work. However, what if we just use one of those [git leak](https://github.com/internetwache/GitTools) scripts.

![running gitdumper](./opensource/gitdumper.png)

Nice! The script downloaded the git repo, let's see if we can do some forensics and see if there's anything useful. ``git log`` reveals the following:

![git log](./opensource/gitlog.png)

Looks like some amatuer developer (me) leaked the JWT secret key, let's check that commit!

![git commit](./opensource/gitcommit.png)

look ma, secret key (and a fake flag)!
```
congratsyoufoundthesecretbutnottheflag52367802618!%^&*$#
```

We can just take this secret flag, and our original raw JWT payload, and forge a token with [jwt.io](https://jwt.io)

![making a JWT](./opensource/jwt.png)

Here's our final token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjA4MDkwNDU0LCJleHAiOjE2MDgwOTc2NTR9.V_YoBnM-EH36f-ddrrNF5wmPDUKsddLIRzeOb31LvPg
```

Paste that into local storage, go into the user console, and bam! flag.

## Flag

```
flag{st0p_s3rv1ng_g1t_p1s}
```
