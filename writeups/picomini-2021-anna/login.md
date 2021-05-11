---
title: picoMini by redpwn 2021 - login (web)
date: 2021-05-11
slug: /writeups/picomini-redpwn-login
excerpt: Client side login seems like a bad idea
author: Anna Hsu
---
# Description
> My dog-sitter's brother made this website but I can't get in; can you help?
>
> login.mars.picoctf.net

# Solution
On first inspection, when faced with a [login screen](https://login.mars.picoctf.net), it seems like SQL injection, because isn't that what always happens with logins in CTFs? However, it's a lot simpler than that. After navigating to website source, we encounter `index.js`. Upon pretty-printing, it's just vanilla JS.

```js
(async()=>{
    await new Promise((e=>window.addEventListener("load", e))),
    document.querySelector("form").addEventListener("submit", (e=>{
        e.preventDefault();
        const r = {
            u: "input[name=username]",
            p: "input[name=password]"
        }
          , t = {};
        for (const e in r)
            t[e] = btoa(document.querySelector(r[e]).value).replace(/=/g, "");
        return "YWRtaW4" !== t.u ? alert("Incorrect Username") : "cGljb0NURns1M3J2M3JfNTNydjNyXzUzcnYzcl81M3J2M3JfNTNydjNyfQ" !== t.p ? alert("Incorrect Password") : void alert(`Correct Password! Your flag is ${atob(t.p)}.`)
    }
    ))
}
)();
```
The important part of the code is in line 12, where it's checking for a username and password that has been turned into Base64 from ASCII via the `btoa()` method, which is reversible with the `atob()` method. The password itself is the flag when decoded. Opening the console and running `atob("cGljb0NURns1M3J2M3JfNTNydjNyXzUzcnYzcl81M3J2M3JfNTNydjNyfQ")` results in the flag.

If you're not convinced it's the real flag, you can decode the username (`admin`) and input both into the login form, which results in an alert announcing the flag.

# Flag
```
picoCTF{53rv3r_53rv3r_53rv3r_53rv3r_53rv3r}
```