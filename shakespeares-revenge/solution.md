Generated using AI |
In this CTF I participated as member of Hidden Investigations.

# shakespeares-revenge - Full Beginner-Friendly Writeup

## Challenge Information

- Challenge name: shakespeares-revenge
- Category: reverse engineering / pwn-style scripting abuse
- Remote service: ncat --ssl shakespeares-revenge.opus4-7.b01le.rs 8443
- Flag format: bctf{...}

---

## My Goal

I decided to do this in a strict order:

1. Analyze every local artifact first.
2. Reverse the interpreter behavior offline.
3. Understand exactly what the provided SPL script is doing.
4. Build a deterministic payload.
5. Run that payload once against the service and read the flag.

---

## Artifacts I Started With

In my workspace I had:

- challenge.spl
- shakespeare (ELF binary)
- shakespeare.c (Ghidra decompiled output)
- server.py

I immediately checked the binary type:

```bash
file shakespeare
```

I got:

- ELF 64-bit LSB PIE executable
- dynamically linked
- not stripped
- includes debug info

This was great because debug info and symbol names usually make reversing much easier.

---

## Step 1 - Quick Triage of Local Files

### 1) server.py

I read server.py first. It only runs:

- ./shakespeare challenge.spl

and then prints a random insult.

Important finding:

- server.py is not the challenge logic itself.
- The real behavior is inside the binary + challenge.spl.

### 2) challenge.spl

I read challenge.spl fully.

At first glance it looked like a Shakespeare Programming Language calculator script with scenes:

- Scene I: setup
- Scene II: input + branch selection
- Scene III: add
- Scene IV: multiply
- Scene V: subtract
- Scene VI: cleanup

The very suspicious line was in Scene VI:

- Revere your player Hamlet.

That line is not part of classic SPL tutorials and looked custom.

### 3) shakespeare.c (decompiled)

I did not try to trust it blindly as source code.

I treated it as reverse-engineering evidence.

I confirmed this quickly when compilation failed with many C++/decompiler artifacts (labels, missing types, broken syntax). That is normal for big decompilation dumps.

---

## Step 2 - Locate Key Runtime Functions in Decompiled Output

I searched for core interpreter symbols and found:

- ShakespeareInterpreter::Impl::compile_play
- ShakespeareInterpreter::Impl::execute_operation
- ShakespeareInterpreter::Impl::evaluate_expression
- ShakespeareInterpreter::Impl::consume_numeric_input
- ShakespeareInterpreter::Impl::run

Then I traced sentence compiler functions:

- compile_input
- compile_output
- compile_push
- compile_pop
- compile_reference
- compile_goto
- compile_question
- compile_assignment
- compile_syscall

This immediately confirmed:

- The interpreter has a hidden syscall opcode.
- The phrase Revere your player X maps to that opcode.

---

## Step 3 - Confirm the Custom Syscall Primitive

From compile_syscall, I recovered this parsing rule:

- Revere your player <character_name>

From execute_operation (SYSCALL case), I recovered the exact runtime behavior:

1. It chooses the named character stack as syscall source.
2. Top stack value is treated as syscall number.
3. It looks up required argument count in a built-in table.
4. It pops that many arguments from the same stack.
5. Then it calls invoke_syscall, which directly calls Linux syscall(...).

This is the core vulnerability/feature I exploited.

---

## Step 4 - Recover Allowed Syscalls and Arg Counts

I extracted the syscall table from the initializer in disassembly (objdump around the lambda that fills syscall_argument_count map).

I found many mappings. The ones that mattered most for my solve were:

- 59 -> 3 args (execve)
- 60 -> 1 arg (exit)
- 0 -> 3 args (read)
- 1 -> 3 args (write)
- 2 -> 3 args (open)
- 257 -> 4 args (openat)

So I decided to target syscall 59 (execve), because if I can run /bin/sh, I can just read the flag file directly from the service environment.

---

## Step 5 - Understand a Critical Stack Quirk

One very important low-level detail was inside RuntimeCharacter::push:

- Values are stored as 32-bit words (ValueType).
- If input value is larger than 32-bit, push splits it into high word then low word.

So pushing 4294967297 (0x00000001_00000001) stores two stack words:

- 1
- 1

Another critical detail:

- RuntimeCharacter::pop pops only one 32-bit word at a time.

That means:

- A single numeric input can create two words on stack.
- Later code that pops "one value" may only consume one word.
- This lets me shape stack memory very precisely.

This is exactly what made the payload possible.

---

## Step 6 - Understand C-String Substitution Sentinel

In SYSCALL argument handling, I found a magic behavior:

- If popped argument equals 4294967295 (0xffffffff), interpreter replaces it with a pointer to a C-string built from a referenced stack.

And in this script, Scene I includes:

- Reference Romeo.

That sets Hamlet to reference Romeo's stack.

So when syscall is executed on Hamlet and arg1 is 0xffffffff:

- arg1 becomes pointer to C-string generated from Romeo stack contents.

This gave me a clean route:

- Put /bin/sh\0 bytes on Romeo stack.
- Put syscall frame on Hamlet stack.
- Trigger Scene VI.

---

## Step 7 - Understand Scene II Branch Selector Exactly

Scene II asks comparisons using SPL noun phrases:

- cat
- cute cat
- cute cute cat
- sum of cute cat and cat

From parser logic, noun magnitude is power_of_two(adjective_count), with sign from noun type.

So:

- cat = 1
- cute cat = 2
- cute cute cat = 4
- sum of cute cat and cat = 3

The control flow behaves as:

- input op > 4 -> Scene VI (syscall trigger)
- else if op > 3 -> Scene V
- else if op > 2 -> Scene IV
- else if op > 1 -> Scene III

So op=2 selects add-scene, and op=5 jumps directly to syscall scene.

---

## Step 8 - Build the Exploit Strategy

I used two phases.

### Phase A - Loop through add scene to shape both stacks

I repeatedly sent triplets:

- first number
- second number
- opcode 2 (go to add scene)

Each loop did arithmetic but, more importantly, manipulated stacks in a predictable way.

I used large constants so split-word behavior would leave byte values on Romeo stack in the right order.

### Phase B - Final trigger

At the end, I sent:

- 98
- 47
- 5

Opcode 5 jumps to Scene VI and executes syscall immediately.

At that point:

- Romeo stack C-string resolved to /bin/sh
- Hamlet stack top frame matched execve requirements:
  - syscall number 59
  - arg1 sentinel 0xffffffff (converted to pointer to /bin/sh)
  - arg2 0
  - arg3 0

So the service process became an interactive shell.

---

## Final Working Payload

I used this exact input sequence:

```text
0
4294967297
2
104
4294967297
2
493921239087
4294967297
2
472446402665
4294967297
2
0
0
2
0
0
2
4294967295
0
2
59
0
2
98
47
5
```

Then, in the shell, I ran:

```bash
cat flag.txt
```

And got the flag.

---

## Flag

```text
bctf{4_p0und_0f_fl35h}
```

---

## Full Solve Timeline (What I Did, In Order)

1. I checked the binary format and confirmed it was a Linux ELF PIE with symbols.
2. I read server.py and confirmed it is just a wrapper.
3. I read challenge.spl and marked suspicious sentence Revere your player Hamlet.
4. I searched decompiled code for compile/execute functions.
5. I confirmed a hidden syscall opcode exists and mapped to that sentence pattern.
6. I traced syscall argument handling and found the 0xffffffff pointer substitution trick.
7. I traced RuntimeCharacter push/pop internals and found 64-bit split into 32-bit words.
8. I extracted syscall allowlist and argument counts from disassembly.
9. I decoded Scene II thresholds and opcode routing (2 for add loops, 5 for final jump).
10. I designed a payload that:

- prepares /bin/sh string bytes on Romeo stack,
- prepares execve frame on Hamlet stack,
- triggers Scene VI.

11. I executed the payload once, got shell, and read flag.txt.

---

## Beginner Glossary

### ELF

Executable and Linkable Format. Standard binary format for Linux executables.

### PIE

Position Independent Executable. Loaded at random memory addresses (ASLR-friendly).

### Decompiler

Tool (like Ghidra) that tries to convert machine code into C-like pseudocode.

### Disassembly

Low-level assembly listing of machine instructions.

### Syscall

Direct request from user-space program to Linux kernel (read, write, execve, etc).

### execve

Linux syscall that starts a new program image (for example /bin/sh).

### Stack (in this challenge)

Per-character value container used by the interpreter. Not the CPU call stack.

### Sentinel value

Special magic value with special meaning. Here 0xffffffff means "replace with C-string pointer".

### C-string

Null-terminated byte string in memory (ends with byte 0).

### Opcode / Operation type

Internal instruction kind interpreter executes (INPUT, OUTPUT, PUSH, POP, SYSCALL, GOTO, ...).

### Runtime state

Interpreter current state: which characters are on stage, stack contents, current scene position, boolean condition state.

---

## Why This Challenge Is Interesting

This was not a normal "decode string and print flag" reverse challenge.

It combined:

- a custom interpreted language,
- non-obvious hidden extension (syscalls),
- parser-level sentence mapping,
- stack word-size edge case,
- and runtime state manipulation.

So the solve was mostly about understanding behavior exactly, not brute forcing.

---

## Repro Tips

- Keep everything deterministic: same payload, same order.
- If /flag does not exist, always check ls first.
- In this instance, the real flag file was flag.txt.

---

## Final Note

I solved this by fully analyzing local artifacts first, then using a single precise exploit flow. No guessing was needed once interpreter behavior was mapped correctly.
