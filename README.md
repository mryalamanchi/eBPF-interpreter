# eBPF-Interpreter

This repository contains a simple eBPF interpreter written in Go. This interpreter provides a basic implementation of eBPF instructions and their execution.

## Features:

- Supports a subset of 64-bit ALU instructions.
    - ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG, MOD, XOR, MOV, ARSH
- Supports a subset of memory instructions.
    - LD, LDX, ST, STX
- Supports a subset of branch instructions.
    - JA, JEQ, JGT, JGE, JLT, JLE, JSET
- Provides a basic memory model for the interpreter.
    - 65536 bytes of memory, configurable.
- Interprets and executes eBPF bytecode.

## Usage:

1. Define your eBPF bytecode in the `bytecode` slice.
2. Call the `Interpret` function with the bytecode.
3. The interpreter will execute the bytecode and print the final state of the registers.

## How to Run:

```bash
go run main.go
```