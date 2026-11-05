---
name: dogbolt-binary-decompiler
version: 1.0.0
description: Decompile and reverse-engineer small binaries (<2MB) using 13 multi-engine decompilers (Ghidra, Hex-Rays/IDA, Binary Ninja, Angr, etc.) via Dogbolt.
author: kadohack12
tags: [reverse-engineering, security, decompiler, ghidra, binary-analysis, mcp]
---

# Dogbolt Binary Decompiler Skill

This skill teaches the AI agent how to analyze, decompile, and inspect binary executables (ELF, PE, Mach-O) using the Dogbolt MCP server.

## When to Use This Skill

Activate this skill whenever the user:
- Asks to analyze, reverse-engineer, or explain an executable/binary file.
- Needs decompiled C source code from a compiled artifact (`.exe`, `.elf`, `.dylib`, `.bin`).
- Wants to compare outputs between industry-standard decompilers (e.g., Ghidra vs. Hex-Rays vs. Binary Ninja).
- Wants to understand what a specific function (e.g., `main`, crypto routines, obfuscated logic) is doing inside a binary.

---

## Safety & Operational Constraints

1. **Size Limit:** Binaries **must not exceed 2 MB**. Check file size before initiating decompilation.
2. **Confidentiality Notice:** Dogbolt is a public service. **NEVER** upload binaries containing private cryptographic keys, hardcoded proprietary secrets, or confidential corporate IP without explicit user confirmation.
3. **Deduplication:** Binaries are indexed by SHA-256. Re-analyzing an existing file is instant and does not re-upload data.

---

## Engine Selection Guide

When deciding which decompiler to target:
- **`ghidra` (Recommended default):** Excellent generic analysis, clean control-flow recovery, handles most architectures (x86, x64, ARM, MIPS).
- **`hex-rays`:** Best-in-class readability for x86/x64 and ARM, closest to idiomatic C.
- **`binaryninja`:** Fast, highly structured Intermediate Representation, strong type recovery.
- **`angr`:** Powerful for symbolic execution analysis, but decompiled output can be verbose.
- **`all`:** Use when comparing engine disagreements or recovering heavily obfuscated code.

---

## Workflow Instructions for the Agent

1. **Verify File:** Check that the target file exists locally and is under 2 MB.
2. **Decompile:**
   - Call `decompile_binary(file_path="...", target_decompiler="ghidra")`.
   - If the user wants a comparison, call `compare_decompilers` across `["ghidra", "hex-rays", "binaryninja"]`.
3. **Analyze Output:**
   - Identify the entry point (`main` or export symbols).
   - Trace string references, system calls, and branching logic.
   - Summarize the binary's behavior, potential risks, and data structures back to the user in clean Markdown.
