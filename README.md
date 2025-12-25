# MiniMachO: Lightweight Behavioral Fingerprinting Tool

A specialized C++ tool designed to extract **static behavioral features** from macOS Mach-O binaries. 
It implements a "SymHash-like" algorithm by analyzing the `LC_LOAD_DYLIB` dependency chain, generating a unique fingerprint for malware clustering and family identification.

## Key Features
* **Zero-Dependency**: Written in pure C/C++ using native `mmap` and `mach-o/loader.h`.
* **Obfuscation Resilient**: Implements lexicographical sorting to counter dependency reordering attacks.
* **Performance**: $O(1)$ complexity relative to file size (only parses Load Commands).
* **Universal**: Compatible with standard Mach-O headers (x86_64/arm64).

## How it works
1. Maps the binary into memory using `mmap`.
2. Traverses `Load Commands` to filter `LC_LOAD_DYLIB`.
3. Normalizes and sorts the import sequence.
4. Computes a DJB2 hash as the unique behavioral signature.

## Usage
```bash
g++ main.cpp -o minimacho
./minimacho /path/to/target