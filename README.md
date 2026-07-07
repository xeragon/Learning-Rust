# Learning Rust for Pentest & Red Team

Repository for resources, code, and tools used to learn Rust for offensive security, pentesting, and red team operations.

---

## Objectives
- Track learning resources (books, guides, tutorials).
- Store code implementations, PoCs, and tools.
- Document notes and best practices for Rust in offensive security.

---

## Resources
- [The Rust Programming Language (Brown University)](https://rust-book.cs.brown.edu) – Primary guide for learning Rust basics.

---

## Structure
```
Learning-Rust/
├── basics/        # Code snippets and notes about Rust basics -> primarly taken from [The Rust Book](https://rust-book.cs.brown.edu)
├── red-team/      # Source code & snippets for tools and PoCs
│   ├── tools/     # Just maps to my public tools built in rust
│   ├── poc/       # Proof of Concepts
│   └── snippets/   # Code snippets that might be usefull
└── resources/     # Downloaded resources (PDFs, slides)
```

---

## Getting Started
1. Install Rust via [rustup](https://rustup.rs):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustc --version
   cargo --version
   ```

2. Create a new project:
   ```bash
   cargo new tool_name --bin
   cd tool_name
   ```

3. Build and run:
   ```bash
   cargo build
   cargo run
   cargo build --release
   ```

---

## Best Practices for Offensive Tools
- Use `--release` and `strip` to reduce binary size.
- Avoid `unsafe` unless necessary.
- Prefer `Result` and `Option` over `unwrap()` for error handling.
- Limit external dependencies to reduce attack surface.

---

## Roadmap
1. Learn Rust basics (ownership, borrowing, lifetimes, concurrency).
2. Study offensive Rust (sockets, processes, FFI, shellcode).
3. Build tools : port scanner, brute-forcer, reverse shell.
4. Build evasive tools : loaders/packers/dropers, C2 implants.

---

## License
MIT License. Ensure all offensive tooling is used legally with proper authorization.
