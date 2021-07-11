# double-slit-experiment
Identify containers at runtime and observe them. No container runtime required. Read only access to the kernel.

# Conventions

### /probe

This is the BPF probe code.
This code should standalone and compile to an elf object with a corresponding Makefile.

### /userspace

There are two userspace components (at least for now).

#### /userspace/go

This is the main `.go` library for the project.

#### /userspace/c

This is a `.so` header library for the project.


