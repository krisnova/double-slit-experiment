/*
 * This file is part of The Double Slit Experiment (https://github.com/kris-nova/doubleslitexperiment).
 * Copyright (c) 2021 Kris Nóva <kris@nivenly.com>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>




#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32
#define DATA_SIZE_32 32
#define DATA_SIZE_64 64

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");


struct clone_data_t {
    int *parent_tid;
    int *child_tid;
    unsigned long clone_flags;
};

struct clone_entry_args_t {
    __u64 _unused;
    __u64 _unused2;

    unsigned long clone_flags;
    unsigned long newsp;
    int *parent_tidptr;
    int *child_tidptr;
    unsigned long tls;
};

/**
 * name: sys_enter_clone
ID: 122
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned long clone_flags;        offset:16;      size:8; signed:0;
        field:unsigned long newsp;      offset:24;      size:8; signed:0;
        field:int __attribute__((user)) * parent_tidptr;        offset:32;      size:8; signed:0;
        field:int __attribute__((user)) * child_tidptr; offset:40;      size:8; signed:0;
        field:unsigned long tls;        offset:48;      size:8; signed:0;

print fmt: "clone_flags: 0x%08lx, newsp: 0x%08lx, parent_tidptr: 0x%08lx, child_tidptr: 0x%08lx, tls: 0x%08lx", ((unsigned long)(REC->clone_flags)), ((unsigned long)(REC->newsp)), ((unsigned long)(REC->parent_tidptr)), ((unsigned long)(REC->child_tidptr)), ((unsigned long)(REC->tls))

 */
SEC("tracepoint/syscalls/sys_enter_clone")
int enter_clone(struct clone_entry_args_t  *args){
    struct clone_data_t clone_data = {};

    clone_data.child_tid = args->child_tidptr;
    clone_data.parent_tid = args->parent_tidptr;
    clone_data.clone_flags = args->clone_flags;

    // Send out on the perf event map
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &clone_data, sizeof(clone_data));
    return 0;
}


struct exec_data_t {
    __u32 pid;
    __u8 fname[DATA_SIZE_32];
    __u8 comm[DATA_SIZE_32];
};

// For Rust libbpf-rs only
struct exec_data_t _edt = {0};



struct execve_entry_args_t {
    __u64 _unused;
    __u64 _unused2;

    const char* filename;
    const char* const* argv;
    const char* const* envp;
};

/**
 * name: sys_enter_execve
ID: 710
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char __attribute__((user)) * filename;      offset:16;      size:8; signed:0;
        field:const char __attribute__((user)) *const __attribute__((user)) * argv;     offset:24; size:8;  signed:0;
        field:const char __attribute__((user)) *const __attribute__((user)) * envp;     offset:32; size:8;  signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *args){
    struct exec_data_t exec_data = {};
    __u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    exec_data.pid = LAST_32_BITS(pid_tgid);
    bpf_probe_read_user_str(exec_data.fname, sizeof(exec_data.fname), args->filename);
    bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));

    // Send out on the perf event map
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";