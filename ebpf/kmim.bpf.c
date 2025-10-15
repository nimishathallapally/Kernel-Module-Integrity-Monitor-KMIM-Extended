// SPDX-License-Identifier: GPL-2.0

// Define basic types first
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

// Define essential BPF constants
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_RING_SIZE (256 * 1024)
#define MAX_MODULES 512
#define MAX_SYSCALLS 512
#define MAX_HIDDEN_CHECKS 100

// Event types
enum event_type {
    MODULE_LOAD = 1,
    MODULE_UNLOAD = 2,
    HIDDEN_MODULE = 3,
    SYSCALL_HOOK = 4,
    UNEXPECTED_EVENT = 5,
    HASH_MISMATCH = 6
};

struct module_event {
    __u32 event_type;
    char name[64];
    __u64 addr;
    __u64 size;
    __u64 timestamp;
    char compiler_info[128];
    __u32 sections_count;
    __u32 module_id;
    __u8 sha256_hash[32];
    __u32 severity; // 0=INFO, 1=WARNING, 2=CRITICAL
};

// Ring buffer for events
struct {
    __u32 type;
    __u32 max_entries;
} events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = BPF_RING_SIZE,
};

// Hash map to track loaded modules
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} loaded_modules SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_MODULES,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct module_event),
};

// Array to store syscall table addresses
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} syscall_table SEC(".maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = MAX_SYSCALLS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};

// Configuration map
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} config SEC(".maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .max_entries = 10,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};

// Hash function for module names
static __u32 hash_module_name(const char *name) {
    __u32 hash = 5381;
    char c;
    int i;
    
    #pragma unroll
    for (i = 0; i < 64 && (c = name[i]) != '\0'; i++) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % MAX_MODULES;
}

// Check if module is hidden (exists in tracepoint but not in /proc/modules)
static int check_hidden_module(const char *name, __u64 addr, __u64 size) {
    struct module_event *event;
    __u32 key = 0; // Config key for hidden module detection
    __u64 *detection_enabled = bpf_map_lookup_elem(&config, &key);
    
    if (!detection_enabled || *detection_enabled == 0)
        return 0;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->event_type = HIDDEN_MODULE;
    bpf_probe_read_kernel_str(event->name, sizeof(event->name), name);
    event->addr = addr;
    event->size = size;
    event->timestamp = bpf_ktime_get_ns();
    event->severity = 2; // CRITICAL
    event->sections_count = 0;
    event->module_id = 0;
    bpf_probe_read_kernel_str(event->compiler_info, sizeof(event->compiler_info), "hidden_detection");
    
    // Initialize hash
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        event->sha256_hash[i] = 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 1;
}

// Simplified tracepoint context structures
struct trace_module_load_ctx {
    __u64 __unused_1;
    __u64 __unused_2;
    char name[56];
    __u64 ip;
    __u32 size;
    int refcnt;
};

struct trace_module_free_ctx {
    __u64 __unused_1;
    __u64 __unused_2;
    char name[56];
    __u64 ip;
    int refcnt;
};

SEC("tp/module/module_load")
int trace_module_load(struct trace_module_load_ctx *ctx) {
    struct module_event *event;
    __u32 module_id;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Generate module ID
    module_id = hash_module_name(ctx->name);
    
    // Capture module metadata
    event->event_type = MODULE_LOAD;
    bpf_probe_read_kernel_str(event->name, sizeof(event->name), ctx->name);
    event->addr = ctx->ip;
    event->size = ctx->size;
    event->timestamp = bpf_ktime_get_ns();
    event->sections_count = 0; // Will be filled by userspace
    event->module_id = module_id;
    event->severity = 0; // INFO
    
    // Initialize compiler info and hash
    event->compiler_info[0] = '\0';
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        event->sha256_hash[i] = 0;
    }
    
    // Store module in tracking map
    bpf_map_update_elem(&loaded_modules, &module_id, event, 0);
    
    // Check for hidden modules
    check_hidden_module(ctx->name, ctx->ip, ctx->size);
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("tp/module/module_free")
int trace_module_free(struct trace_module_free_ctx *ctx) {
    struct module_event *event;
    __u32 module_id;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Generate module ID
    module_id = hash_module_name(ctx->name);
    
    // Capture module metadata
    event->event_type = MODULE_UNLOAD;
    bpf_probe_read_kernel_str(event->name, sizeof(event->name), ctx->name);
    event->addr = ctx->ip;
    event->size = 0; // Size not available in free event
    event->timestamp = bpf_ktime_get_ns();
    event->sections_count = 0;
    event->module_id = module_id;
    event->severity = 0; // INFO
    
    // Initialize compiler info and hash
    event->compiler_info[0] = '\0';
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        event->sha256_hash[i] = 0;
    }
    
    // Remove module from tracking map
    bpf_map_delete_elem(&loaded_modules, &module_id);
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// Detect unexpected module operations
SEC("kprobe/do_init_module")
int detect_unexpected_load(struct pt_regs *ctx) {
    struct module_event *event;
    __u32 key = 1; // Config key for unexpected event detection
    __u64 *detection_enabled = bpf_map_lookup_elem(&config, &key);
    
    if (!detection_enabled || *detection_enabled == 0)
        return 0;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->event_type = UNEXPECTED_EVENT;
    event->timestamp = bpf_ktime_get_ns();
    event->severity = 1; // WARNING
    bpf_probe_read_kernel_str(event->compiler_info, sizeof(event->compiler_info), "unexpected_module_init");
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
