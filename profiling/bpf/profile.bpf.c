// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "profile.bpf.h"
#include "pid.h"
#include "ume.h"

#define PF_KTHREAD 0x00200000

struct global_config_t {
    uint64_t ns_pid_ino;
};

const volatile struct global_config_t global_config;

struct io_state {
    struct sample_key key;
    u64 start;
    u64 weight;
};

#define IO_SAMPLE_INTERVAL_NS 1000000

struct io_sampler {
    u64 next;
    u64 count;
    u64 read_bytes;
    u64 write_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct io_sampler);
    __uint(max_entries, 1);
} io_sampling SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct io_state);
    __uint(max_entries, 16384);
} io_reqs SEC(".maps");

#define IO_REQ_MAX_NS (60ull * 1000000000ull)

static __always_inline struct sample_value *sample_value(struct sample_key *key) {
    struct sample_value *val = bpf_map_lookup_elem(&counts, key);
    if (val) {
        return val;
    }
    struct sample_value zero = {};
    bpf_map_update_elem(&counts, key, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&counts, key);
}

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    u32 tgid = 0;
    current_pid(global_config.ns_pid_ino, &tgid);

    struct sample_key key = {};
    struct sample_value *val;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (tgid == 0 || task == 0) {
        return 0;
    }
    int flags = 0;
    if (pyro_bpf_core_read(&flags, sizeof(flags), &task->flags)) {
        bpf_dbg_printk("failed to read task->flags\n");
        return 0;
    }
    if (flags & PF_KTHREAD) {
        bpf_dbg_printk("skipping kthread %d\n", tgid);
        return 0;
    }

    struct pid_config *config = bpf_map_lookup_elem(&pids, &tgid);
    if (config == NULL) {
        struct pid_config unknown = {
                .type = PROFILING_TYPE_UNKNOWN,
        };
        if (bpf_map_update_elem(&pids, &tgid, &unknown, BPF_NOEXIST)) {
            bpf_dbg_printk("failed to update pids map. probably concurrent update\n");
            return 0;
        }
        struct pid_event event = {
                .op  = OP_REQUEST_UNKNOWN_PROCESS_INFO,
                .pid = tgid
        };
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return 0;
    }

    if (config->type == PROFILING_TYPE_ERROR || config->type == PROFILING_TYPE_UNKNOWN) {
        return 0;
    }

    if (config->type == PROFILING_TYPE_PYTHON) {
        bpf_tail_call(ctx, &progs, PROG_IDX_PYTHON);
        return 0;
    }

    if (config->type == PROFILING_TYPE_FRAMEPOINTERS) {
        key.pid = tgid;
        key.user_stack = bpf_get_stackid(ctx, &stacks, USER_STACKID_FLAGS);

        val = sample_value(&key);
        if (val)
            val->cpu++;
    }
    return 0;
}

SEC("kprobe/submit_bio")
int BPF_KPROBE(submit_bio_enter, struct bio *bio) {
    u32 zero = 0;
    struct io_sampler *sampler = bpf_map_lookup_elem(&io_sampling, &zero);
    if (sampler == NULL) {
        return 0;
    }
    sampler->count++;
    u32 op = BPF_CORE_READ(bio, bi_opf) & 0xff; // REQ_OP_MASK
    u64 size = BPF_CORE_READ(bio, bi_iter.bi_size);
    if (op == 0) { // REQ_OP_READ
        sampler->read_bytes += size;
    } else if (op == 1 || op == 7) { // REQ_OP_WRITE, REQ_OP_ZONE_APPEND; discards and write-zeroes are not data
        sampler->write_bytes += size;
    }
    u64 now = bpf_ktime_get_ns();
    if (now < sampler->next) {
        return 0;
    }
    u64 weight = sampler->count;
    u64 read_bytes = sampler->read_bytes;
    u64 write_bytes = sampler->write_bytes;
    sampler->count = 0;
    sampler->read_bytes = 0;
    sampler->write_bytes = 0;
    sampler->next = now + IO_SAMPLE_INTERVAL_NS;

    u32 tgid = 0;
    current_pid(global_config.ns_pid_ino, &tgid);
    if (tgid == 0) {
        return 0;
    }
    struct pid_config *config = bpf_map_lookup_elem(&pids, &tgid);
    if (config == NULL || (config->type != PROFILING_TYPE_FRAMEPOINTERS && config->type != PROFILING_TYPE_PYTHON)) {
        return 0;
    }
    struct io_state state = {
        .key.pid = tgid,
        .key.user_stack = bpf_get_stackid(ctx, &stacks, USER_STACKID_FLAGS),
        .start = now,
        .weight = weight,
    };
    struct sample_value *val = sample_value(&state.key);
    if (val) {
        val->io_read_bytes += read_bytes;
        val->io_write_bytes += write_bytes;
    }
    u64 id = (u64)bio;
    bpf_map_update_elem(&io_reqs, &id, &state, BPF_ANY);
    return 0;
}

SEC("kprobe/bio_endio")
int BPF_KPROBE(bio_endio_enter, struct bio *bio) {
    u64 id = (u64)bio;
    struct io_state *state = bpf_map_lookup_elem(&io_reqs, &id);
    if (state == NULL) {
        return 0;
    }
    struct sample_key key = state->key;
    u64 weight = state->weight;
    u64 delta = bpf_ktime_get_ns() - state->start;
    bpf_map_delete_elem(&io_reqs, &id);
    if (delta > IO_REQ_MAX_NS) {
        return 0;
    }
    struct sample_value *val = sample_value(&key);
    if (val) {
        val->io_time_ns += delta * weight;
    }
    return 0;
}


SEC("kprobe/disassociate_ctty")
int BPF_KPROBE(disassociate_ctty, int on_exit) {
    if (!on_exit) {
        return 0;
    }
    u32 pid = 0;
    current_pid(global_config.ns_pid_ino, &pid);
    if (pid == 0) {
        return 0;
    }
    bpf_map_delete_elem(&pids, &pid);
    struct pid_event event = {
        .op  = OP_PID_DEAD,
        .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// execve/execveat
SEC("kprobe/exec")
int BPF_KPROBE(exec, void *_) {
    u32 pid = 0;
    current_pid(global_config.ns_pid_ino, &pid);
    if (pid == 0) {
        return 0;
    }
    struct pid_event event = {
            .op  = OP_REQUEST_EXEC_PROCESS_INFO,
            .pid = pid
    };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
