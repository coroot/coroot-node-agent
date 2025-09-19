struct nodejs_proc_stats {
    __u64 event_loop_blocked_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} nodejs_prev_event_loop_iter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} nodejs_current_io_cb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct nodejs_proc_stats));
    __uint(max_entries, 10240);
} nodejs_stats SEC(".maps");

SEC("uprobe/uv_io_poll_exit")
int uv_io_poll_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 timestamp = bpf_ktime_get_ns();
    if ((__u32)pid_tgid != (__u32)pid) {
        return 0;
    }
    bpf_map_update_elem(&nodejs_prev_event_loop_iter, &pid, &timestamp, BPF_ANY);
    return 0;
}

SEC("uprobe/uv_io_poll_enter")
int uv_io_poll_enter(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    if ((__u32)pid_tgid != (__u32)pid) {
        return 0;
    }
    __u64 *prev = bpf_map_lookup_elem(&nodejs_prev_event_loop_iter, &pid);
    if (!prev) {
        return 0;
    }
    __u64 duration = bpf_ktime_get_ns() - *prev;
    bpf_map_delete_elem(&nodejs_prev_event_loop_iter, &pid);
    struct nodejs_proc_stats *stats = bpf_map_lookup_elem(&nodejs_stats, &pid);
    if (!stats) {
        struct nodejs_proc_stats s = {};
        bpf_map_update_elem(&nodejs_stats, &pid, &s, BPF_ANY);
        stats = bpf_map_lookup_elem(&nodejs_stats, &pid);
        if (!stats) {
            return 0;
        }
    }
    __sync_fetch_and_add(&stats->event_loop_blocked_time, duration);
    return 0;
}

SEC("uprobe/uv_io_cb_enter")
int uv_io_cb_enter(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    if ((__u32)pid_tgid != (__u32)pid) {
        return 0;
    }
    __u64 timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&nodejs_current_io_cb, &pid, &timestamp, BPF_ANY);
    return 0;
}

SEC("uprobe/uv_io_cb_exit")
int uv_io_cb_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    if ((__u32)pid_tgid != (__u32)pid) {
        return 0;
    }
    __u64 *start = bpf_map_lookup_elem(&nodejs_current_io_cb, &pid);
    if (!start) {
        return 0;
    }
    __u64 duration = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&nodejs_current_io_cb, &pid);
    struct nodejs_proc_stats *stats = bpf_map_lookup_elem(&nodejs_stats, &pid);
    if (!stats) {
        struct nodejs_proc_stats s = {};
        bpf_map_update_elem(&nodejs_stats, &pid, &s, BPF_ANY);
        stats = bpf_map_lookup_elem(&nodejs_stats, &pid);
        if (!stats) {
            return 0;
        }
    }
    __sync_fetch_and_add(&stats->event_loop_blocked_time, duration);
    return 0;
}
