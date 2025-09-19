struct python_proc_stats {
    __u64 thread_lock_wait_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct python_proc_stats));
    __uint(max_entries, 10240);
} python_stats SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 10240);
} python_thread_locks SEC(".maps");

SEC("uprobe/pthread_cond_timedwait_enter")
int pthread_cond_timedwait_enter(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&python_thread_locks, &pid_tgid, &timestamp, BPF_ANY);
    return 0;
}

SEC("uprobe/pthread_cond_timedwait_exit")
int pthread_cond_timedwait_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *timestamp = bpf_map_lookup_elem(&python_thread_locks, &pid_tgid);
    if (!timestamp) {
        return 0;
    }
    __u64 duration = bpf_ktime_get_ns() - *timestamp;
    bpf_map_delete_elem(&python_thread_locks, &pid_tgid);
    __u64 pid = pid_tgid >> 32;
    struct python_proc_stats *stats = bpf_map_lookup_elem(&python_stats, &pid);
    if (!stats) {
        struct python_proc_stats s = {};
        bpf_map_update_elem(&python_stats, &pid, &s, BPF_ANY);
        stats = bpf_map_lookup_elem(&python_stats, &pid);
        if (!stats) {
            return 0;
        }
    }
    __sync_fetch_and_add(&stats->thread_lock_wait_time, duration);
    return 0;
}
