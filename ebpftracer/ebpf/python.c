struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} python_thread_events SEC(".maps");

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

struct python_thread_event {
    __u32 type;
    __u32 pid;
    __u64 duration;
};

SEC("uprobe/pthread_cond_timedwait_exit")
int pthread_cond_timedwait_exit(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *timestamp = bpf_map_lookup_elem(&python_thread_locks, &pid_tgid);
    if (!timestamp) {
        return 0;
    }
    struct python_thread_event e = {
        .type = EVENT_TYPE_PYTHON_THREAD_LOCK,
        .pid = pid_tgid >> 32,
        .duration = bpf_ktime_get_ns()-*timestamp,
    };
    bpf_perf_event_output(ctx, &python_thread_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
