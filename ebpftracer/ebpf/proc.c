#define TASK_COMM_LEN	16
#define CLONE_THREAD 	0x00010000

struct proc_event {
    __u32 type;
    __u32 pid;
    __u32 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} proc_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 10240);
} oom_info SEC(".maps");

struct trace_event_raw_task_newtask__stub {
    __u64 unused;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    long unsigned int clone_flags;
};

SEC("tracepoint/task/task_newtask")
int task_newtask(struct trace_event_raw_task_newtask__stub *args)
{
    if (args->clone_flags & CLONE_THREAD) { // skipping threads
        return 0;
    }
    struct proc_event e = {
        .type = EVENT_TYPE_PROCESS_START,
        .pid = args->pid,
    };
    bpf_perf_event_output(args, &proc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

struct trace_event_raw_sched_process_template__stub {
    __u64 unused;
    char comm[TASK_COMM_LEN];
    __u32 pid;
};

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template__stub *args)
{
    __u64 id = bpf_get_current_pid_tgid();
    if (id >> 32 != (__u32)id) { // skipping threads
        return 0;
    }
    struct proc_event e = {
        .type = EVENT_TYPE_PROCESS_EXIT,
        .pid = args->pid,
    };
    if (bpf_map_lookup_elem(&oom_info, &e.pid)) {
        e.reason = EVENT_REASON_OOM_KILL;
        bpf_map_delete_elem(&oom_info, &e.pid);
    }
    bpf_perf_event_output(args, &proc_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

struct trace_event_raw_mark_victim__stub {
    __u64 unused;
    int pid;
};

SEC("tracepoint/oom/mark_victim")
int oom_mark_victim(struct trace_event_raw_mark_victim__stub *args)
{
    __u32 pid = args->pid;
    bpf_map_update_elem(&oom_info, &pid, &pid, BPF_ANY);
    return 0;
}
