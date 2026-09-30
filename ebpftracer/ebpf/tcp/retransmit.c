struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_retransmit_events SEC(".maps");

struct trace_event_raw_tcp_event_sk_skb__stub {
    __u64 unused;
#if defined(__CTX_EXTRA_PADDING)
    __u64 unused2;
#endif
    void *sbkaddr;
    void *skaddr;
#if __KERNEL_FROM >= 420
    int state;
#endif
    __u16 sport;
    __u16 dport;
#if __KERNEL_FROM >= 512
    __u16 family;
#endif
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

#if __KERNEL_FROM >= 416
SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb__stub *args)
{
    struct tcp_event e = {
        .type = EVENT_TYPE_TCP_RETRANSMIT,
        .sport = args->sport,
        .dport = args->dport,
    };
    __builtin_memcpy(&e.saddr, &args->saddr_v6, sizeof(e.saddr));
    __builtin_memcpy(&e.daddr, &args->daddr_v6, sizeof(e.daddr));

    bpf_perf_event_output(args, &tcp_retransmit_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}
#else
SEC("kprobe/tcp_retransmit_skb")
int tcp_retransmit_skb(struct pt_regs *ctx)
{
    struct trace_event_raw_inet_sock_set_state__stub args = {};
    if (read_sock((void *)PT_REGS_PARM1(ctx), &args) < 0) {
        return 0;
    }
    struct tcp_event e = {
        .type = EVENT_TYPE_TCP_RETRANSMIT,
        .sport = args.sport,
        .dport = args.dport,
    };
    __builtin_memcpy(&e.saddr, &args.saddr_v6, sizeof(e.saddr));
    __builtin_memcpy(&e.daddr, &args.daddr_v6, sizeof(e.daddr));

    bpf_perf_event_output(ctx, &tcp_retransmit_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}
#endif
