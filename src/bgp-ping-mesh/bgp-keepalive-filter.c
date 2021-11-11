/**
 * An eBPF TC filter function to identify TCP BGP keep-alive packets
 * (with timestamps) and send them to userspace for processing
 *
 * Note that parsing TCP timestamps in kernel eBPF space is hard, hence
 * this code simply forwards the packets
 */

// #define KBUILD_MODNAME "bgp_keepalive_filter"

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#include <linux/bpf.h>
// #include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define DROP 0  // drop the packet
#define KEEP -1 // keep the packet and send it to userspace returning -1

#define IP_TCP 	 6

int tcp_rtt_filter(struct __sk_buff *skb)
{
    // TC filter programs don't have access to 'data' and 'data_end'
    // void *data_end = (void *)(long)skb->data_end;
    // void *data = (void *)(long)skb->data;

    u8 *cursor = 0;
    struct ethernet_t *eth = cursor_advance(cursor, sizeof(*eth));

    if (eth->type != 0x0800)
       return DROP;

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->nextp != IP_TCP) {
        bpf_trace_printk( "tcp_rtt_filter: Not TCP but %u\n", ip->nextp );
        return DROP;
    }

    u32 ip_header_length = ip->hlen << 2;    // SHL 2 -> *4 multiply

    // check ip header length against minimum
    if (ip_header_length < sizeof(*ip)) {
      bpf_trace_printk("tcp_rtt_filter: invalid IP header length %u\n", ip_header_length );
      return DROP;
    }

    // shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    // int ip_hlen = ip->hlen << 2;
    // tcp = (void*) ip + ip_hlen;
    // if ((void*)(tcp+1) > data_end) return DROP;

    u8 tcp_hlen = tcp->offset << 2;
    if ( tcp_hlen < sizeof(struct tcp_t)+12 ) {
      bpf_trace_printk( "tcp_rtt_filter: tcp_hlen too small to have timestamp option %u<%u\n",
        tcp_hlen, sizeof(struct tcp_t)+12 );
      return DROP;
    }

    // TODO TCP keep-alive request has specific size (17 bytes)
    if (tcp->dst_port == 179 || tcp->src_port == 179) {
      bpf_trace_printk("bgp_rtt_monitor: found BGP packet with timestamps, forwarding bpf_ktime_get_ns=%llu\n", bpf_ktime_get_ns() );
      return KEEP;
    }

    bpf_trace_printk( "tcp_rtt_filter: dropping non-BGP TCP packet\n" );
    return DROP;
}

// char ____license[] __attribute__((section("license"), used)) = "GPL";
