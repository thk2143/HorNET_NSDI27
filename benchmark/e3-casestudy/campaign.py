class Prop:
    def __init__(self, key, name, expect, note):
        self.key, self.name, self.expect, self.note = key, name, expect, note


class Campaign:
    def __init__(self, nf, obj, entry, world, props):
        self.nf, self.obj, self.entry = nf, obj, entry
        self.world, self.props = world, props

    def label(self, prop):
        return f'{self.nf}_{prop.key}'


CAMPAIGNS = [
    Campaign(
        'fw', 'hxdp/xdp_fw_kern.o', 'xdp_fw_prog',
        'fully symbolic packet and length; tx_port seeded {6:6, 7:7}; '
        'flow_ctx_table EMPTY (cold start); ingress_ifindex symbolic',
        [Prop('q1', 'never_pass_never_tx', 'holds',
              'safety: never hands the packet to the stack, never TXes'),
         Prop('q2', 'non_ip_dropped', 'holds',
              'a non-IPv4 frame is dropped'),
         Prop('q3', 'unsolicited_inbound_dropped', 'holds',
              'nothing gets in on B_PORT without a learned flow'),
         Prop('q4', 'outbound_tcp_redirected', 'holds',
              'TCP from the trusted side is redirected out B_PORT'),
         Prop('q5', 'icmp_dropped', 'holds',
              'a protocol with no L4 flow key is dropped, not forwarded')]),

    Campaign(
        'crab', 'crab/lb_kern.o', 'xdp_prog_simple',
        "IPv4 TCP SYN (flags/dataofs/reserved pinned, ihl NOT) at 1514 bytes; "
        "targets_count/targets_map/macs_map seeded with the three backends; "
        "cpu_rr_idx open, so the round-robin index is symbolic",
        [Prop('q1', 'never_drop_never_redirect', 'holds',
              'safety: translates or forwards, never drops'),
         Prop('q2', 'syn_never_passed', 'violated',
              'a SYN with ihl < 5 never reaches handle_syn and falls out as PASS'),
         Prop('q3', 'target_ip_is_configured', 'holds',
              'a translated packet is addressed to a configured backend'),
         Prop('q4', 'target_mac_is_configured', 'holds',
              'and carries that backend\'s configured MAC'),
         Prop('q5', 'l4_proto_preserved', 'holds',
              'the rewrite does not change the L4 protocol')]),

    Campaign(
        'hercules', 'hercules/redirect_userspace.o',
        'xdp_prog_redirect_userspace',
        'IPv4 at 1514 bytes, everything else symbolic; num_xsks[0] = 1; '
        'xsks_map and local_addr left open',
        [Prop('q1', 'never_drop_never_tx', 'holds',
              'safety: a dispatcher passes or redirects'),
         Prop('q2', 'non_udp_passed', 'holds',
              'SCION rides on UDP, so anything else is the kernel\'s'),
         Prop('q3', 'wrong_udp_port_passed', 'holds',
              'it cannot steal another application\'s UDP traffic'),
         Prop('q4', 'redirect_implies_scion_port', 'holds',
              'anything taken from the kernel was addressed to the SCION port'),
         Prop('q5', 'redirect_implies_udp', 'holds',
              'and was UDP')]),

    Campaign(
        'katran', 'katran/balancer_main.o', 'balancer_ingress',
        'IPv4 at 574 bytes, everything else symbolic; vip_map holds two '
        'services on 10.0.0.1 (80/TCP, 443/UDP); lru_mapping EMPTY (cold '
        'start); the ARRAY maps, ch_rings included, in bounds with free contents',
        [Prop('q1', 'no_redirect_no_abort', 'holds',
              'safety: the return surface is DROP / PASS / TX'),
         Prop('q2', 'tx_is_ipip', 'violated',
              'ICMP echo is answered by katran itself with XDP_TX'),
         Prop('q3', 'encap_hdr_plain_ipv4', 'holds',
              'the outer header is IPv4, no options, unfragmented, TTL 64'),
         Prop('q4', 'encap_src_in_ipip_prefix', 'holds',
              'the IPIP outer source is in katran\'s 172.16/16 prefix'),
         Prop('q5', 'encap_tos_is_default', 'violated',
              'COPY_INNER_PACKET_TOS carries the client\'s TOS into the outer header')]),
]
