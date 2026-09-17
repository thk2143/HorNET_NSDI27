# The specification format

A specification is a JSON file. It states the world the program starts in and
the conditions to decide about it, and hornet answers each condition with a
verdict. Every file under `benchmark/specs/` and
`benchmark/e3-casestudy/specs/` is an example.

```json
{
  "input": { "packet": "Ether()/IP(proto=6)", "context": {"pkt_len": 100},
             "maps": {"vip_map": {"0x0a000001": "0x01000000"}} },
  "exit_conditions": {
    "non_ip_is_passed": {
      "assert": "all",
      "cond": {"or": [{"field": "eth_type", "value": "0x0800"},
                      {"ret": 2}]}
    }
  }
}
```

Keys whose name starts with `_` are notes: never parsed, and never part of a
recorded hash.

## `input` — the world

All three parts are optional; what is left out stays symbolic, which is the
weakest assumption and therefore the strongest result.

| Key | Meaning |
|---|---|
| `packet` | a scapy expression, e.g. `"Ether(type=0x0800)/IP(proto=6)"`. Only the bytes the expression sets are fixed; the rest of the frame stays free. A byte counts as set only when every field contributing to it was assigned |
| `context` | `pkt_len`, `ingress_ifindex`, `rx_queue_index`. `pkt_len` may not be shorter than the packet expression |
| `maps` | `{"<map name>": {"<key>": "<value>"}}`. A map named here is closed: it holds exactly these entries, and `{}` is an empty map. A map not named is open — any contents the program could find |

Map keys and values are read in **memory order**, lowest address first, so the
native integer 3 in a 4-byte value is `"0x03000000"`.

## Conditions

Two sections, and a file may hold either or both:

- `exit_conditions` — decided at every exit the program can reach, where `r0`
  (the XDP action) exists.
- `block_conditions` — decided at one basic block, named by `"block": <n>`.
  `-s info` prints the block numbers. A `ret` atom is not allowed here.

Each condition is `{"assert": "all" | "exists", "cond": <condition>}`:

| `assert` | Question | Verdicts |
|---|---|---|
| `all` | does it hold everywhere it is decided? | `holds` / `violated` |
| `exists` | is there somewhere it holds? | `sat` / `unsat` |

`violated` and `sat` come with a counterexample: the packet bytes, map
contents and helper return values that produce it, and the blocks that run. A
`holds` or `unsat` on a block that no input can reach is reported as
`VACUOUS` — the condition was not really tested.

## Conditions and atoms

A condition is an atom or a tree: `{"and": [...]}`, `{"or": [...]}`,
`{"not": <condition>}`. "A implies B" is written `{"or": [{"not": A}, B]}`.

| Atom | Example | What it says |
|---|---|---|
| packet field | `{"field": "ip_dst", "value": "10.0.0.1"}` | a named header field equals a value |
| packet bytes | `{"offset": 14, "size": 4, "value": "0x45000020"}` | the same, at a raw offset |
| return value | `{"ret": 2}`, `{"ret": 3, "op": "ne"}` | `r0` is (or is not) this XDP action |
| packet length | `{"pkt_len": {"min": 34, "max": 1514}}` | the frame length is in this range |
| context | `{"ctx": "ingress_ifindex", "value": 1}` | a context scalar equals a value |
| map entry | `{"map": "vip_map", "key": "0x0a000001", "value": "0x07000000"}`, or `"contains": false` | what a map holds after the program ran |
| global | `{"bss": "counter", "size": 4, "value": 1}` | a `.bss` symbol holds a value |
| helper return | `{"idx": 223, "helper": "bpf_xdp_adjust_head", "op": "eq", "value": 0}` | what a call site returned; `"returns": "null"` / `"non_null"` for a pointer-returning helper |

Values may be an integer, `"0x..."` hex, dotted IPv4, colon-separated MAC, or
a list of byte values; each must match the width of what it is compared to.
Packet fields are the usual Ethernet/IPv4/TCP/UDP ones at their fixed offsets
(`eth_dst`, `eth_type`, `ip_proto`, `ip_src`, `ip_dst`, `tcp_dport`,
`udp_dport`, …); anything else is written as `offset` + `size`.

A call site is named by `"idx"`, the instruction index that `-s info` prints
for every helper call; naming the `"helper"` alongside it is optional and is
checked against what that instruction actually calls. (E1's case files also
accept `"nth": <k>`, the kth call of that helper in program order, which that
harness resolves to an `idx` before handing the spec to hornet.)

## Writing one

`--spec-init` prints a skeleton for a program — its maps, the packet bytes it
reads and the branches it takes — which is the shortest way to start:

```bash
venv/bin/python -m hornet -i example/katran/balancer_main.o \
    -e balancer_ingress --spec-init draft.json
```
