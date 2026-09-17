# The E1 cases

54 small XDP programs, written for this evaluation, that ask whether hornet
answers what the kernel answers. 250 checks, all PASS.

## One case

```
cases/<stem>/
  runs.json      concrete runs, answered by the KERNEL (../oracle/kernel.json)
  <prop>.json    ordinary hornet specs, answered BY HAND in `_expect`
objs/<stem>.o    the compiled program
```

Either file may be absent. `runs.json` gives each run a packet, optionally map
contents, an ingress context and `observe` (what to read back besides `r0`);
`runs.schema.json` is the schema. `_`-prefixed keys are notes: never parsed,
never hashed, so editing one cannot make a recorded answer stale.

A **run** is checked by asking the solver about the value the kernel observed:
it must hold at some reachable exit (otherwise the check is WRONG — hornet
rules out what the kernel did) and at every reachable exit (otherwise
UNDETERMINED — sound but imprecise). A **spec** is checked against the verdict
`_expect` states, derived by hand from the program and the kernel's helper
code. `baseline.json` records the status of every check; a status that changes
is a failure until it is re-recorded.

Two mechanisms appear in the table below:

- `pin` — a run may fix a helper outcome the kernel guarantees for that input
  but hornet leaves free, e.g. that `bpf_xdp_adjust_head` succeeds on a frame
  long enough for it.
- `nondet` — for helpers whose result the kernel does not repeat (a random
  number, a clock, the current pid), the kernel's distinct samples are recorded
  and the check asks that hornet admits every one of them.

## The cases

The helper cases together call all 22 helpers the tracker models.

| Case | Checked behavior | Runs / specs / checks |
|---|---|---|
| **map** — map semantics | | |
| `map_hash_lookup` | `HASH` lookup, null check, closed vs. open world | 4 / 2 / 11 |
| `map_open_closed_world` | initial contents: fresh `HASH` empty, `ARRAY` full | 2 / 2 / 14 |
| `map_array_pkt_key` | packet-derived `ARRAY` index | 3 / 1 / 5 |
| `map_two_maps_btf` | two maps in one object | 3 / 0 / 7 |
| `map_btf_mixed_defs` | BTF map definitions of different sizes | 1 / 0 / 1 |
| `map_atomic_add_fetch` | atomic add and fetch on a map value | 2 / 0 / 2 |
| **helper** — helper semantics | | |
| `helper_adjust_head_len` | frame growth by `bpf_xdp_adjust_head` | 2 / 1 / 6 |
| `helper_adjust_head_shrink` | VLAN tag removed by `bpf_xdp_adjust_head` | 3 / 1 / 4 |
| `helper_adjust_tail` | frame shrink by `bpf_xdp_adjust_tail` (pinned) | 1 / 0 / 2 |
| `helper_adjust_meta` | metadata reserved by `bpf_xdp_adjust_meta` (pinned) | 1 / 0 / 1 |
| `helper_xdp_buff_len` | `bpf_xdp_get_buff_len` is the frame length, not a free value | 2 / 0 / 2 |
| `helper_redirect_map_devmap` | `DEVMAP` redirect | 3 / 2 / 9 |
| `helper_redirect_flags0` | `bpf_redirect` | 2 / 1 / 3 |
| `helper_redirect_flags_nonzero` | redirect flags | 1 / 0 / 1 |
| `helper_map_update_noexist` | map update flags | 2 / 0 / 4 |
| `helper_map_update_capacity` | update on a full map | 1 / 0 / 2 |
| `helper_map_update_retval` | branching on a map update's return value | 0 / 1 / 2 |
| `helper_multi_callsite` | several helper call sites in one program (`nondet`) | 2 / 1 / 6 |
| `helper_csum_diff` | `bpf_csum_diff` | 1 / 0 / 1 |
| `helper_perf_event_output` | `bpf_perf_event_output` leaves the decision alone | 2 / 0 / 2 |
| `helper_prandom` | `bpf_get_prandom_u32`, read as u32 (`nondet`) | 1 / 0 / 1 |
| `helper_pid_tgid` | `bpf_get_current_pid_tgid` (`nondet`) | 1 / 0 / 1 |
| `helper_uid_gid` | `bpf_get_current_uid_gid` (`nondet`) | 1 / 0 / 1 |
| `helper_numa_node` | `bpf_get_numa_node_id` (`nondet`) | 1 / 0 / 1 |
| `helper_clock_family` | `bpf_jiffies64` and `ktime_get_{boot,coarse,tai}_ns` (`nondet`) | 1 / 0 / 1 |
| **mem** — the XDP memory model | | |
| `mem_pkt_bounds_forms` | the four forms of a packet-bounds check | 3 / 1 / 5 |
| `mem_pkt_wide_offset` | packet access past offset 255 | 2 / 1 / 6 |
| `mem_ctx_scalars` | `xdp_md` context fields | 2 / 1 / 4 |
| `mem_bss_zero_init` | `.bss` starts at zero | 2 / 0 / 4 |
| `mem_bss_two_globals` | two `.bss` globals are distinct objects | 2 / 0 / 6 |
| `mem_bss_nonstatic_global` | a non-static `.bss` global | 1 / 0 / 2 |
| `mem_rodata_table` | a `.rodata` constant table | 3 / 0 / 3 |
| **join** — state merging | | |
| `join_scalar_phi` | scalars at a join | 3 / 1 / 5 |
| `join_pkt_offset_phi` | packet offsets at a join | 4 / 1 / 5 |
| `join_map_key_phi` | map keys at a join | 3 / 1 / 5 |
| `join_map_value_ptr_phi` | map-value pointers at a join | 3 / 0 / 3 |
| `join_pkt_write_sibling` | packet writes on sibling paths | 2 / 1 / 7 |
| **raw** — read-after-write | | |
| `raw_pkt_write_read` | packet write then read | 3 / 1 / 10 |
| `raw_pkt_var_off` | packet access at a variable offset | 2 / 1 / 6 |
| `raw_pkt_order_same_block` | read/write ordering inside one block | 2 / 1 / 5 |
| `raw_map_value_write_read` | map-value write then lookup | 2 / 1 / 6 |
| `raw_map_update_lookup` | update then lookup | 2 / 1 / 9 |
| `raw_map_delete_lookup` | delete then lookup | 3 / 1 / 9 |
| `raw_map_write_keys_disjoint` | accesses under different keys | 2 / 1 / 8 |
| `raw_map_delete_write_store` | write through a deleted map pointer | 1 / 0 / 2 |
| `raw_bss_var_off` | `.bss` access at a variable offset | 2 / 0 / 4 |
| `raw_lookup_update_order` | lookup followed by update/delete | 2 / 0 / 4 |
| `raw_atomic_add_map_fold` | atomic add then map read | 1 / 0 / 2 |
| **pipe** — NF pipelines | | |
| `pipe_arp_antispoof` | ARP parsing and `HASH` lookup | 5 / 2 / 11 |
| `pipe_vlan_strip` | VLAN strip and head adjustment | 3 / 1 / 4 |
| `pipe_flow_counter_redirect` | flow counting and redirect | 4 / 0 / 6 |
| `pipe_tailcall_index` | tail call through a `PROG_ARRAY` | 3 / 1 / 10 |
| `pipe_tailcall_after_adjust` | tail call after head adjustment | 2 / 1 / 4 |
| `pipe_tailcall_blocklist` | tail call into a callee with its own map | 2 / 1 / 5 |

Totals: map 6 cases / 40 checks, helper 19 / 50, mem 7 / 30, join 5 / 25,
raw 11 / 65, pipe 6 / 40.

## The kernel answers

`../oracle/kernel.json` holds what the kernel returned for every run, recorded
once with `BPF_PROG_TEST_RUN` (`../oracle/record.py`, the only privileged step
in E1) and checked against the object and run it was recorded for, by hash. An
ordinary E1 run only reads that file and needs no privileges.
