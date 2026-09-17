from __future__ import annotations

from track.block import Block
from bpf.constants import JA, CALL, EXIT, LD, IMM
from bpf.instr import Instr


def _tail_target(instrs: list[Instr], start: int, end: int, progs: list):
    callees = [r for r in progs if not r.is_main]
    if not callees:
        raise ValueError(
            f"instruction {end} is a bpf_tail_call but no callee was given -- "
            "pass --tail OBJ:ENTRY@SLOT")

    map_id = None
    for i in range(end - 1, start - 1, -1):
        ins = instrs[i]
        if (ins.opcode_class == LD and ins.opcode_mode == IMM
                and ins.dst_reg == 2 and getattr(ins, 'relocated', False)
                and ins.reloc_region == 0):
            map_id = ins.reloc_tag
            break

    if map_id is not None:
        hit = [r for r in callees if r.map_id == map_id]
        if not hit:
            raise ValueError(
                f"instruction {end}: bpf_tail_call into map{map_id}, which no "
                "--tail target was loaded into")
        return hit[0]
    if len(callees) == 1:
        return callees[0]
    raise ValueError(
        f"instruction {end}: cannot tell which prog array this bpf_tail_call "
        f"uses (r2 comes from another block) and there are {len(callees)} "
        "callees to choose from")


def get_next_block_no(blocks: list[Block], untraced: set[int]) -> int:
    for item in untraced:
        if all(p not in untraced for p in blocks[item].preds):
            return item
    print(f"get_next_block_no: cannot find next block to trace: {untraced}")
    exit(1)

class Cfg_builder:
    def __init__(self, instrs: list[Instr], progs: list = None,
                 verbose: bool = False):
        self.instrs = instrs
        self.progs = progs or []
        self.verbose = verbose

    def build_cfg(self) -> tuple[list[Block], dict[int, list[int]], dict[int, int]]:
        instrs = self.instrs
        progs = self.progs
        verbose = self.verbose

        blocks: list[Block] = []
        n = len(instrs)

        leaders: set[int] = {0}
        leaders.update(r.start for r in progs)
        for i in range(n):
            instr = instrs[i]
            if instr.is_jump():
                if instr.is_exit():
                    if i + 1 < n:
                        leaders.add(i + 1)
                elif instr.is_call():
                    if instr.is_tail_call() and i + 1 < n:
                        leaders.add(i + 1)
                else:
                    target = i + 1 + instr.jump_offset()
                    if 0 <= target < n:
                        leaders.add(target)
                    if i + 1 < n:
                        leaders.add(i + 1)

        sorted_leaders = sorted(leaders)
        for i, start in enumerate(sorted_leaders):
            end = sorted_leaders[i + 1] - 1 if i + 1 < len(sorted_leaders) else n - 1
            blocks.append(Block(i, start, end))

        block_start_map: dict[int, int] = {block.start: idx for idx, block in enumerate(blocks)}
        cfg: dict[int, list[int]] = {i: [] for i in range(len(blocks))}

        for block in blocks:
            i = block.num
            end = block.end
            last_instr = instrs[end]

            if last_instr.is_jump():
                code = last_instr.opcode_code
                if code == JA:
                    target = end + 1 + last_instr.jump_offset()
                    assert target in block_start_map
                    succ = block_start_map[target]
                    cfg[i].append(succ)
                    block.succ_t = succ
                    blocks[succ].preds.append(i)
                    block.jump = True
                elif code == CALL:
                    if last_instr.is_tail_call():
                        callee = _tail_target(instrs, block.start, end, progs)
                        block.branch = True
                        succ = block_start_map[callee.start]
                        cfg[i].append(succ)
                        block.succ_t = succ
                        blocks[succ].preds.append(i)
                    target = end + 1
                    assert target in block_start_map
                    succ = block_start_map[target]
                    cfg[i].append(succ)
                    block.succ_f = succ
                    blocks[succ].preds.append(i)
                elif code == EXIT:
                    block.exit = True
                else:
                    block.branch = True
                    target = end + 1 + last_instr.offset
                    if target in block_start_map:
                        succ = block_start_map[target]
                        cfg[i].append(succ)
                        block.succ_t = succ
                        blocks[succ].preds.append(i)
                    else:
                        print("build_cfg: conditional jump target not found in block_start_map")
                        exit(1)
                    if end + 1 in block_start_map:
                        succ = block_start_map[end + 1]
                        assert succ == i + 1, "build_cfg: fallthrough block is not next block"
                        cfg[i].append(succ)
                        block.succ_f = succ
                        blocks[succ].preds.append(i)
                    else:
                        print("build_cfg: fallthrough target not found in block_start_map")
                        exit(1)
            else:
                if end + 1 in block_start_map:
                    succ = block_start_map[end + 1]
                    cfg[i].append(succ)
                    block.succ_f = succ
                    blocks[succ].preds.append(i)

        for region in progs:
            region.entry_block = block_start_map[region.start]
            if region.entry_block != 0:
                blocks[region.entry_block].prog_entry = region

        if verbose:
            print("Basic blocks:")
            for block in blocks:
                print(f"  Block {block.num}: [{block.start}, {block.end}]")
            print("CFG:")
            for k, v in cfg.items():
                print(f"  Block {k} -> {v}")

        return blocks, cfg, block_start_map
