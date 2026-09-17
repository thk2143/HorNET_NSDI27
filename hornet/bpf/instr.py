from bpf.constants import *


class Instr:
    def __init__(self, idx: int, addr: int, bytecode: bytes = None, nop: bool = False):
        self.idx: int = idx
        self.addr: int = addr

        self.bytecode = bytecode
        self.nop = nop
        self.opcode_class = -1

        if not self.nop:
            self.parse_bytecode()

    def __str__(self):
        if self.nop:
            return f'{self.idx}: nop'
        elif self.opcode_class in (ALU, ALU64):
            op = alu_op_to_str[self.opcode_code]
            s = 'K' if self.opcode_s == S_IMM else 'X'
            dst = f"r{self.dst_reg}"
            src = f'r{self.src_reg}' if self.opcode_s == S_REG else f"{self.imm}"
            return f"{self.idx}: [{op}, {s}, {'ALU' if self.opcode_class == ALU else 'ALU64'}] {dst} {src} / offset={self.offset}"
        elif self.opcode_class in (JMP, JMP32):
            op = jmp_op_to_str[self.opcode_code]
            if self.opcode_code == CALL:
                return f'{self.idx}: [{op}, K, JMP] call {self.imm} / src_reg={self.src_reg}'
            elif self.opcode_code == EXIT:
                return f'{self.idx}: [{op}, K, JMP] exit'
            elif self.opcode_code == JA:
                s = 'K' if self.opcode_s == S_IMM else 'X'
                return f"{self.idx}: [{op}, {s}, {'JMP' if self.opcode_class == JMP else 'JMP32'}] PC += {self.offset if self.opcode_class == JMP else self.imm}"
            s = 'K' if self.opcode_s == S_IMM else 'X'
            dst = f"r{self.dst_reg}"
            src = f'r{self.src_reg}' if self.opcode_s == S_REG else f"{self.imm}"
            return f"{self.idx}: [{op}, {s}, {'JMP' if self.opcode_class == JMP else 'JMP32'}] {dst} {src} / PC += {self.offset}"
        mode = mode_to_str[self.opcode_mode]
        sz = sz_to_str[self.opcode_sz]
        class_str = {LD: 'LD', LDX: 'LDX', ST: 'ST', STX: 'STX'}[self.opcode_class]
        return (f"{self.idx}: [{mode}, {sz}, {class_str}] r{self.dst_reg} r{self.src_reg}"
                f" / offset={self.offset}, imm={self.imm}, wide={self.wide_instr}")

    def parse_bytecode(self):
        bytecode = self.bytecode
        self.opcode = bytecode[0]

        self.opcode_class = self.opcode & OPC_CLASS_MASK

        if self.opcode_class in (ALU, ALU64, JMP, JMP32):
            self.opcode_s    = (self.opcode & OPC_S_MASK)    >> 3
            self.opcode_code = (self.opcode & OPC_CODE_MASK) >> 4

        if self.opcode_class in (LD, LDX, ST, STX):
            self.opcode_sz   = (self.opcode & OPC_SZ_MASK)   >> 3
            self.opcode_mode = (self.opcode & OPC_MODE_MASK)  >> 5

        self.src_reg = (bytecode[1] >> 4) & 0x0F
        self.dst_reg =  bytecode[1]       & 0x0F

        self.offset = int.from_bytes(bytecode[2:4], byteorder='little', signed=True)
        self.imm    = int.from_bytes(bytecode[4:8], byteorder='little', signed=True)

        self.wide_instr = False
        if bytecode[0] == 0x18:
            self.wide_instr = True
            self.next_imm = int.from_bytes(bytecode[8:16], byteorder='little')

        self.relocated = False
        self.rodata_offset = None
        self.bss_offset = 0

    def set_reloc_tag(self, tag, region=0, rodata_offset=None, bss_offset=0):
        self.relocated = True
        self.reloc_tag = tag
        self.reloc_region = region
        self.rodata_offset = rodata_offset
        self.bss_offset = bss_offset

    def is_load(self):   return self.opcode_class in (LD, LDX)
    def is_store(self):  return self.opcode_class in (ST, STX)
    def is_alu(self):    return self.opcode_class in (ALU, ALU64)
    def is_jump(self):   return self.opcode_class in (JMP, JMP32)
    def is_call(self):   return self.is_jump() and self.opcode_code == CALL
    def is_tail_call(self):
        return (self.is_call() and self.src_reg == 0
                and self.imm == HELPER_TAIL_CALL)
    def is_branch(self): return self.is_jump() and self.opcode_code not in (JA, CALL, EXIT)
    def is_exit(self):   return self.is_jump() and self.opcode_code == EXIT
    def jump_offset(self):
        if self.opcode_class == JMP32 and self.opcode_code == JA:
            return self.imm
        return self.offset
