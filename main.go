package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Opcodes for 64-bit ALU instructions
const (
	ALU64_ADD_IMM  = 0x07
	ALU64_ADD_REG  = 0x0f
	ALU64_SUB_IMM  = 0x17
	ALU64_SUB_REG  = 0x1f
	ALU64_MUL_IMM  = 0x27
	ALU64_MUL_REG  = 0x2f
	ALU64_DIV_IMM  = 0x37
	ALU64_DIV_REG  = 0x3f
	ALU64_OR_IMM   = 0x47
	ALU64_OR_REG   = 0x4f
	ALU64_AND_IMM  = 0x57
	ALU64_AND_REG  = 0x5f
	ALU64_LSH_IMM  = 0x67
	ALU64_LSH_REG  = 0x6f
	ALU64_RSH_IMM  = 0x77
	ALU64_RSH_REG  = 0x7f
	ALU64_NEG      = 0x87
	ALU64_MOD_IMM  = 0x97
	ALU64_MOD_REG  = 0x9f
	ALU64_XOR_IMM  = 0xa7
	ALU64_XOR_REG  = 0xaf
	ALU64_MOV_IMM  = 0xb7
	ALU64_MOV_REG  = 0xbf
	ALU64_ARSH_IMM = 0xc7
	ALU64_ARSH_REG = 0xcf
)

// Opcodes for Byteswap instructions
const (
	BYTESWAP_LE16 = 0xd4
	BYTESWAP_LE32 = 0xd4
	BYTESWAP_LE64 = 0xd4
	BYTESWAP_BE16 = 0xdc
	BYTESWAP_BE32 = 0xdc
	BYTESWAP_BE64 = 0xdc
)

// Opcodes for Memory instructions
const (
	MEM_LDDW    = 0x18
	MEM_LDABSW  = 0x20
	MEM_LDABSH  = 0x28
	MEM_LDABSB  = 0x30
	MEM_LDABSDW = 0x38
	MEM_LDINDW  = 0x40
	MEM_LDINDH  = 0x48
	MEM_LDINDB  = 0x50
	MEM_LDINDDW = 0x58
	MEM_LDXW    = 0x61
	MEM_LDXH    = 0x69
	MEM_LDXB    = 0x71
	MEM_LDXDW   = 0x79
	MEM_STW     = 0x62
	MEM_STH     = 0x6a
	MEM_STB     = 0x72
	MEM_STDW    = 0x7a
	MEM_STXW    = 0x63
	MEM_STXH    = 0x6b
	MEM_STXB    = 0x73
	MEM_STXDW   = 0x7b
)

// Opcodes for Branch instructions
const (
	BRANCH_JA       = 0x05
	BRANCH_JEQ_IMM  = 0x15
	BRANCH_JEQ_REG  = 0x1d
	BRANCH_JGT_IMM  = 0x25
	BRANCH_JGT_REG  = 0x2d
	BRANCH_JGE_IMM  = 0x35
	BRANCH_JGE_REG  = 0x3d
	BRANCH_JLT_IMM  = 0xa5
	BRANCH_JLT_REG  = 0xad
	BRANCH_JLE_IMM  = 0xb5
	BRANCH_JLE_REG  = 0xbd
	BRANCH_JSET_IMM = 0x45
	BRANCH_JSET_REG = 0x4d
	BRANCH_JNE_IMM  = 0x55
	BRANCH_JNE_REG  = 0x5d
	BRANCH_JSGT_IMM = 0x65
	BRANCH_JSGT_REG = 0x6d
	BRANCH_JSGE_IMM = 0x75
	BRANCH_JSGE_REG = 0x7d
	BRANCH_JSLT_IMM = 0xc5
	BRANCH_JSLT_REG = 0xcd
	BRANCH_JSLE_IMM = 0xd5
	BRANCH_JSLE_REG = 0xdd
	BRANCH_CALL     = 0x85
	BRANCH_EXIT     = 0x95
)

// eBPF Instruction format
// +----------------+----------------+----------------+---------------+
// | 8-bit Opcode   | 4-bit  Dest    | 4-bit  Src     | 16-bit Offset |
// +----------------+----------------+----------------+---------------+
// | 32-bit Immediate Value                                           |
// +------------------------------------------------------------------+

// eBPF Instruction
type Instruction struct {
	Opcode uint8
	Dst    uint8
	Src    uint8
	Offset int16
	Imm    int32
}

// Interpreter state

type State struct {
	Memory []byte
	Regs   [11]int64
	PC     int
}

const MemorySize = 65536 // 64KB for demonstration purposes

func NewState() *State {
	return &State{
		Memory: make([]byte, MemorySize),
	}
}

func (s *State) storeWord(address int64, value int32) error {
	if address < 0 || address+4 > int64(len(s.Memory)) {
		return errors.New("memory access out of bounds")
	}
	binary.LittleEndian.PutUint32(s.Memory[address:address+4], uint32(value))
	return nil
}

func (s *State) storeHalfWord(address int64, value int16) error {
	if address < 0 || address+2 > int64(len(s.Memory)) {
		return errors.New("memory access out of bounds")
	}
	binary.LittleEndian.PutUint16(s.Memory[address:address+2], uint16(value))
	return nil
}

func (s *State) storeByte(address int64, value int8) error {
	if address < 0 || address+1 > int64(len(s.Memory)) {
		return errors.New("memory access out of bounds")
	}
	s.Memory[address] = byte(value)
	return nil
}

func (s *State) storeDoubleWord(address int64, value int64) error {
	if address < 0 || address+8 > int64(len(s.Memory)) {
		return errors.New("memory access out of bounds")
	}
	binary.LittleEndian.PutUint64(s.Memory[address:address+8], uint64(value))
	return nil
}

func (s *State) loadWord(address int64) int64 {
	if address < 0 || address+4 > int64(len(s.Memory)) {
		return 0
	}
	return int64(binary.LittleEndian.Uint32(s.Memory[address : address+4]))
}

func (s *State) loadHalfWord(address int64) int64 {
	if address < 0 || address+2 > int64(len(s.Memory)) {
		return 0
	}
	return int64(int16(binary.LittleEndian.Uint16(s.Memory[address : address+2])))
}

func (s *State) loadByte(address int64) int64 {
	if address < 0 || address+1 > int64(len(s.Memory)) {
		return 0
	}
	return int64(int8(s.Memory[address]))
}

func (s *State) loadDoubleWord(address int64) int64 {
	if address < 0 || address+8 > int64(len(s.Memory)) {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(s.Memory[address : address+8]))
}

// Execute an eBPF instruction
func (s *State) Execute(instr Instruction) error {
	switch instr.Opcode {
	case ALU64_ADD_IMM:
		s.Regs[instr.Dst] += int64(instr.Imm)
	case ALU64_ADD_REG:
		s.Regs[instr.Dst] += s.Regs[instr.Src]
	case ALU64_SUB_IMM:
		s.Regs[instr.Dst] -= int64(instr.Imm)
	case ALU64_SUB_REG:
		s.Regs[instr.Dst] -= s.Regs[instr.Src]
	case ALU64_MUL_IMM:
		s.Regs[instr.Dst] *= int64(instr.Imm)
	case ALU64_MUL_REG:
	case ALU64_DIV_IMM:
		s.Regs[instr.Dst] /= int64(instr.Imm)
	case ALU64_DIV_REG:
		s.Regs[instr.Dst] /= s.Regs[instr.Src]
	case ALU64_OR_IMM:
		s.Regs[instr.Dst] |= int64(instr.Imm)
	case ALU64_OR_REG:
		s.Regs[instr.Dst] |= s.Regs[instr.Src]
	case ALU64_AND_IMM:
		s.Regs[instr.Dst] &= int64(instr.Imm)
	case ALU64_AND_REG:
		s.Regs[instr.Dst] &= s.Regs[instr.Src]
	case ALU64_LSH_IMM:
		s.Regs[instr.Dst] <<= uint64(instr.Imm)
	case ALU64_LSH_REG:
		s.Regs[instr.Dst] <<= uint64(s.Regs[instr.Src])
	case ALU64_RSH_IMM:
		s.Regs[instr.Dst] >>= uint64(instr.Imm)
	case ALU64_RSH_REG:
		s.Regs[instr.Dst] >>= uint64(s.Regs[instr.Src])
	case ALU64_NEG:
		s.Regs[instr.Dst] = -s.Regs[instr.Dst]
	case ALU64_MOD_IMM:
		s.Regs[instr.Dst] %= int64(instr.Imm)
	case ALU64_MOD_REG:
		s.Regs[instr.Dst] %= s.Regs[instr.Src]
	case ALU64_XOR_IMM:
		s.Regs[instr.Dst] ^= int64(instr.Imm)
	case ALU64_XOR_REG:
		s.Regs[instr.Dst] ^= s.Regs[instr.Src]
	case ALU64_MOV_IMM:
		s.Regs[instr.Dst] = int64(instr.Imm)
	case ALU64_MOV_REG:
		fmt.Println("MOV_REG", instr.Dst, instr.Src)
		s.Regs[instr.Dst] = s.Regs[instr.Src]
	case ALU64_ARSH_IMM:
		s.Regs[instr.Dst] = int64(uint64(s.Regs[instr.Dst]) >> uint64(instr.Imm))
	case ALU64_ARSH_REG:
		s.Regs[instr.Dst] = int64(uint64(s.Regs[instr.Dst]) >> uint64(s.Regs[instr.Src]))

		// Memory instructions
	case MEM_LDDW:
		s.Regs[instr.Dst] = int64(instr.Imm)
	case MEM_LDXW:
		s.Regs[instr.Dst] = s.loadWord(s.Regs[instr.Src] + int64(instr.Offset))
	case MEM_LDXH:
		s.Regs[instr.Dst] = s.loadHalfWord(s.Regs[instr.Src] + int64(instr.Offset))
	case MEM_LDXB:
		s.Regs[instr.Dst] = s.loadByte(s.Regs[instr.Src] + int64(instr.Offset))
	case MEM_LDXDW:
		s.Regs[instr.Dst] = s.loadDoubleWord(s.Regs[instr.Src] + int64(instr.Offset))
	case MEM_STW:
		s.storeWord(s.Regs[instr.Dst]+int64(instr.Offset), instr.Imm)
	case MEM_STH:
		s.storeHalfWord(s.Regs[instr.Dst]+int64(instr.Offset), int16(instr.Imm))
	case MEM_STB:
		s.storeByte(s.Regs[instr.Dst]+int64(instr.Offset), int8(instr.Imm))
	case MEM_STDW:
		s.storeDoubleWord(s.Regs[instr.Dst]+int64(instr.Offset), int64(instr.Imm))
	case MEM_STXW:
		s.storeWord(s.Regs[instr.Dst]+int64(instr.Offset), int32(s.Regs[instr.Src]))
	case MEM_STXH:
		s.storeHalfWord(s.Regs[instr.Dst]+int64(instr.Offset), int16(s.Regs[instr.Src]))
	case MEM_STXB:
		s.storeByte(s.Regs[instr.Dst]+int64(instr.Offset), int8(s.Regs[instr.Src]))
	case MEM_STXDW:
		s.storeDoubleWord(s.Regs[instr.Dst]+int64(instr.Offset), s.Regs[instr.Src])

	case BRANCH_JA:
		s.PC += int(instr.Offset)
	case BRANCH_JEQ_IMM:
		if s.Regs[instr.Dst] == int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JEQ_REG:
		if s.Regs[instr.Dst] == s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JGT_IMM:
		if s.Regs[instr.Dst] > int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JGT_REG:
		if s.Regs[instr.Dst] > s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JGE_IMM:
		if s.Regs[instr.Dst] >= int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JGE_REG:
		if s.Regs[instr.Dst] >= s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JLT_IMM:
		if s.Regs[instr.Dst] < int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JLT_REG:
		if s.Regs[instr.Dst] < s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JLE_IMM:
		if s.Regs[instr.Dst] <= int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JLE_REG:
		if s.Regs[instr.Dst] <= s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSET_IMM:
		if s.Regs[instr.Dst]&int64(instr.Imm) != 0 {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSET_REG:
		if s.Regs[instr.Dst]&s.Regs[instr.Src] != 0 {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JNE_IMM:
		if s.Regs[instr.Dst] != int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JNE_REG:
		if s.Regs[instr.Dst] != s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSGT_IMM:
		if s.Regs[instr.Dst] > int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSGT_REG:
		if s.Regs[instr.Dst] > s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSGE_IMM:
		if s.Regs[instr.Dst] >= int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSGE_REG:
		if s.Regs[instr.Dst] >= s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSLT_IMM:
		if s.Regs[instr.Dst] < int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSLT_REG:
		if s.Regs[instr.Dst] < s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSLE_IMM:
		if s.Regs[instr.Dst] <= int64(instr.Imm) {
			s.PC += int(instr.Offset)
		}
	case BRANCH_JSLE_REG:
		if s.Regs[instr.Dst] <= s.Regs[instr.Src] {
			s.PC += int(instr.Offset)
		}
	case BRANCH_CALL:
		s.Regs[8] = int64(s.PC + 1)
		s.PC += int(instr.Offset)
	case BRANCH_EXIT:
		return errors.New("exit")

	default:
		fmt.Printf("Unsupported opcode: %d\n", instr.Opcode)
		return errors.New("unsupported opcode")
	}
	return nil
}

// Interpret an eBPF program
func Interpret(bytecode []byte) {

	program := make([]Instruction, len(bytecode)/8)
	for i := 0; i < len(bytecode); i += 8 {

		insn := Instruction{
			Opcode: bytecode[i],
			Dst:    bytecode[i+1] & 0x0F,
			Src:    (bytecode[i+1] >> 4) & 0x0F,
			Offset: int16(bytecode[i+2]) | int16(bytecode[i+3])<<8,
			Imm:    int32(bytecode[i+4]) | int32(bytecode[i+5])<<8 | int32(bytecode[i+6])<<16 | int32(bytecode[i+7])<<24,
		}

		// Store instruction in program memory
		program[i/8] = insn
	}

	state := State{}
	for state.PC < len(program) {

		instr := program[state.PC]
		err := state.Execute(instr)
		if err != nil {
			fmt.Println("Error:", err)
			break
		}
		state.PC++
	}

	// print registers
	fmt.Println("Registers:")
	for i, reg := range state.Regs {
		fmt.Printf("R%d: %d\n", i, reg)
	}

}

func main() {

	bytecode :=
		[]byte{
			// opcode      [dst+src]  [offset]	[imm]
			ALU64_MOV_IMM, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // r1 = 5
			ALU64_MOV_IMM, 0x02, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, // r2 = 9
			ALU64_ADD_REG, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = r1 + r2
			ALU64_MOV_REG, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = r1
			ALU64_SUB_IMM, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // r0 = r0 - 3
			BRANCH_EXIT, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
		}

	Interpret(bytecode)
}
