#include <stdlib.h>

#define LE

#include "codec.h"

static int opcode_buffer_prepared;
static unsigned int opcode_buffer[NUM_OPTION];

int LookUpSpecial(union uinstr instr);

void PrepareSpecial(union uinstr instr);

int LookUpRegImm(union uinstr instr);

void PrepareRegImm(union uinstr instr);

int LookUpMMI(union uinstr instr);

void PrepareMMI(union uinstr instr);

int LookUpPMFHL(union uinstr instr);

void PreparePMFHL(union uinstr instr);

int LookUpMMI0(union uinstr instr);

void PrepareMMI0(union uinstr instr);

int LookUpMMI1(union uinstr instr);

void PrepareMMI1(union uinstr instr);

int LookUpMMI2(union uinstr instr);

void PrepareMMI2(union uinstr instr);

int LookUpMMI3(union uinstr instr);

void PrepareMMI3(union uinstr instr);

int LookUpCOP0(union uinstr instr);

void PrepareCOP0(union uinstr instr);

int LookUpMF0(union uinstr instr);

void PrepareMF0(union uinstr instr);

int LookUpMT0(union uinstr instr);

void PrepareMT0(union uinstr instr);

int LookUpMF0DBG(union uinstr instr);

void PrepareMF0DBG(union uinstr instr);

int LookUpMT0DBG(union uinstr instr);

void PrepareMT0DBG(union uinstr instr);

int LookUpMF0PREF(union uinstr instr);

void PrepareMF0PREF(union uinstr instr);

int LookUpMT0PREF(union uinstr instr);

void PrepareMT0PREF(union uinstr instr);

int LookUpBC0(union uinstr instr);

void PrepareBC0(union uinstr instr);

int LookUpC0(union uinstr instr);

void PrepareC0(union uinstr instr);

int LookUpCOP1(union uinstr instr);

void PrepareCOP1(union uinstr instr);

int LookUpBC1(union uinstr instr);

void PrepareBC1(union uinstr instr);

int LookUpS(union uinstr instr);

void PrepareS(union uinstr instr);

int LookUpD(union uinstr instr);

void PrepareD(union uinstr instr);

int LookUpW(union uinstr instr);

void PrepareW(union uinstr instr);

int LookUpL(union uinstr instr);

void PrepareL(union uinstr instr);

int LookUpOpcode(union uinstr instr);

static int LookUpPrimaryOpcode(int opcode)
{
	return REVERSED;
}

unsigned long long sign_extend(unsigned short data)
{
	unsigned long long ans;
	if (data >> 15)
		ans = 0xFFFFFFFFFFFF0000ULL | data;
	else
		ans = data;
	return ans;
}

/// <summary>
/// ����ָ�����ͨ��ָ����ṹ��
/// </summary>
/// <returns>
/// ת����ϵĽṹ�壬ʧ��ʱ return_value.opcode == -1
/// </returns>
/// <param name="instruction">
/// Ҫ����� MIPS R5900 ָ�32 λԪ��
/// </param>
struct instr_t DecodeInstruction(unsigned int instruction)
{
	union uinstr anyl = {0};
	anyl.code = instruction;
	struct instr_t ans = {0};
	if (instruction == 0)
	{
		ans.opcode = NOP;
		return ans;
	}
	int index = LookUpOpcode(anyl);
	ans.opcode = index;
	if (index >= NUM_OPTION) return ans.opcode = -1, ans;
	struct instr_def* def = instrs + index;
	if (def->type == IT_code)
	{
		ans.imm = anyl.dtype.data;
	}
	else if (def->type == IT_imm)
	{
		ans.imm = sign_extend((unsigned short)anyl.itype.imm);
		ans.rt = anyl.itype.rt;
		ans.rs = anyl.itype.rs;
	}
	else if (def->type == IT_immu)
	{
		ans.imm = anyl.itype.imm;
		ans.rt = anyl.itype.rt;
		ans.rs = anyl.itype.rs;
	}
	else if (def->type == IT_imma)
	{
		ans.imm = sign_extend((unsigned short)anyl.itype.imm) << 2;
		ans.rt = anyl.itype.rt;
		ans.rs = anyl.itype.rs;
	}
	else if (def->type == IT_jump)
	{
		ans.imm = (unsigned long long)anyl.jtype.addr << 2;
	}
	else if (def->type == IT_reg)
	{
		ans.rd = anyl.rtype.rd;
		ans.rt = anyl.rtype.rt;
		ans.rs = anyl.rtype.rs;
		ans.sa = anyl.rtype.sa;
	}
	else if (def->type == IT_regf)
	{
		ans.rd = anyl.rtype.sa;
		ans.rt = anyl.rtype.rt;
		ans.rs = anyl.rtype.rd;
	}
	else ans.opcode = -1;
	return ans;
}

/// <summary>
/// ����ָ��ṹ�岢����ָ�32 λԪ��
/// </summary>
/// <returns>
/// ת����ϵĽṹ�壬ʧ��ʱ���� 0 ��NOP��
/// </returns>
/// <param name="instruction">
/// �����˵� MIPS R5900 ָ��
/// </param>
unsigned int EncodeInstruction(struct instr_t instruction)
{
	union uinstr ans = {0};
	ans.code = GetTemplateByIndex((int)instruction.opcode);
	switch (instruction.opcode)
	{
#include "encode.inc"
	}
	return ans.code;
}

/// <summary>
/// ���ݶ���Ĳ�������OpCode.h ֮���壩��ȡָ���
/// </summary>
/// <returns>
/// ָ���ṹ�壬ʧ��ʱ���� NOP ��Ӧ֮�ṹ��
/// </returns>
/// <param name="instruction">
/// Ҫȡ�õĶ�������
/// </param>
struct instr_def GetInstructionDefinitionByIndex(int option)
{
	if (option >= NUM_OPTION) return instrs[NOP];
	return instrs[option];
}

/// <summary>
/// ���ݶ�������ƣ�InsDef.h ֮���壩��ȡָ���
/// </summary>
/// <returns>
/// ָ���ṹ�壬ʧ��ʱ���� NOP ��Ӧ֮�ṹ��
/// </returns>
/// <param name="instruction">
/// Ҫȡ�õĶ���֮����
/// </param>
struct instr_def GetInstructionDefinitionByName(const char *name)
{
	for (int i = 0; i < NUM_OPTION; ++i)
	{
		if (strcmp(instrs[i].name, name) == 0)
			return instrs[i];
	}
	return instrs[NOP];
}

int LookUpOpcode(union uinstr instr)
{
	int opcode = PrimaryOpcodeLookUpTable[ instr.base.opcode ];
	if (opcode == SPECIAL)
		return LookUpSpecial(instr);
	if (opcode == REGIMM)
		return LookUpRegImm(instr);
	if (opcode == COP0)
		return LookUpCOP0(instr);
	if (opcode == COP1)
		return LookUpCOP1(instr);
	if (opcode == MMI)
		return LookUpMMI(instr);
	return opcode;
}

unsigned int GetTemplateByIndex(int opcode)
{
	// if (!opcode_buffer_prepared) PrepareOpcodeBuffer();
	return opcode_buffer[opcode];
}

void PrepareOpcodeBuffer()
{
	if (opcode_buffer_prepared) return;
	union uinstr tmp = {0};
	for (int i = 0; i < 64; ++i)
	{
		if (PrimaryOpcodeLookUpTable[i] == REVERSED) continue;
		tmp.base.opcode = i;
		if (PrimaryOpcodeLookUpTable[i] < 0)
		{
			switch (PrimaryOpcodeLookUpTable[i])
			{
			case SPECIAL:
				PrepareSpecial(tmp);
				break;
			case REGIMM:
				PrepareRegImm(tmp);
				break;
			case COP0:
				PrepareCOP0(tmp);
				break;
			case COP1:
				PrepareCOP1(tmp);
				break;
			case MMI:
				PrepareMMI(tmp);
				break;
			}
			continue;
		}
		opcode_buffer[PrimaryOpcodeLookUpTable[i]] = tmp.code;
	}
	opcode_buffer_prepared = 1;
}

void PrepareSpecial(union uinstr instr)
{
	union uinstr tmp = instr;
	for (int i = 0; i < 64; ++i)
	{
		if (SpecialOpcodeLookUpTable[i] < 0) continue;
		tmp.rtype.funct = i;
		opcode_buffer[SpecialOpcodeLookUpTable[i]] = tmp.code;
	}
}

void PrepareRegImm(union uinstr instr)
{
	union uinstr tmp = instr;
	for (int i = 0; i < 32; ++i)
	{
		if (RegImmOpcodeLookUpTable[i] < 0) continue;
		tmp.itype.rt = i;
		opcode_buffer[RegImmOpcodeLookUpTable[i]] = tmp.code;
	}
}

void PrepareMMI(union uinstr instr)
{
	union uinstr tmp = instr;
	for (int i = 0; i < 64; ++i)
	{
		if (MMIOpcodeLookUpTable[i] == REVERSED) continue;
		tmp.rtype.funct = i;
		if (MMIOpcodeLookUpTable[i] < 0)
		{
			switch (MMIOpcodeLookUpTable[i])
			{
			case PMFHL:
				PreparePMFHL(tmp);
				break;
			case MMI0:
				PrepareMMI0(tmp);
				break;
			case MMI1:
				PrepareMMI1(tmp);
				break;
			case MMI2:
				PrepareMMI2(tmp);
				break;
			case MMI3:
				PrepareMMI3(tmp);
				break;
			}
			continue;
		}
		opcode_buffer[MMIOpcodeLookUpTable[i]] = tmp.code;
	}
}

void PreparePMFHL(union uinstr instr)
{
	for (int i = 0; i < 5; ++i)
	{
		instr.rtype.sa = i;
		opcode_buffer[PMFHLOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMMI0(union uinstr instr)
{
	for (int i = 0; i < 32; ++i)
	{
		if (MMI0OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.sa = i;
		opcode_buffer[MMI0OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMMI1(union uinstr instr)
{
	for (int i = 0; i < 32; ++i)
	{
		if (MMI1OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.sa = i;
		opcode_buffer[MMI1OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMMI2(union uinstr instr)
{
	for (int i = 0; i < 32; ++i)
	{
		if (MMI2OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.sa = i;
		opcode_buffer[MMI2OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMMI3(union uinstr instr)
{
	for (int i = 0; i < 32; ++i)
	{
		if (MMI3OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.sa = i;
		opcode_buffer[MMI3OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareCOP0(union uinstr instr)
{
	for (int i = 0; i < 32; ++i)
	{
		if (COP0OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.rs = i;
		switch (COP0OpcodeLookUpTable[i])
		{
		case MF0:
			PrepareMF0(instr);
			break;
		case MT0:
			PrepareMT0(instr);
			break;
		case BC0:
			PrepareBC0(instr);
			break;
		case C0:
			PrepareC0(instr);
			break;
		}
	}
}

void PrepareMF0(union uinstr instr)
{
	opcode_buffer[MFC0] = instr.code;
	instr.rtype.rd = 24;
	PrepareMF0DBG(instr);
	instr.rtype.rd = 25;
	PrepareMF0PREF(instr);
}

void PrepareMT0(union uinstr instr)
{
	opcode_buffer[MTC0] = instr.code;
	instr.rtype.rd = 24;
	PrepareMT0DBG(instr);
	instr.rtype.rd = 25;
	PrepareMT0PREF(instr);
}

void PrepareMF0DBG(union uinstr instr)
{
	for (int i = 0; i < 8; ++i)
	{
		if (MF0DebugOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[MF0DebugOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMT0DBG(union uinstr instr)
{
	for (int i = 0; i < 8; ++i)
	{
		if (MT0DebugOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[MT0DebugOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMF0PREF(union uinstr instr)
{
	for (int i = 0; i < 2; ++i)
	{
		if (MF0PrefOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[MF0PrefOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareMT0PREF(union uinstr instr)
{
	for (int i = 0; i < 2; ++i)
	{
		if (MT0PrefOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[MT0PrefOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareBC0(union uinstr instr)
{
	for (int i = 0; i < 4; ++i)
	{
		if (BC0OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.rt = i;
		opcode_buffer[BC0OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareC0(union uinstr instr)
{
	for (int i = 0; i < 64; ++i)
	{
		if (C0OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.rt = i;
		opcode_buffer[C0OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareCOP1(union uinstr instr)
{
	for (int i = 0; i < 32; ++i)
	{
		if (COP1OpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.rs = i;
		if (COP1OpcodeLookUpTable[i] < 0)
		{
			switch (COP1OpcodeLookUpTable[i])
			{
			case BC1:
				PrepareBC1(instr);
				break;
			case S:
				PrepareS(instr);
				break;
			case D:
				PrepareD(instr);
				break;
			case W:
				PrepareW(instr);
				break;
			case L:
				PrepareL(instr);
				break;
			}
			continue;
		}
		opcode_buffer[COP1OpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareBC1(union uinstr instr)
{
	instr.rtype.rt = 0;
	opcode_buffer[BC1F] = instr.code;
	instr.rtype.rt = 1;
	opcode_buffer[BC1T] = instr.code;
}

void PrepareS(union uinstr instr)
{
	for (int i = 0; i < 64; ++i)
	{
		if (SOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[SOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareD(union uinstr instr)
{
	for (int i = 0; i < 64; ++i)
	{
		if (DOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[DOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareW(union uinstr instr)
{
	for (int i = 0; i < 64; ++i)
	{
		if (WOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[WOpcodeLookUpTable[i]] = instr.code;
	}
}

void PrepareL(union uinstr instr)
{
	for (int i = 0; i < 64; ++i)
	{
		if (LOpcodeLookUpTable[i] == REVERSED) continue;
		instr.rtype.funct = i;
		opcode_buffer[LOpcodeLookUpTable[i]] = instr.code;
	}
}

int LookUpSpecial(union uinstr instr)
{
	return SpecialOpcodeLookUpTable[ instr.rtype.funct ];
}

int LookUpRegImm(union uinstr instr)
{
	return RegImmOpcodeLookUpTable[ instr.itype.rt ];
}

int LookUpMMI(union uinstr instr)
{
	int opcode = MMIOpcodeLookUpTable[instr.rtype.funct];
	if (opcode == MMI0)
		return LookUpMMI0(instr);
	if (opcode == MMI1)
		return LookUpMMI1(instr);
	if (opcode == MMI2)
		return LookUpMMI2(instr);
	if (opcode == MMI3)
		return LookUpMMI3(instr);
	if (opcode == PMFHL)
		return LookUpPMFHL(instr);
	return opcode;
}

int LookUpPMFHL(union uinstr instr)
{
	return PMFHLOpcodeLookUpTable[ instr.rtype.sa ];
}

int LookUpMMI0(union uinstr instr)
{
	return MMI0OpcodeLookUpTable[ instr.rtype.sa ];
}

int LookUpMMI1(union uinstr instr)
{
	return MMI1OpcodeLookUpTable[instr.rtype.sa];
}

int LookUpMMI2(union uinstr instr)
{
	return MMI2OpcodeLookUpTable[instr.rtype.sa];
}

int LookUpMMI3(union uinstr instr)
{
	return MMI3OpcodeLookUpTable[instr.rtype.sa];
}

int LookUpCOP0(union uinstr instr)
{
	switch (COP0OpcodeLookUpTable[instr.rtype.rs])
	{
	case MF0:
		return LookUpMF0(instr);
	case MT0:
		return LookUpMT0(instr);
	case BC0:
		return LookUpBC0(instr);
	case C0:
		return LookUpC0(instr);
	default:
		return COP0OpcodeLookUpTable[instr.rtype.rs];
	}
}

int LookUpMF0(union uinstr instr)
{
	int opcode = instr.rtype.rd;
	if (opcode == MF0DBG)
		return LookUpMF0DBG(instr);
	if (opcode == MF0PREF)
		return LookUpMF0PREF(instr);
	return MF0OpcodeLookUpTable[opcode];
}

int LookUpMT0(union uinstr instr)
{
	int opcode = instr.rtype.rd;
	if (opcode == MT0DBG)
		return LookUpMT0DBG(instr);
	if (opcode == MT0PREF)
		return LookUpMT0PREF(instr);
	return MT0OpcodeLookUpTable[opcode];
}

int LookUpMF0DBG(union uinstr instr)
{
	return MF0DebugOpcodeLookUpTable[ instr.rtype.funct ];
}

int LookUpMT0DBG(union uinstr instr)
{
	return MT0DebugOpcodeLookUpTable[instr.rtype.funct];
}

int LookUpMF0PREF(union uinstr instr)
{
	return MF0PrefOpcodeLookUpTable[instr.rtype.funct];
}

int LookUpMT0PREF(union uinstr instr)
{
	return MT0PrefOpcodeLookUpTable[instr.rtype.funct];
}

int LookUpBC0(union uinstr instr)
{
	return BC0OpcodeLookUpTable[ instr.rtype.rt ];
}

int LookUpC0(union uinstr instr)
{
	return C0OpcodeLookUpTable[instr.rtype.rs];
}

int LookUpCOP1(union uinstr instr)
{
	int opcode = COP1OpcodeLookUpTable[ instr.rtype.rs ];
	switch (opcode)
	{
	case BC1:
		return LookUpBC1(instr);
	case S:
		return LookUpS(instr);
	case D:
		return LookUpD(instr);
	case W:
		return LookUpW(instr);
	case L:
		return LookUpL(instr);
	default:
		return opcode;
	}
}

int LookUpBC1(union uinstr instr)
{
	return BC1OpcodeLookUpTable[ instr.rtype.rt ];
}

int LookUpS(union uinstr instr)
{
	return SOpcodeLookUpTable[instr.rtype.funct];
}

int LookUpD(union uinstr instr)
{
	return DOpcodeLookUpTable[instr.rtype.funct];
}

int LookUpW(union uinstr instr)
{
	return WOpcodeLookUpTable[instr.rtype.funct];
}

int LookUpL(union uinstr instr)
{
	return LOpcodeLookUpTable[instr.rtype.funct];
}
