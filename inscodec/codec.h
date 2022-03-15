#ifndef _CODEC_H_
#define _CODEC_H_

#include "opnm.h"
// #define IT_nop  0
// #define IT_reg  16
// #define IT_jump 32
// #define IT_imm  64
// #define IT_code 128
// #define IT_immu 65
// #define IT_imma 66
// #define IT_regf 17
#include "ins_def.h"

#ifdef __cplusplus
extern "C" {
#endif
	/* Structures */
	struct instr_t
	{
		unsigned int opcode;
		unsigned int rs;
		unsigned int rt;
		unsigned int rd;
		unsigned int sa;
		unsigned long long imm;
	};

#ifdef LE
	struct instr_base
	{
		unsigned int _data : 26;
		unsigned int opcode : 6;
	};

	struct instr_j
	{
		unsigned int addr : 26;
		unsigned int opcode : 6;
	};

	struct instr_r
	{
		unsigned int funct : 6;
		unsigned int sa : 5;
		unsigned int rd : 5;
		unsigned int rt : 5;
		unsigned int rs : 5;
		unsigned int opcode : 6;
	};

	struct instr_d
	{
		unsigned int funct : 6;
		unsigned int data : 20;
		unsigned int opcode : 6;
	};

	struct instr_i
	{
		unsigned int imm : 16;
		unsigned int rt : 5;
		unsigned int rs : 5;
		unsigned int opcode : 6;
	};
#else
	struct instr_base
	{
		unsigned int opcode : 6;
		unsigned int _data : 26;
	};

	struct instr_j
	{
		unsigned int opcode : 6;
		unsigned int addr : 6;
	};

	struct instr_r
	{
		unsigned int opcode : 6;
		unsigned int rs : 5;
		unsigned int rt : 5;
		unsigned int rd : 5;
		unsigned int sa : 5;
		unsigned int funct : 6;
	};

	struct instr_d
	{
		unsigned int opcode : 6;
		unsigned int data : 20;
		unsigned int funct : 6;
	};

	struct instr_i
	{
		unsigned int opcode : 6;
		unsigned int rs : 5;
		unsigned int rt : 5;
		unsigned int imm : 16;
	};
#endif
	union uinstr
	{
		unsigned int code;
		struct instr_base base;
		struct instr_i itype;
		struct instr_j jtype;
		struct instr_r rtype;
		struct instr_d dtype;
	};

	/* Opcode Look up tables. */
	static int PrimaryOpcodeLookUpTable[] =
	{
		 SPECIAL, REGIMM,        J,      JAL,      BEQ,      BNE,    BLEZL,  BGTZ,
			ADDI,  ADDIU,     SLTI,    SLTIU,     ANDI,      ORI,     XORI,   LUI,
			COP0,   COP1, REVERSED, REVERSED,     BEQL,     BNEL,    BLEZL, BGTZL,
		   DADDI, DADDIU,      LDL,      LDR,      MMI, REVERSED,       LQ,    SQ,
			  LB,     LH,      LWL,       LW,      LBU,      LHU,      LWR,   LWU,
			  SB,     SH,      SWL,       SW,      SDL,      SDR,      SWR, CACHE,
		REVERSED,   LWC1, REVERSED,     PREF, REVERSED,     LDC1, REVERSED,    LD,
		REVERSED,   SWC1, REVERSED, REVERSED, REVERSED,     SDC1, REVERSED,    SD
	};

	/* reg: funct */
	static int SpecialOpcodeLookUpTable[] =
	{
		 SLL, REVERSED,  SRL,  SRA,     SLLV, REVERSED,     SRLV,     SRAV,
		  JR,     JALR, MOVZ, MOVN,  SYSCALL,    BREAK, REVERSED,     SYNC,
		MFHI,     MTHI, MFLO, MTLO,    DSLLV, REVERSED,    DSRLV,    DSRAV,
		MULT,    MULTU,  DIV, DIVU, REVERSED, REVERSED, REVERSED, REVERSED,
		 ADD,     ADDU,  SUB, SUBU,      AND,       OR,      XOR,      NOR,
		MFSA,     MTSA,  SLT, SLTU,     DADD,    DADDU,     DSUB,    DSUBU,
		 TGE,     TGEU,  TLT, TLTU,      TEQ, REVERSED,      TNE, REVERSED,
		DSLL, REVERSED, DSRL, DSRA,   DSLL32, REVERSED,   DSRL32,   DSRA32
	};

	/* imm: rt */
	static int RegImmOpcodeLookUpTable[] =
	{
		  BLTZ,   BGEZ,     BLTZL,   BGEZL, REVERSED, REVERSED, REVERSED, REVERSED,
		  TGEI,  TGEIU,     TLTI,    TLTIU,     TEQI, REVERSED,     TNEI, REVERSED,
		BLTZAL, BGEZAL,  BLTZALL,  BGEZALL, REVERSED, REVERSED, REVERSED, REVERSED,
		 MTSAB,  MTSAH, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
	};

	/* reg: funct */
	static int MMIOpcodeLookUpTable[] =
	{
		MADD, MADDU, REVERSED, REVERSED, PLZCW, REVERSED, REVERSED, REVERSED,
		MMI0, MMI2, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		MFHI1, MTHI1, MFLO1, MTLO1, REVERSED, REVERSED, REVERSED, REVERSED,
		MULT1, MULTU1, DIV1, DIVU1, REVERSED, REVERSED, REVERSED, REVERSED,
		MADD1, MADDU1, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		MMI1, MMI3, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		PMFHL, PMTHL_LW, REVERSED, REVERSED, PSLLH, REVERSED, PSRLH, PSRAH,
		REVERSED, REVERSED, REVERSED, REVERSED, PSLLW, REVERSED, PSRLW, PSRAW,
	};

	/* reg: sa */
	static int PMFHLOpcodeLookUpTable[] =
	{
		PMFHL_LW, PMFHL_UW, PMFHL_SLW, PMFHL_LH, PMFHL_SH,
	};

	/* reg: sa */
	static int MMI0OpcodeLookUpTable[] =
	{
		PADDW, PSUBW, PCGTW, PMAXW,
		PADDH, PSUBH, PCGTH, PMAXH,
		PADDB, PSUBB, PCGTB, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED,
		PADDSW, PSUBSW, PEXTLW, PPACW,
		PADDSH, PSUBSH, PEXTLH, PPACH,
		PADDSB, PSUBSB, PEXTLB, PPACB,
		REVERSED, REVERSED, PEXT5, PPAC5,
	};

	/* reg: sa */
	static int MMI1OpcodeLookUpTable[] =
	{
		REVERSED, PABSW, PCEQW, PMINW,
		PADSBH, PABSH, PCEQH, PMINH,
		REVERSED, REVERSED, PCEQB, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED,
		PADDUW, PSUBUW, PEXTUW, REVERSED,
		PADDUH, PSUBUH, PEXTUH, REVERSED,
		PADDUB, PSUBUB, PEXTUB, QFSRV,
		REVERSED, REVERSED, REVERSED, REVERSED,
	};

	/* reg: sa */
	static int MMI2OpcodeLookUpTable[] =
	{
		PMADDW, REVERSED, PSLLVW, PSRLVW,
		PMSUBW, REVERSED, REVERSED, REVERSED,
		PMFHI, PMFLO, PINTH, REVERSED,
		PMULTW, PDIVW, PCPYLD, REVERSED,
		PMADDH, PHMADH, PAND, PXOR,
		PMSUBH, PHMSBH, REVERSED, REVERSED,
		REVERSED, REVERSED, PEXEH, PREVH,
		PMULTH, PDIVBW, PEXEW, PROT3W,
	};

	static int MMI3OpcodeLookUpTable[] =
	{
		PMADDUW, REVERSED, REVERSED, PSRAVW,
		REVERSED, REVERSED, REVERSED, REVERSED,
		PMTHI, PMTLO, PINTEH, REVERSED,
		PMULTUW, PDIVUW, PCPYUD, REVERSED,
		REVERSED, REVERSED, POR, PNOR,
		REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, PEXCH, PCPYH,
		REVERSED, REVERSED, PEXCW, REVERSED,
	};

	/* reg: rs */
	static int COP0OpcodeLookUpTable[] =
	{
		MF0, REVERSED, REVERSED, REVERSED, MT0, REVERSED, REVERSED, REVERSED,
		BC0, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		C0, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
	};

	/* REG: RD */
	static int MF0OpcodeLookUpTable[] =
	{
		MFC0, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0,
		MFC0, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0,
		MFC0, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0,
		MF0DBG, MF0PREF, MFC0, MFC0, MFC0, MFC0, MFC0, MFC0
	};

	static int MT0OpcodeLookUpTable[] =
	{
		MTC0, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0,
		MTC0, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0,
		MTC0, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0,
		MT0DBG, MT0PREF, MTC0, MTC0, MTC0, MTC0, MTC0, MTC0
	};

	/* reg: rd=Debug(24) funct */
	static int MF0DebugOpcodeLookUpTable[] =
	{
		MFBPC, REVERSED, MFIAB, MFIABM, MFDAB, MFDABM, MFDVB, MFDVBM,
	};

	/* reg: rd=Debug(24) funct */
	static int MT0DebugOpcodeLookUpTable[] =
	{
		MTBPC, REVERSED, MTIAB, MTIABM, MTDAB, MTDABM, MTDVB, MTDVBM,
	};

	static int MF0PrefOpcodeLookUpTable[] =
	{
		MFPS, MFPC,
	};

	static int MT0PrefOpcodeLookUpTable[] =
	{
		MTPS, MTPC,
	};

	/* rt */
	static int BC0OpcodeLookUpTable[] =
	{
		BC0F, BC0T, BC0FL, BC0TL,
	};

	static int C0OpcodeLookUpTable[] =
	{
		REVERSED, TLBR, TLBWI, REVERSED, REVERSED, REVERSED, TLBWR, REVERSED,
		TLBP, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		ERET, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		EI, DI, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
	};

	/* reg, rs */
	static int COP1OpcodeLookUpTable[] =
	{
		MFC1, DMFC1, CFC1, REVERSED, MTC1, DMTC1, CTC1, REVERSED,
		BC1, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		S, D, REVERSED, REVERSED, W, L, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
	};

	/* rt */
	static int BC1OpcodeLookUpTable[] =
	{
		BC1F, BC1T,
	};

	/* reg, funct */
	static int SOpcodeLookUpTable[] =
	{
		ADD_S, SUB_S, MUL_S, DIV_S, SQRT_S, ABS_S, MOV_S, NEG_S,
		ROUND_L_S, TRUNC_L_S, CEIL_L_S, FLOOR_L_S, ROUND_W_S, TRUNC_W_S, CEIL_W_S, FLOOR_W_S,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, CVT_D_S, REVERSED, REVERSED, CVT_W_S, CVT_L_S, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		C_F_S, C_UN_S, C_EQ_S, C_UEQ_S, C_OLT_S, C_ULT_S, C_OLE_S, C_ULE_S,
		C_SF_S, C_NGLE_S, C_SEQ_S, C_NGL_S, C_LT_S, C_NGE_S, C_LE_S, C_NGE_S,
	};

	/* reg, funct */
	static int DOpcodeLookUpTable[] =
	{
		ADD_D, SUB_D, MUL_D, DIV_D, SQRT_D, ABS_D, MOV_D, NEG_D,
		ROUND_L_D, TRUNC_L_D, CEIL_L_D, FLOOR_L_D, ROUND_W_D, TRUNC_W_D, CEIL_W_D, FLOOR_W_D,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		CVT_S_D, REVERSED, REVERSED, REVERSED, CVT_W_D, CVT_L_D, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		C_F_D, C_UN_D, C_EQ_D, C_UEQ_D, C_OLT_D, C_ULT_D, C_OLE_D, C_ULE_D,
		C_SF_D, C_NGLE_D, C_SEQ_D, C_NGL_D, C_LT_D, C_NGE_D, C_LE_D, C_NGE_D,
	};

	static int WOpcodeLookUpTable[] =
	{
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		CVT_S_W, CVT_D_W, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
	};

	static int LOpcodeLookUpTable[] =
	{
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		CVT_S_L, CVT_D_L, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
		REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED, REVERSED,
	};

	/* Functions */
	int LookUpOpcode(union uinstr instr);

	unsigned int GetTemplateByIndex(int opcode);

	void PrepareOpcodeBuffer();

	struct instr_t DecodeInstruction(unsigned int instruction);

	unsigned int EncodeInstruction(struct instr_t instruction);

	struct instr_def GetInstructionDefinationByIndex(int option);

	struct instr_def GetInstructionDefinationByName(const char* name);

#define NUM_OPTION (sizeof(instrs) / sizeof(struct instr_def))

#ifdef __cplusplus
}
#endif

#endif