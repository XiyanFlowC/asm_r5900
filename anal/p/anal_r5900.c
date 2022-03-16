#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../inscodec/codec.c"

#define R5900_ARITH(op_type, ch) \
    op->dst = r_anal_value_new();\
    op->src[0] = r_anal_value_new();\
    op->src[1] = r_anal_value_new();\
    op->dst->reg = r_reg_get(anal->reg, gpr_names[tmp.rd], R_REG_TYPE_GPR);\
    op->src[0]->reg = r_reg_get(anal->reg, gpr_names[tmp.rs], R_REG_TYPE_GPR);\
    op->src[1]->reg = r_reg_get(anal->reg, gpr_names[tmp.rt], R_REG_TYPE_GPR);\
    op->type = R_ANAL_OP_TYPE_##op_type;\
    r_strbuf_setf (&op->esil, "%s,%s,"#ch",%s,=",\
        gpr_names[tmp.rs],\
        gpr_names[tmp.rt],\
        gpr_names[tmp.rd]);

//static char regbuf[8]; // use to make hi reg name str, e.g. v0h, a0h, ...

#define R5900_HIARITH(op_type, ch) \
/*    op->dst = r_anal_value_new();// TODO: The dst can't be two register, how did others deal with 128-bit SIMD?\ 
    op->src[0] = r_anal_value_new();\
    op->src[1] = r_anal_value_new();\
    snprintf(regbuf, 8, "%sh", gpr_names[tmp.rd]);\
    op->dst->reg = r_reg_get(anal->reg, regbuf, R_REG_TYPE_GPR);\
    snprintf(regbuf, 8, "%sh", gpr_names[tmp.rs]);\
    op->src[0]->reg = r_reg_get(anal->reg, regbuf, R_REG_TYPE_GPR);\
    snprintf(regbuf, 8, "%sh", gpr_names[tmp.rt]);\
    op->src[1]->reg = r_reg_get(anal->reg, regbuf, R_REG_TYPE_GPR);*/\
    op->type = R_ANAL_OP_TYPE_##op_type;\
    r_strbuf_setf (&op->esil, "%sh,%sh,"#ch",%sh,=",\
        gpr_names[tmp.rs],\
        gpr_names[tmp.rt],\
        gpr_names[tmp.rd]);

static int r5900_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
    ut32 instr;
    memcpy(&instr, data, 4);

    op->addr = addr;
    op->type = R_ANAL_OP_TYPE_UNK;
    op->size = 4;

    struct instr_t tmp = DecodeInstruction(instr);
    long long imm = *(long long*)&tmp.imm;
    int opcode = *(int*)&tmp.opcode;

    switch(tmp.opcode) {
        case NOP:
        op->type = R_ANAL_OP_TYPE_NOP;
        break;
        case SYSCALL:
        op->type = R_ANAL_OP_TYPE_SWI;
        break;
        case BREAK:
        op->type = R_ANAL_OP_TYPE_TRAP;
        break;

        /* jump */
        case J:
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = tmp.imm;
        op->delay = 1;
        r_strbuf_setf (&op->esil, "0x%llx,pc,=", imm);
        break;
        case JAL:
        op->type = R_ANAL_OP_TYPE_CALL;
        op->jump = tmp.imm;
        op->delay = 1;
        op->fail = addr + 8;
        r_strbuf_setf (&op->esil, "0x%llx,pc,=,0x%llx,ra,=", imm, imm);
        break;
        case JALR:
        op->type = R_ANAL_OP_TYPE_UCALL;
        op->jump = tmp.imm;
        op->delay = 1;
        op->fail = addr + 8;
        r_strbuf_setf (&op->esil, "0x%llx,pc,=,%s,=", imm, gpr_names[tmp.rd]);
        break;
        case JR:
        if (tmp.rs == 31) { // jr ra
            op->type = R_ANAL_OP_TYPE_RET;
        }
        else { // reg jmp - switch etc.
            op->type = R_ANAL_OP_TYPE_RJMP;
        }
        
        op->delay = 1;
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, "pc",  R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, gpr_names[tmp.rs], R_REG_TYPE_GPR);
        r_strbuf_set (&op->esil, gpr_names[tmp.rs]);
        r_strbuf_append (&op->esil, ",pc,:=");
        // op->reg = gpr_names[tmp.rs];
        break;

        /* branch */
        case BEQ:
        case BEQL:
        case BGEZ:
        case BGEZL:
        case BGEZAL:
        case BGEZALL:
        case BGTZ:
        case BGTZL:
        case BLEZ:
        case BLEZL:
        case BLTZ:
        case BLTZL:
        case BLTZAL:
        case BLTZALL:
        case BNE:
        case BNEL:
        op->type = R_ANAL_OP_TYPE_CJMP;
        op->delay = 1;
        op->jump = addr + 4 + imm;
        op->fail = addr + 8;
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->src[1] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, "pc", R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, gpr_names[tmp.rs], R_REG_TYPE_GPR);
        op->src[1]->imm = imm;
        op->src[1]->type = R_ANAL_VAL_IMM; // default by imm
        switch(opcode) { // TODO: Add emulation codes
            case BEQL:
            op->delay = 0;
            case BEQ:
            op->cond = R_ANAL_COND_EQ;
            op->src[1]->reg = r_reg_get (anal->reg, gpr_names[tmp.rt], R_REG_TYPE_GPR);
            op->src[1]->type = R_ANAL_VAL_REG; // the value is reg
            break;
            case BGEZALL:
            op->delay = 0;
            case BGEZAL:
            op->type = R_ANAL_OP_TYPE_CCALL;
            op->cond = R_ANAL_COND_GE;
            break;
            case BGEZL:
            op->delay = 0;
            case BGEZ:
            op->cond = R_ANAL_COND_GE;
            break;
            case BGTZL:
            op->delay = 0;
            case BGTZ:
            op->cond = R_ANAL_COND_GT;
            break;
            case BLTZL:
            op->delay = 0;
            case BLTZ:
            op->cond = R_ANAL_COND_LT;
            break;
            case BLTZALL:
            op->delay = 0;
            case BLTZAL:
            op->cond = R_ANAL_COND_LT;
            op->type = R_ANAL_OP_TYPE_CCALL;
            break;
            case BNEL:
            op->delay = 0;
            case BNE:
            op->cond = R_ANAL_COND_NE;
            op->src[1]->reg = r_reg_get (anal->reg, gpr_names[tmp.rt], R_REG_TYPE_GPR);
            op->src[1]->type = R_ANAL_VAL_REG;
            break;
        }
        break;

        /* load and store */
        case LB:
        case LBU:
        op->refptr = 1;
        case LH:
        case LHU:
        if(!op->refptr)
            op->refptr = 2;
        case LW:
        case LWU:
        if(!op->refptr)
            op->refptr = 4;
        case LD: // TODO: LDL, LDR, LWL, LWR
                 // NOTE: ~L and ~R seems always appears in pairs to make sence
                 // Ignore one of them?
        if(!op->refptr)
            op->refptr = 8;
        case LQ:
        if(!op->refptr)
            op->refptr = 16;

        if(tmp.rs == 28) {
            op->ptr = anal->gp + imm;
        }
        else if (tmp.rs == 29) { // reg is sp, stack operation
            op->type = R_ANAL_OP_TYPE_POP;
        }
        else {
            op->ptr = imm + r_reg_getv(anal->reg, gpr_names[tmp.rs]);
        }
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, gpr_names[tmp.rt], R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, gpr_names[tmp.rs], R_REG_TYPE_GPR);
        op->src[0]->delta = imm;
        op->src[0]->type = R_ANAL_VAL_MEM;
        // r_strbuf_set (&op->esil, "")
        op->type = R_ANAL_OP_TYPE_LOAD;
        // op->reg = gpr_names[tmp.rt]; // do these lines really affect?
        // op->ireg = gpr_names[tmp.rs];
        op->val = *(uint64_t*)&imm;
        op->sign = true;
        break;
        case SB: // TODO: add esil and emu code
        op->refptr = 1;
        case SH:
        if(!op->refptr)
            op->refptr = 2;
        case SW:
        if(!op->refptr)
            op->refptr = 4;
        case SD:
        if(!op->refptr)
            op->refptr = 8;
        case SQ:
        if(!op->refptr)
            op->refptr = 16;

        if(tmp.rs == 28) { // gp
            op->ptr = anal->gp + imm;
        }
        else if (tmp.rs == 29) {
            op->type = R_ANAL_OP_TYPE_PUSH;
        }
        else {
            op->ptr = imm + r_reg_getv(anal->reg, gpr_names[tmp.rs]);
        }
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->delta = imm;
        op->dst->reg = r_reg_get (anal->reg, gpr_names[tmp.rs], R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, gpr_names[tmp.rt], R_REG_TYPE_GPR);
        op->dst->type = R_ANAL_VAL_MEM;
        // r_strbuf_set (&op->esil, "")
        op->type = R_ANAL_OP_TYPE_STORE;
        break;

        /* arithmetic */
        case LUI:
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, gpr_names[tmp.rt], R_REG_TYPE_GPR);
        op->dst->type = R_ANAL_VAL_REG;
        op->src[0]->imm = imm << 16;
        op->src[0]->type = R_ANAL_VAL_IMM;
        r_strbuf_setf (&op->esil, "16,0x%llX,0xffff,&,<<,%s,=", imm, gpr_names[tmp.rt]);
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
        case ADD:
        case ADDU:
        case DADD:
        case DADDU:
        R5900_ARITH(ADD, +) // TODO: these instr should not share same logic

        if (tmp.opcode == DADDU && tmp.rt == 0) { // move ( daddu rd, rs, zero)
            op->type = R_ANAL_OP_TYPE_MOV;
            r_anal_value_free (op->src[1]);
            op->src[1] = NULL;
            // op->mnemonic = (char*)r_str_newf ("move %s, %s", gpr_names[tmp.rd], gpr_names[tmp.rs]);
        }
        break;
        case ADDIU:
        case ADDI:
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->src[1] = r_anal_value_new();
        op->dst->reg = r_reg_get(anal->reg, gpr_names[tmp.rd], R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get(anal->reg, gpr_names[tmp.rs], R_REG_TYPE_GPR);
        op->src[1]->imm = imm;
        op->type = R_ANAL_OP_TYPE_ADD;
        r_strbuf_setf (&op->esil, "%lld,%s,+,%s,=",
            imm,
            gpr_names[tmp.rs],
            gpr_names[tmp.rt]);// TODO: these instr should not share same logic
        break;
        case SLL:
        case DSLL:
        case DSLL32:
        r_strbuf_setf (&op->esil, "%s,%llu,<<,%s,=",
            gpr_names[tmp.rt],
            tmp.sa,
            gpr_names[tmp.rd]);
        op->type = R_ANAL_OP_TYPE_SHL;
        break;
        case SRL: // TODO : improve the esil gen
        case DSRL:
        case DSRL32:
        r_strbuf_setf (&op->esil, "%s,%llu,>>,%s,=",
            gpr_names[tmp.rt],
            tmp.sa,
            gpr_names[tmp.rd]);
        op->type = R_ANAL_OP_TYPE_SHR;
        break;
        case SRA: // TODO: currently work as SRL, needs further implementation
        case DSRA:
        case DSRA32:
        r_strbuf_setf (&op->esil, "%s,%llu,>>,%s,=",
            gpr_names[tmp.rt],
            tmp.sa,
            gpr_names[tmp.rd]);
        op->type = R_ANAL_OP_TYPE_SAR;
        break;
        case SUB:
        case SUBU:
        case DSUB:
        case DSUBU:
        R5900_ARITH(SUB,-) // TODO: these instr should not share same logic
        break;
        case AND:
        R5900_ARITH(AND,&)
        break;
        case OR:
        R5900_ARITH(OR,|)
        break;
        case XOR:
        R5900_ARITH(XOR,^)
        break;
        case PAND:
        R5900_ARITH(AND,&)
        R5900_HIARITH(AND,&)
        break;
        case POR:
        R5900_ARITH(OR,|)
        R5900_HIARITH(OR,|)
        break;
        case PXOR:
        R5900_ARITH(XOR,^)
        R5900_HIARITH(XOR,^)
        break;
        case PADDUW:
        if(tmp.rt == 0) {// padduw rd, rs, zero (qmove rd, rs)
            op->type = R_ANAL_OP_TYPE_MOV;
            r_strbuf_setf (&op->esil, "%sh,%sh,=,%sh,%sh,=",
                tmp.rs, tmp.rd, tmp.rs, tmp.rd);
        }
        op->type = R_ANAL_OP_TYPE_ADD;
        break;
        case MULT:
        case MULTU:
        R5900_ARITH(MUL,*);
        r_strbuf_setf (&op->esil, "32,0xFFFFFFFF,%s,%s,*,DUP,&,DUP,%s,=,lo,=,>>,hi,=",
            gpr_names[tmp.rs], gpr_names[tmp.rt], gpr_names[tmp.rd]);
        break;
        case DIV:
        case DIVU:
        R5900_ARITH(DIV,/);
        // r_strbuf_setf (&op->esil, "32,0xFFFFFFFF,%s,%s,/,DUP,&,DUP,%s,=,lo,=,>>,hi,=", // TODO: handle the hi & lo for Q and R
        //     gpr_names[tmp.rs], gpr_names[tmp.rt], gpr_names[tmp.rd]);
        break;
        case MFHI:
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, gpr_names[tmp.rd], R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, "hi", R_REG_TYPE_GPR);
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "hi,%s,=", gpr_names[tmp.rd]);
        break;
        case MFLO:
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, gpr_names[tmp.rd], R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, "lo", R_REG_TYPE_GPR);
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "lo,%s,=", gpr_names[tmp.rd]);
        break;
        case MTHI:
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, "hi", R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, gpr_names[tmp.rd], R_REG_TYPE_GPR);
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "%s,hi,=", gpr_names[tmp.rd]);
        break;
        case MTLO:
        op->dst = r_anal_value_new();
        op->src[0] = r_anal_value_new();
        op->dst->reg = r_reg_get (anal->reg, "lo", R_REG_TYPE_GPR);
        op->src[0]->reg = r_reg_get (anal->reg, gpr_names[tmp.rd], R_REG_TYPE_GPR);
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "%s,lo,=", gpr_names[tmp.rd]);
        break;
    }

    return 4;
}
#undef R5900_ARITH
#undef R5900_HIARITH

static bool set_r5900_reg_profile(RAnal* anal) {
    const char *p =
    "=PC    pc\n"
    "=SP    sp\n"
    "=BP    fp\n"
    "=A0    a0\n"
    "=A1    a1\n"
    "=A2    a2\n"
    "=A3    a3\n"
    "=SN    v0\n"
    "gpr    zero    .64 0   0\n"
    "gpr    zeroh   .64 8   0\n"
    "gpr    at  .64 16  0\n"
    "gpr    ath .64 24  0\n"
    "gpr    v0  .64 32  0\n"
    "gpr    v0h .64 40  0\n"
    "gpr	v1	.64	48	0\n"
    "gpr    v1h .64 56  0\n"
    "gpr	a0	.64	64	0\n"
    "gpr    a0h .64 72  0\n"
    "gpr	a1	.64	80	0\n"
    "gpr    a1h .64 88  0\n"
    "gpr	a2	.64	96	0\n"
    "gpr    a2h .64 104 0\n"
    "gpr	a3	.64	112	0\n"
    "gpr    a3h .64 120 0\n"
    "gpr	t0	.64	128	0\n"
    "gpr    t0h .64 136 0\n"
    "gpr	t1	.64	144	0\n"
    "gpr    t1h .64 152 0\n"
    "gpr	t2	.64	160	0\n"
    "gpr    t2h .64 168 0\n"
    "gpr	t3	.64	176	0\n"
    "gpr    t3h .64 184 0\n"
    "gpr	t4	.64	192	0\n"
    "gpr    t4h .64 200 0\n"
    "gpr	t5	.64	208	0\n"
    "gpr    t5h .64 216 0\n"
    "gpr	t6	.64	224	0\n"
    "gpr    t6h .64 232 0\n"
    "gpr	t7	.64	240	0\n"
    "gpr    t7h .64 248 0\n"
    "gpr    s0  .64 256 0\n"
    "gpr    s0h .64 264 0\n"
    "gpr    s1  .64 272 0\n"
    "gpr    s1h .64 280 0\n"
    "gpr    s2  .64 288 0\n"
    "gpr    s2h .64 296 0\n"
    "gpr    s3  .64 304 0\n"
    "gpr    s3h .64 312 0\n"
    "gpr    s4  .64 320 0\n"
    "gpr    s4h .64 328 0\n"
    "gpr    s5  .64 336 0\n"
    "gpr    s5h .64 344 0\n"
    "gpr    s6  .64 352 0\n"
    "gpr    s6h .64 360 0\n"
    "gpr    s7  .64 368 0\n"
    "gpr    s7h .64 376 0\n"
    "gpr    t8  .64 384 0\n"
    "gpr    t8h .64 392 0\n"
    "gpr	k0	.64	400	0\n"
    "gpr    k0h .64 408 0\n"
    "gpr	k1	.64	416	0\n"
    "gpr    k1h .64 424 0\n"
    "gpr	gp	.64	432	0\n"
    "gpr    gph .64 440 0\n"
    "gpr	sp	.64	448 0\n"
    "gpr    sph .64 456 0\n"
    "gpr	fp	.64	464	0\n"
    "gpr	fph	.64	472	0\n"
    "gpr	ra	.64	480	0\n" // 32 bits ?
//    "gpr    rah .64 344 0\n"
    "gpr	pc	.64	488	0\n"; // 32 bits ?
    return r_reg_set_profile_string(anal->reg, p);
}

static int r5900_archinfo(RAnal* a, int query) {
    return 4;
}

RAnalPlugin r_anal_plugin_r5900 = {
    .name = "r5900",
    .desc = "mips r5900 code analysis plugin",
    .license = "MIT",
    .author = "xiyan",
    .arch = "r5900",
    .bits = 32,
    .op = r5900_op,
    .archinfo = r5900_archinfo,
    .esil = true,
    .set_reg_profile = set_r5900_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_r5900,
    .version = R2_VERSION
};
#endif
