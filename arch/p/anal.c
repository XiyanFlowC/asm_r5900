#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../inscodec/codec.h"

#define CREATE_DST (dst = r_vector_push (&op->dsts, NULL))
#define CREATE_SRC (src0 = r_vector_push (&op->srcs, NULL))
#define CREATE_SRC2 (CREATE_SRC, src1 = r_vector_push (&op->srcs, NULL))
#define CREATE_DST_SRC (CREATE_DST, CREATE_SRC)
#define CREATE_DST_SRC2 (CREATE_DST, CREATE_SRC2)

#define R5900_ARITH(op_type, ch) \
    ((RAnalValue *)r_vector_push (&op->dsts, NULL))->reg = gpr_names[tmp.rd];\
    ((RAnalValue *)r_vector_push (&op->srcs, NULL))->reg = gpr_names[tmp.rs];\
    ((RAnalValue *)r_vector_push (&op->srcs, NULL))->reg = gpr_names[tmp.rt];\
    op->type = R_ANAL_OP_TYPE_##op_type;\
    r_strbuf_setf (&op->esil, "%s,%s,"#ch",%s,=",\
        gpr_names[tmp.rs],\
        gpr_names[tmp.rt],\
        gpr_names[tmp.rd]);

//static char regbuf[8]; // use to make hi reg name str, e.g. v0h, a0h, ...

#define R5900_HIARITH(op_type, ch) \
    op->type = R_ANAL_OP_TYPE_##op_type;\
    r_strbuf_setf (&op->esil, "%sh,%sh,"#ch",%sh,=",\
        gpr_names[tmp.rs],\
        gpr_names[tmp.rt],\
        gpr_names[tmp.rd]);

int r5900_op(RAnalOp *op, ut64 addr, struct instr_t tmp, RAnalOpMask mask) {
    // ut32 instr;
    // memcpy(&instr, data, 4);

    op->addr = addr;
    op->type = R_ANAL_OP_TYPE_UNK;
    op->size = 4;

    // struct instr_t tmp = DecodeInstruction(instr);
    long long imm = *(long long*)&tmp.imm;
    int opcode = *(int*)&tmp.opcode;

    RAnalValue *dst, *src0, *src1;

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
        
        CREATE_DST_SRC;
        op->delay = 1;
        dst->reg = "pc";
        src0->reg = gpr_names[tmp.rs];
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
        CREATE_DST_SRC2;
        dst->reg = "pc";
        src0->reg = gpr_names[tmp.rs];
        src1->imm = imm;
        src1->type = R_ANAL_VAL_IMM; // default by imm
        switch(opcode) { // TODO: Add emulation codes
            case BEQL:
            op->delay = 0;
            case BEQ:
            op->cond = R_ANAL_COND_EQ;
            src1->reg = gpr_names[tmp.rt];
            src1->type = R_ANAL_VAL_REG; // the value is reg
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
            src1->reg = gpr_names[tmp.rt];
            src1->type = R_ANAL_VAL_REG;
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

        CREATE_DST_SRC;
        dst->reg = gpr_names[tmp.rt];
        src0->reg = gpr_names[tmp.rs];
        src0->delta = imm;
        src0->type = R_ANAL_VAL_MEM;
        // r_strbuf_set (&op->esil, "")
        op->type = R_ANAL_OP_TYPE_LOAD;
        // op->reg = gpr_names[tmp.rt]; // do these lines really affect?
        // op->ireg = gpr_names[tmp.rs];
        // op->val = *(uint64_t*)&imm;
        // op->sign = true;
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

        // if(tmp.rs == 28) { // gp
        //     op->ptr = anal->gp + imm;
        // }
        // else if (tmp.rs == 29) {
        //     op->type = R_ANAL_OP_TYPE_PUSH;
        // }
        // else {
        //     op->ptr = imm + r_reg_getv(anal->reg, gpr_names[tmp.rs]);
        // }
        CREATE_DST_SRC;
        dst->delta = imm;
        dst->reg = gpr_names[tmp.rs];
        dst->type = R_ANAL_VAL_MEM;
        src0->reg = gpr_names[tmp.rt];
        // r_strbuf_set (&op->esil, "")
        op->type = R_ANAL_OP_TYPE_STORE;
        break;

        /* arithmetic */
        case LUI:
        CREATE_DST_SRC;
        dst->reg = gpr_names[tmp.rt];
        dst->type = R_ANAL_VAL_REG;
        src0->imm = imm << 16;
        src0->type = R_ANAL_VAL_IMM;
        r_strbuf_setf (&op->esil, "16,0x%llX,0xffff,&,<<,%s,=", imm, gpr_names[tmp.rt]);
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
        case ADD:
        case ADDU:
        case DADD:
        case DADDU:
        R5900_ARITH(ADD, +) // TODO: these instr should not share same logic

        // if (tmp.opcode == DADDU && tmp.rt == 0) { // move ( daddu rd, rs, zero)
        //     op->type = R_ANAL_OP_TYPE_MOV;
        //     r_anal_value_free (op->srcs[1]);
        //     op->srcs[1] = NULL;
        //     // op->mnemonic = (char*)r_str_newf ("move %s, %s", gpr_names[tmp.rd], gpr_names[tmp.rs]);
        // }
        break;
        case ADDIU:
        case ADDI:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rs];
        src1->imm = imm;
        op->type = R_ANAL_OP_TYPE_ADD;
        r_strbuf_setf (&op->esil, "%lld,%s,+,%s,=",
            imm,
            gpr_names[tmp.rs],
            gpr_names[tmp.rt]);// TODO: these instr should not share same logic
        break;
        case ORI:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rs];
        src1->imm = imm;
        op->type = R_ANAL_OP_TYPE_OR;
        r_strbuf_setf (&op->esil, "%lld,%s,|,%s,=",
            imm,
            gpr_names[tmp.rs],
            gpr_names[tmp.rt]);
        break;
        case XORI:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rs];
        src1->imm = imm;
        op->type = R_ANAL_OP_TYPE_XOR;
        r_strbuf_setf (&op->esil, "%lld,%s,^,%s,=",
            imm,
            gpr_names[tmp.rs],
            gpr_names[tmp.rt]);
        break;
        case ANDI:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rs];
        src1->imm = imm;
        op->type = R_ANAL_OP_TYPE_AND;
        r_strbuf_setf (&op->esil, "%lld,%s,&,%s,=",
            imm,
            gpr_names[tmp.rs],
            gpr_names[tmp.rt]);
        break;
        case SLL:
        case DSLL:
        case DSLL32:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rt];
        src1->imm = tmp.sa;
        r_strbuf_setf (&op->esil, "%s,%llu,<<,%s,=",
            gpr_names[tmp.rt],
            (unsigned long long)tmp.sa,
            gpr_names[tmp.rd]);
        op->type = R_ANAL_OP_TYPE_SHL;
        break;
        case SRL: // TODO : improve the esil gen
        case DSRL:
        case DSRL32:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rt];
        src1->imm = tmp.sa;
        r_strbuf_setf (&op->esil, "%s,%llu,>>,%s,=",
            gpr_names[tmp.rt],
            (unsigned long long)tmp.sa,
            gpr_names[tmp.rd]);
        op->type = R_ANAL_OP_TYPE_SHR;
        break;
        case SRA: // TODO: currently work as SRL, needs further implementation
        case DSRA:
        case DSRA32:
        CREATE_DST_SRC2;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = gpr_names[tmp.rt];
        src1->imm = tmp.sa;
        r_strbuf_setf (&op->esil, "%s,%llu,>>,%s,=",
            gpr_names[tmp.rt],
            (unsigned long long)tmp.sa,
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
        if(tmp.rt == 0) { // padduw rd, rs, zero (qmove rd, rs)
            op->type = R_ANAL_OP_TYPE_MOV;
            r_strbuf_setf (&op->esil, "%sh,%sh,=,%s,%s,=",
                gpr_names[tmp.rs], gpr_names[tmp.rd], gpr_names[tmp.rs], gpr_names[tmp.rd]);
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
        CREATE_DST_SRC;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = "hi";
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "hi,%s,=", gpr_names[tmp.rd]);
        break;
        case MFLO:
        CREATE_DST_SRC;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = "lo";
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "lo,%s,=", gpr_names[tmp.rd]);
        break;
        case MTHI:
        CREATE_DST_SRC;
        dst->reg = "hi";
        src0->reg = gpr_names[tmp.rd];
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "%s,hi,=", gpr_names[tmp.rd]);
        break;
        case MTLO:
        CREATE_DST_SRC;
        dst->reg = "lo";
        src0->reg = gpr_names[tmp.rd];
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "%s,lo,=", gpr_names[tmp.rd]);
        break;
        case MFHI1:
        CREATE_DST_SRC;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = "hih";
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "hih,%s,=", gpr_names[tmp.rd]);
        break;
        case MFLO1:
        CREATE_DST_SRC;
        dst->reg = gpr_names[tmp.rd];
        src0->reg = "loh";
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "loh,%s,=", gpr_names[tmp.rd]);
        break;
        case MTHI1:
        CREATE_DST_SRC;
        dst->reg = "hih";
        src0->reg = gpr_names[tmp.rd];
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "%s,hih,=", gpr_names[tmp.rd]);
        break;
        case MTLO1:
        CREATE_DST_SRC;
        dst->reg = "loh";
        src0->reg = gpr_names[tmp.rd];
        op->type = R_ANAL_OP_TYPE_MOV;
        r_strbuf_setf (&op->esil, "%s,loh,=", gpr_names[tmp.rd]);
        break;
        case MTC1:
        //op->dsts = r_anal_value_new();
        //op->srcs[0] = r_anal_value_new();
        //op->dsts->reg = r_reg_get (anal->reg, "") // TODO: update register spec
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
        case SYNC:
        op->type = R_ANAL_OP_TYPE_SYNC;
        break;
    }

    return 4;
}
#undef R5900_ARITH
#undef R5900_HIARITH
