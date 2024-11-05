#include <r_asm.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_types.h>
#include <r_util/r_strbuf.h>

#include "../../inscodec/xyutils.h"
#include "../../inscodec/codec.c"

// get next word, return the terminating char*
// the buffer will recieve the word this function read.
// 
const char *get_next_word(const char *str, char *buffer) {
    while((*str == ' ' || *str == '\t') && *str != '\0') {
        ++str;
    }

    while((*str >= 'a' && *str <= 'z') ||
        (*str >= 'A' && *str <= 'B') ||
        (*str >= '0' && *str <= '9') ||
        (*str == '.'))
    {
        *buffer++ = *str++;
    }

    *buffer = '\0';
    return str;
}

// target num:
// 
int _get_target_(const char *str) {
    
    if(str[0] == 'i') {
        if(str[1] == 'm') return 1;
    }
    if(str[0] == 's') {
        if(str[1] == 'a') return 2;
    }
    if(str[0] == 'r') {
        if(str[1] == 't') return 3;
        if(str[1] == 'd') return 4;
        if(str[1] == 's') return 5;
    }
    if(str[0] == 'f') {
        if(str[1] == 't') return 3;
        if(str[1] == 's') return 4;
        if(str[1] == 'd') return 2;
    }
}

int r5900_op(RAnalOp *op, ut64 addr, struct instr_t tmp);

int disas(struct instr_t instr, ut32 offset, RAnalOp *op) {
    char mnemonic[128];
    char para_buf[512];
    struct instr_def def = GetInstructionDefinitionByIndex(instr.opcode);
    strcpy(mnemonic, def.name);
    strlwr(mnemonic);
    
    char *orip = def.para;
    char *para = para_buf;

    if(*orip != '_')
    while (*orip != '\0') {
        int type;
        switch (*orip) {
            case '!':
            type = 1;
            break;
            case '$':
            type = 2;
            break;
            case '^':
            type = 3;
            break;
            case '@':
            type = 4;
            break;
            case '#':
            type = 5;
            break;
            case '*':
            case '%':
            case '&':
            type = 6;
            break;
            default:
            *para++ = *orip++;
            goto wh_end;
        }

        unsigned long long value;
        int target = _get_target_(++orip);
        switch(target) {
            case 1:
            value = instr.imm;
            break;
            case 2:
            value = instr.sa;
            break;
            case 3:
            value = instr.rt;
            break;
            case 4:
            value = instr.rd;
            break;
            case 5:
            value = instr.rs;
        }
        if(def.type == IT_imma && target == 1) {
            value += offset + 4;
        }

        switch(type) {
            case 5:
            para += output_int(para, value, 0);
            break;
            case 1:
            case 6:
            para += output_int(para, value, 1);
            break;
            case 2:
            strcpy(para, gpr_names[value]);
            para += strlen(gpr_names[value]);
            break;
            case 3:
            strcpy(para, cop0r_names[value]);
            para += strlen(cop0r_names[value]);
            break;
            case 4:
            strcpy(para, cop1r_names[value]);
            para += strlen(cop1r_names[value]);
            break;
        }

        orip += 2;

        wh_end:;
    }

    *para = '\0';
    //sprintf(buffer, "%s %s",mnemonic, para_buf);
    if (*orip == '_') op->mnemonic = r_str_newf("%s", mnemonic);
    else op->mnemonic = r_str_newf("%s %s", mnemonic, para_buf);
    return 4;
}

int as(const char *str, ut32 offset, struct instr_t *result) {
    char buffer[128]; // may overflow, need to improve in the future.
    const char *next = get_next_word(str, buffer);
    if(buffer[0] == '\0') return -10;
    
    int option = -1;
    strupr(buffer);
    for (int i = 0; i < OPTION_COUNT; ++i)
	{
		if (strcmp(instructions[i].name,  buffer) == 0)
			option = i;
	}
    if(option == -1) return -17;

    result->opcode = option;
    result->imm = 0;
    result->rs = 0;
    result->rt = 0;
    result->rd = 0;

    struct instr_def def;
    def = GetInstructionDefinitionByIndex(option);
    const char *para = str_first_not(next, ' ');
    
    if(*para == '\0' && def.para[0] != '_') {
        return -11;
    }

    if(*para != '\0' && def.para[0] == '_') {
        return -16;
    }

    if(def.para[0] == '_') return 0;
    
    const char *orip = def.para;
    while (*orip != '\0') {
        if(*para == '\0') return -20;

        long long value;
        int tmp;
        switch (*orip) {
            case '!':
            tmp = parse_int(&value, para);
            if(tmp == -1) return -12; // format error
            para += tmp;
            break;
            case '$':
            para = get_next_word(para, buffer);
            value = index_of(gpr_names, 32, buffer);
            break;
            case '^':
            para = get_next_word(para, buffer);
            value = index_of(cop0r_names, 32, buffer);
            break;
            case '@':
            para = get_next_word(para, buffer);
            value = index_of(cop1r_names, 32, buffer);
            break;
            case '#':
            case '&':
            tmp = parse_int(&value, para);
            if(tmp == -1) return -13; // format error
            para += tmp;
            break;
            case '*':
            case '%':
            tmp = parse_int(&value, para);
            if(tmp == -1) return -14; // format error
            para += tmp;
            if(value < 0) return -15;
            break;
            default:
            if(*para != *orip) return -30;
            if(*orip == ' ') {
                para = str_first_not(para, ' ');
                ++orip;
                goto wh_end; // jump to while's end
            }

            ++orip, ++para;
            goto wh_end;
        }

        switch(_get_target_(++orip)) {
            case 1:
            result->imm = value;
            break;
            case 2:
            result->sa = value;
            break;
            case 3:
            result->rt = value;
            break;
            case 4:
            result->rd = value;
            break;
            case 5:
            result->rs = value;
        }

        if(def.type == IT_imma) {
            result->imm -= offset + 4;
        }

        orip += 2;

        wh_end:;
    }
    return 0;
}

#ifndef TEST
static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
    ut64 offset = op->addr;
    ut8 *buf = op->bytes;
    int len = op->size;

    if (len < 4) return -1;
    op->size = 4;
    ut32 instr;
    memcpy(&instr, buf, 4);

    disas(DecodeInstruction(instr), offset, op);
    r5900_op(op, offset, DecodeInstruction(instr));
    return true;
}

static bool encode(RArchSession *a, RAnalOp *op, RArchEncodeMask mask) {
    struct instr_t tmp;
    int ret = as(op->mnemonic, op->addr, &tmp);
    if(ret) {
        return false;
    }

    ut32 result = EncodeInstruction(tmp);
    free(op->bytes);
    op->bytes = r_mem_dup(&result, 4);
    op->size = 4;
    return true;
}

bool init(RArchSession *as) {
    R_RETURN_VAL_IF_FAIL (as, false);

    PrepareOpcodeBuffer();
    return true;
}

static char *regs(RArchSession *as) {
    return strdup(
    "=PC    pc\n"
    "=SP    sp\n"
    "=BP    fp\n"
    "=A0    a0\n"
    "=A1    a1\n"
    "=A2    a2\n"
    "=A3    a3\n"
    "=SN    v0\n"
    "=R0    v0\n"
    "=R1    v1\n"
    "gpr    zero    .64 0   0\n"
    "gpr    zeroh   .64 8   0\n"
    "gpr    at  .64 16  0\n"
    "gpr    ath .64 24  0\n"
    "gpr    v0  .64 32  0\n"
    "gpr    v0h .64 40  0\n"
    "gpr    v1  .64 48  0\n"
    "gpr    v1h .64 56  0\n"
    "gpr    a0  .64 64  0\n"
    "gpr    a0h .64 72  0\n"
    "gpr    a1  .64 80  0\n"
    "gpr    a1h .64 88  0\n"
    "gpr    a2  .64 96  0\n"
    "gpr    a2h .64 104 0\n"
    "gpr    a3  .64 112 0\n"
    "gpr    a3h .64 120 0\n"
    "gpr    t0  .64 128 0\n"
    "gpr    t0h .64 136 0\n"
    "gpr    t1  .64 144 0\n"
    "gpr    t1h .64 152 0\n"
    "gpr    t2  .64 160 0\n"
    "gpr    t2h .64 168 0\n"
    "gpr    t3  .64 176 0\n"
    "gpr    t3h .64 184 0\n"
    "gpr    t4  .64 192 0\n"
    "gpr    t4h .64 200 0\n"
    "gpr    t5  .64 208 0\n"
    "gpr    t5h .64 216 0\n"
    "gpr    t6  .64 224 0\n"
    "gpr    t6h .64 232 0\n"
    "gpr    t7  .64 240 0\n"
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
    "gpr    k0  .64 400 0\n"
    "gpr    k0h .64 408 0\n"
    "gpr    k1  .64 416 0\n"
    "gpr    k1h .64 424 0\n"
    "gpr    gp  .64 432 0\n"
    "gpr    gph .64 440 0\n"
    "gpr    sp  .64 448 0\n"
    "gpr    sph .64 456 0\n"
    "gpr    fp  .64 464 0\n"
    "gpr    fph .64 472 0\n"
    "gpr    ra  .64 480 0\n"
    "gpr    rah .64 488 0\n"
    "gpr    pc  .64 496 0\n"
    "gpr    pch .64 504 0\n"
    "gpr    lo  .64 512 0\n"
    "gpr    loh .64 520 0\n"
    "gpr    hi  .64 528 0\n"
    "gpr    hih .64 536 0\n");
}

static int r5900_archinfo(RArchSession *as, ut32 query) {
    return 4;
}

RArchPlugin r_arch_plugin_r5900 = {
    .meta = {
        .name = "r5900",
        .author = "xiyan",
        .license = "MIT",
        .desc = "r5900(aka. TX79) little endian assembly plugin"
    },
    .arch = "mips",
    .cpus = "r5900",
    .bits = 64,
    .regs = regs,
    .info = r5900_archinfo,
    .encode = encode,
    .decode = decode,
    .init = init,
    .endian = R_SYS_ENDIAN_LITTLE,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ARCH,
    .data = &r_arch_plugin_r5900,
    .version = R2_VERSION
};
#endif

#endif