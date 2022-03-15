#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../inscodec/codec.c"

static int r5900_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
    ut32 instr;
    memcpy(&instr, data, 4);

    op->addr = addr;
    op->type = R_ANAL_OP_TYPE_UNK;
    op->size = 4;

    struct instr_t tmp = DecodeInstruction(instr);

    switch(tmp.opcode) {
        case NOP:
        op->type = R_ANAL_OP_TYPE_NOP;
        break;
    }

    return 4;
}

static bool set_r5900_reg_profile(RAnal* anal) {
    const char *p =
    "=PC    pc\n"
    "=SP    sp\n"
    "=BP    fp\n"
    "=A0    a0\n"
    "=A1    a1\n"
    "=A2    a2\n"
    "=A3    a3\n"
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
	"gpr	k0	.64	256	0\n"
    "gpr    k0h .64 264 0\n"
	"gpr	k1	.64	272	0\n"
    "gpr    k1h .64 280 0\n"
	"gpr	gp	.64	288	0\n"
    "gpr    gph .64 296 0\n"
	"gpr	sp	.64	304	0\n"
    "gpr    sph .64 312 0\n"
	"gpr	fp	.64	320	0\n"
    "gpr    fph .64 328 0\n"
	"gpr	ra	.64	336	0\n"
    "gpr    rah .64 344 0\n"
	"gpr	pc	.64	352	0\n";
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
    .esil = false,
    .set_reg_profile = set_r5900_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_r5900,
    .version = R2_VERSION
};
#endif
