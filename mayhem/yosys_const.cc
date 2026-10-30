// libFuzzer harness: yosys constant-folding kernel (RTLIL::const_* in kernel/calc.cc, CellTypes::eval,
// Const string round-trips) on 4-state inputs, plus a uint64 reference check for 2-state unsigned operands.
#include <cstddef>
#include <cstdint>
#include <string>

#include "kernel/celltypes.h"
#include "kernel/rtlil.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE

namespace {

struct Op {
	const char *type;
	RTLIL::IdString id;
	RTLIL::Const (*fn)(const RTLIL::Const &, const RTLIL::Const &, bool, bool, int);
};

#define OP(n) {"$" #n, ID($##n), RTLIL::const_##n}
const Op ops[] = {
	OP(not), OP(and), OP(or), OP(xor), OP(xnor), OP(reduce_and),
	OP(reduce_or), OP(reduce_xor), OP(reduce_xnor), OP(reduce_bool), OP(logic_not), OP(logic_and),
	OP(logic_or), OP(shl), OP(shr), OP(sshl), OP(sshr), OP(shift),
	OP(shiftx), OP(lt), OP(le), OP(eq), OP(ne), OP(eqx),
	OP(nex), OP(ge), OP(gt), OP(add), OP(sub), OP(mul),
	OP(div), OP(mod), OP(divfloor), OP(modfloor), OP(pow), OP(pos),
	OP(neg),
};
#undef OP
const size_t nops = sizeof(ops) / sizeof(ops[0]);

struct Reader {
	const uint8_t *p;
	size_t n;
	unsigned bitpos = 0;
	uint8_t byte() { return n ? (n--, *p++) : 0; }
	RTLIL::Const cnst(int width, bool four_state)
	{
		std::vector<RTLIL::State> bits;
		for (int i = 0; i < width; i++) {
			unsigned v = (n ? p[0] : 0) >> bitpos;
			bitpos += four_state ? 2 : 1;
			if (bitpos >= 8) { bitpos = 0; if (n) { p++; n--; } }
			if (four_state)
				bits.push_back((RTLIL::State)(v & 3));
			else
				bits.push_back((v & 1) ? RTLIL::State::S1 : RTLIL::State::S0);
		}
		if (bitpos) { bitpos = 0; if (n) { p++; n--; } }
		return RTLIL::Const(bits);
	}
};

bool two_state_u64(const RTLIL::Const &c, uint64_t &out)
{
	out = 0;
	for (int i = 0; i < GetSize(c); i++) {
		if (c[i] == RTLIL::State::S1) {
			if (i >= 64) return false;
			out |= (uint64_t)1 << i;
		} else if (c[i] != RTLIL::State::S0)
			return false;
	}
	return true;
}

bool initialized = false;

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 6)
		return -1;
	if (!initialized) {
		Yosys::yosys_setup();
		initialized = true;
	}
	Reader r{data, size};
	unsigned sel = r.byte();
	const Op &op = ops[sel % nops];
	unsigned flags = r.byte();
	bool signed1 = flags & 1, signed2 = flags & 2, four_state = flags & 4;
	int w1 = r.byte() % 131, w2 = r.byte() % 131, wy = 1 + r.byte() % 130;
	RTLIL::Const a = r.cnst(w1, four_state), b = r.cnst(w2, four_state);

	RTLIL::Const y = op.fn(a, b, signed1, signed2, wy);
	if (GetSize(y) != wy)
		__builtin_trap();

	bool err = false;
	RTLIL::Const y2 = CellTypes::eval(op.id, a, b, signed1, signed2, wy, &err);
	if (!err && GetSize(y2) != wy)
		__builtin_trap();

	// Reference check: 2-state unsigned operands narrower than 64 bits.
	uint64_t ua, ub, uy;
	if (!four_state && !signed1 && !signed2 && w1 <= 32 && w2 <= 32 && wy <= 64 &&
	    two_state_u64(a, ua) && two_state_u64(b, ub) && two_state_u64(y, uy)) {
		uint64_t mask = wy == 64 ? ~(uint64_t)0 : (((uint64_t)1 << wy) - 1);
		const std::string t = op.type;
		bool check = true;
		uint64_t want = 0;
		if (t == "$add") want = ua + ub;
		else if (t == "$sub") want = ua - ub;
		else if (t == "$mul") want = ua * ub;
		else if (t == "$and") want = ua & ub;
		else if (t == "$or") want = ua | ub;
		else if (t == "$xor") want = ua ^ ub;
		else if (t == "$lt") want = ua < ub;
		else if (t == "$ge") want = ua >= ub;
		else if (t == "$eq") want = ua == ub;
		else if (t == "$ne") want = ua != ub;
		else if (t == "$div" && ub) want = ua / ub;
		else if (t == "$mod" && ub) want = ua % ub;
		else if (t == "$shl") want = ub >= 64 ? 0 : ua << ub;
		else if (t == "$shr") want = ub >= 64 ? 0 : ua >> ub;
		else check = false;
		if (check && uy != (want & mask))
			__builtin_trap();
	}

	// Const <-> string round trips.
	std::string s = a.as_string();
	RTLIL::Const back = RTLIL::Const::from_string(s);
	if (!(back == a))
		__builtin_trap();
	(void)a.as_int(signed1);
	(void)a.as_bool();
	(void)a.is_fully_def();
	(void)a.try_as_int(signed2);
	if (!four_state && w1 % 8 == 0)
		(void)a.decode_string();
	RTLIL::Const ext = a;
	ext.extu(wy);
	return 0;
}
