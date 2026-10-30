// libFuzzer harness: cxxrtl runtime value<Bits> arithmetic against an unsigned __int128 reference.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "cxxrtl/cxxrtl.h"

using namespace cxxrtl;

namespace {

typedef unsigned __int128 u128;
typedef __int128 s128;

template<size_t Bits>
u128 mask128()
{
	return Bits == 128 ? ~(u128)0 : (((u128)1 << Bits) - 1);
}

template<size_t Bits>
value<Bits> to_value(u128 x)
{
	value<Bits> v;
	for (size_t i = 0; i < value<Bits>::chunks; i++)
		v.data[i] = (chunk_t)(x >> (i * 32));
	v.data[value<Bits>::chunks - 1] &= value<Bits>::msb_mask;
	return v;
}

template<size_t Bits>
u128 from_value(const value<Bits> &v)
{
	u128 x = 0;
	for (size_t i = 0; i < value<Bits>::chunks; i++)
		x |= (u128)v.data[i] << (i * 32);
	return x;
}

template<size_t Bits>
s128 sext128(u128 x)
{
	if (Bits == 128)
		return (s128)x;
	return (s128)(x << (128 - Bits)) >> (128 - Bits);
}

template<size_t Bits>
void check(u128 got, u128 want)
{
	if (got != (want & mask128<Bits>()))
		__builtin_trap();
}

template<size_t Bits>
int run(unsigned op, u128 a, u128 b)
{
	a &= mask128<Bits>();
	b &= mask128<Bits>();
	value<Bits> va = to_value<Bits>(a), vb = to_value<Bits>(b);
	u128 shamt = b >= 128 ? 128 : b;
	switch (op) {
		case 0: check<Bits>(from_value(va.add(vb)), a + b); break;
		case 1: check<Bits>(from_value(va.sub(vb)), a - b); break;
		case 2: check<Bits>(from_value(va.neg()), (u128)0 - a); break;
		case 3: check<Bits>(from_value(va.bit_and(vb)), a & b); break;
		case 4: check<Bits>(from_value(va.bit_or(vb)), a | b); break;
		case 5: check<Bits>(from_value(va.bit_xor(vb)), a ^ b); break;
		case 6: check<Bits>(from_value(va.bit_not()), ~a); break;
		case 7: check<Bits>(from_value(va.shl(vb)), shamt >= 128 ? 0 : a << (unsigned)shamt); break;
		case 8: check<Bits>(from_value(va.shr(vb)), shamt >= 128 ? 0 : a >> (unsigned)shamt); break;
		case 9: {
			s128 sa = sext128<Bits>(a);
			unsigned sh = shamt >= 127 ? 127 : (unsigned)shamt;
			check<Bits>(from_value(va.sshr(vb)), (u128)(sa >> sh));
			break;
		}
		case 10: {
			size_t want = 0;
			if (a == 0) want = Bits;
			else {
				uint64_t hi = (uint64_t)(a >> 64), lo = (uint64_t)a;
				want = (hi ? __builtin_clzll(hi) : 64 + __builtin_clzll(lo)) - (128 - Bits);
			}
			if (va.ctlz() != want) __builtin_trap();
			break;
		}
		case 11: {
			size_t want = __builtin_popcountll((uint64_t)a) + __builtin_popcountll((uint64_t)(a >> 64));
			if (va.ctpop() != want) __builtin_trap();
			break;
		}
		case 12:
			if (va.ucmp(vb) != (a < b)) __builtin_trap();
			break;
		case 13:
			if (va.scmp(vb) != (sext128<Bits>(a) < sext128<Bits>(b))) __builtin_trap();
			break;
		case 14: {
			if (b == 0) return -1;
			auto qr = va.udivmod(vb);
			check<Bits>(from_value(std::get<0>(qr)), a / b);
			check<Bits>(from_value(std::get<1>(qr)), a % b);
			break;
		}
		case 15: {
			if (b == 0) return -1;
			s128 sa = sext128<Bits>(a), sb = sext128<Bits>(b);
			if (sb == -1 && sa == (s128)((u128)1 << 127)) return -1;
			auto qr = va.sdivmod(vb);
			check<Bits>(from_value(std::get<0>(qr)), (u128)(sa / sb));
			check<Bits>(from_value(std::get<1>(qr)), (u128)(sa % sb));
			break;
		}
		case 16: {
			u128 m = (a ^ (b << 1)) & mask128<Bits>();
			check<Bits>(from_value(va.bwmux(vb, to_value<Bits>(m))), (a & ~m) | (b & m));
			break;
		}
	}
	return 0;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 34)
		return -1;
	u128 a, b;
	memcpy(&a, data + 2, 16);
	memcpy(&b, data + 18, 16);
	unsigned op = data[1] % 17;
	switch (data[0] % 9) {
		case 0: return run<1>(op, a, b);
		case 1: return run<8>(op, a, b);
		case 2: return run<31>(op, a, b);
		case 3: return run<32>(op, a, b);
		case 4: return run<42>(op, a, b);
		case 5: return run<63>(op, a, b);
		case 6: return run<64>(op, a, b);
		case 7: return run<100>(op, a, b);
		default: return run<128>(op, a, b);
	}
}
