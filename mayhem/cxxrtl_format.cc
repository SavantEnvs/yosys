// libFuzzer harness: cxxrtl runtime Verilog-style number formatting (cxxrtl::fmt_part::render).
// Differential oracle: an independent byte-vector big-number conversion of the same value.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cxxrtl/cxxrtl.h"

using namespace cxxrtl;

namespace {

struct Params {
	bool signed_, group, show_base, hex_upper;
	unsigned base;
	int sign, justify;
	char padding;
	size_t width;
};

std::string reference(const std::vector<uint8_t> &bytes_in, size_t bits, const Params &p)
{
	std::vector<uint8_t> v = bytes_in;
	bool negative = p.signed_ && ((v[(bits - 1) / 8] >> ((bits - 1) % 8)) & 1);
	std::string prefix;
	if (negative) {
		prefix = "-";
		unsigned carry = 1;
		for (size_t i = 0; i < v.size(); i++) {
			unsigned x = (uint8_t)~v[i] + carry;
			v[i] = (uint8_t)x;
			carry = x >> 8;
		}
		if (bits % 8)
			v.back() &= (uint8_t)(0xff >> (8 - bits % 8));
	} else {
		if (p.sign == 1) prefix = "+";
		if (p.sign == 2) prefix = " ";
	}
	std::string digits;
	if (p.base == 10) {
		if (p.show_base) prefix += "0d";
		bool zero = true;
		for (uint8_t b : v) if (b) zero = false;
		if (zero) digits = "0";
		while (!zero) {
			unsigned rem = 0;
			for (size_t i = v.size(); i-- > 0;) {
				unsigned cur = rem * 256 + v[i];
				v[i] = (uint8_t)(cur / 10);
				rem = cur % 10;
			}
			digits += (char)('0' + rem);
			zero = true;
			for (uint8_t b : v) if (b) zero = false;
		}
	} else {
		size_t top = 0;
		for (size_t i = 0; i < bits; i++)
			if ((v[i / 8] >> (i % 8)) & 1) top = i + 1;
		if (top == 0) top = 1;
		size_t step = p.base == 2 ? 1 : p.base == 8 ? 3 : 4;
		if (p.show_base)
			prefix += p.base == 2 ? "0b" : p.base == 8 ? "0o" : (p.hex_upper ? "0X" : "0x");
		for (size_t i = 0; i < top; i += step) {
			unsigned d = 0;
			for (size_t k = 0; k < step; k++) {
				size_t idx = i + k;
				if (idx < bits && ((v[idx / 8] >> (idx % 8)) & 1)) d |= 1u << k;
			}
			digits += (p.hex_upper ? "0123456789ABCDEF" : "0123456789abcdef")[d];
		}
	}
	return prefix + std::string(digits.rbegin(), digits.rend());
}

template<size_t Bits>
int run(const uint8_t *data, size_t size, const Params &p_in)
{
	Params p = p_in;
	const size_t nbytes = (Bits + 7) / 8;
	std::vector<uint8_t> bytes(nbytes, 0);
	for (size_t i = 0; i < nbytes && i < size; i++)
		bytes[i] = data[i];
	if (Bits % 8)
		bytes.back() &= (uint8_t)(0xff >> (8 - Bits % 8));

	value<Bits> val;
	for (size_t i = 0; i < Bits; i++)
		if ((bytes[i / 8] >> (i % 8)) & 1)
			val.data[i / value<Bits>::chunk::bits] |= (chunk_t)1 << (i % value<Bits>::chunk::bits);

	fmt_part part = {};
	part.type = fmt_part::INTEGER;
	part.justify = fmt_part::RIGHT;
	part.padding = ' ';
	part.width = 0;
	part.base = p.base;
	part.signed_ = p.signed_;
	part.sign = (decltype(part.sign))p.sign;
	part.hex_upper = p.hex_upper;
	part.show_base = p.show_base;
	part.group = false;
	std::string actual = part.render(val);
	std::string expected = reference(bytes, Bits, p);
	if (actual != expected)
		__builtin_trap();

	part.group = p.group;
	part.justify = (decltype(part.justify))p.justify;
	part.padding = p.padding;
	part.width = p.width;
	std::string padded = part.render(val);
	if (padded.size() < p.width)
		__builtin_trap();
	return 0;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 7)
		return -1;
	static const unsigned bases[] = {2, 8, 10, 16};
	static const char paddings[] = {' ', '0', '_', 'x'};
	Params p;
	p.signed_ = data[1] & 1;
	p.group = data[1] & 2;
	p.show_base = data[1] & 4;
	p.hex_upper = data[1] & 8;
	p.base = bases[data[2] & 3];
	p.sign = (data[2] >> 2) % 3;
	p.justify = (data[3] & 3) % 3;
	p.padding = paddings[(data[3] >> 2) & 3];
	p.width = data[4] % 80;
	const uint8_t *val = data + 5;
	size_t n = size - 5;
	switch (data[0] % 14) {
		case 0: return run<1>(val, n, p);
		case 1: return run<2>(val, n, p);
		case 2: return run<3>(val, n, p);
		case 3: return run<7>(val, n, p);
		case 4: return run<8>(val, n, p);
		case 5: return run<13>(val, n, p);
		case 6: return run<31>(val, n, p);
		case 7: return run<32>(val, n, p);
		case 8: return run<33>(val, n, p);
		case 9: return run<64>(val, n, p);
		case 10: return run<65>(val, n, p);
		case 11: return run<100>(val, n, p);
		case 12: return run<128>(val, n, p);
		default: return run<200>(val, n, p);
	}
}
