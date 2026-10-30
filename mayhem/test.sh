#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer functional checks of the yosys driver that mayhem/build.sh built in
# build-tests/ (normal flags). Every check parses the driver's own output for a specific value.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


YOSYS="$SRC/build-tests/yosys"
[ -x "$YOSYS" ] || { echo "test.sh: $YOSYS missing; mayhem/build.sh did not build it" >&2; emit_ctrf "yosys-known-answer" 0 1 0; exit 1; }

W=$(mktemp -d "${TMPDIR:-/tmp}/yosys-test.XXXXXX")
trap 'rm -rf "$W"' EXIT
cd "$W"

passed=0; failed=0
check() { # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then passed=$((passed+1)); echo "PASS $1"
  else failed=$((failed+1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}
ys() { "$YOSYS" -p "$1" 2>&1; }

cat > alu.v <<'V'
module alu(input [7:0] a, input [7:0] b, output [7:0] s, output [7:0] p, output lt);
  assign s = a + b;
  assign p = a * b;
  assign lt = a < b;
endmodule
V
cat > add4.v <<'V'
module adder(input [3:0] a, input [3:0] b, output [3:0] y);
  assign y = a + b;
endmodule
V

# 1. version banner
check "version banner" "1" "$("$YOSYS" -V 2>&1 | grep -Ec '^Yosys [0-9]+\.[0-9]+')"

# 2. constant evaluation of a synthesised-from-Verilog module
out=$(ys "read_verilog alu.v; hierarchy -top alu; proc; eval -set a 200 -set b 100 -show s -show p -show lt")
check "eval 200+100 mod 256" "\\s = 8'00101100" "$(echo "$out" | grep -o '\\s = [0-9]*'"'"'[01]*' | head -1)"
check "eval 200*100 mod 256" "\\p = 8'00100000" "$(echo "$out" | grep -o '\\p = [0-9]*'"'"'[01]*' | head -1)"
check "eval 200<100" "\\lt = 1'0" "$(echo "$out" | grep -o '\\lt = [0-9]*'"'"'[01]*' | head -1)"
out=$(ys "read_verilog alu.v; hierarchy -top alu; proc; eval -set a 3 -set b 250 -show lt")
check "eval 3<250" "\\lt = 1'1" "$(echo "$out" | grep -o '\\lt = [0-9]*'"'"'[01]*' | head -1)"

# 3. SAT proofs: a true statement is proved, a false one refuted
out=$(ys "read_verilog add4.v; proc; sat -set a 3 -set b 4 -prove y 7")
check "sat proves 3+4=7" "SAT proof finished - no model found: SUCCESS!" "$(echo "$out" | grep 'SAT proof finished')"
out=$(ys "read_verilog add4.v; proc; sat -set a 3 -set b 4 -prove y 8")
check "sat refutes 3+4=8" "SAT proof finished - model found: FAIL!" "$(echo "$out" | grep 'SAT proof finished')"
out=$(ys "read_verilog add4.v; proc; sat -set a 9 -set b 9 -prove y 2")
check "sat proves 9+9=2 mod 16" "SAT proof finished - no model found: SUCCESS!" "$(echo "$out" | grep 'SAT proof finished')"

# 4. gate-level mapping statistics for a 4-bit adder
out=$(ys "read_verilog add4.v; proc; opt; techmap; opt; stat")
check "techmap cells" "14 cells" "$(echo "$out" | grep -o '[0-9]* cells$' | tail -1)"
check "techmap XOR count" "7 \$_XOR_" "$(echo "$out" | grep -o '[0-9]* *\$_XOR_' | tr -s ' ')"
check "techmap AND count" "5 \$_AND_" "$(echo "$out" | grep -o '[0-9]* *\$_AND_' | tr -s ' ')"

# 5. Verilog writer golden output
got=$("$YOSYS" -q -p "read_verilog add4.v; proc; opt; write_verilog -noattr -" 2>&1 | grep -v '^/\*' | grep -v '^$')
want=$(cat <<'V'
module adder(a, b, y);
  input [3:0] a;
  wire [3:0] a;
  input [3:0] b;
  wire [3:0] b;
  output [3:0] y;
  wire [3:0] y;
  assign y = a + b;
endmodule
V
)
check "write_verilog golden" "$want" "$got"

# 6. JSON and RTLIL round trips preserve the design
"$YOSYS" -q -p "read_verilog add4.v; proc; opt; write_json add4.json; write_rtlil add4.il" >/dev/null 2>&1
check "json has \$add cell" "1" "$(grep -c '"type": "\$add"' add4.json)"
check "json round trip" "$want" "$("$YOSYS" -q -p "read_json add4.json; write_verilog -noattr -" 2>&1 | grep -v '^/\*' | grep -v '^$')"
check "rtlil round trip" "$want" "$("$YOSYS" -q -p "read_rtlil add4.il; write_verilog -noattr -" 2>&1 | grep -v '^/\*' | grep -v '^$')"

# 7. random-vector cross-check of cell models (const evaluation vs. techmapped gates, via SAT)
for cell in '$add' '$sub' '$mul' '$shl' '$lt' '$xor' '$and' '$eq'; do
  check "test_cell $cell" "20" "$(ys "test_cell -n 20 -s 7 $cell" | grep -c 'Eval testing: ok.')"
done

emit_ctrf "yosys-known-answer" "$passed" "$failed" 0
