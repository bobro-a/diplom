LLVM_PROFDATA=$(dirname $LLVM_CLANG)/llvm-profdata
LLVM_CLANG=$(shell afl-clang-fast -print-prog-name=clang)

build: afl cov

afl:
	afl-clang-fast -O2 -g $(shell pkg-config --cflags glib-2.0) \
  	-o dhcp-wrapper main.c $(shell pkg-config --libs glib-2.0) -lpcap

cov:
	clang-19 -O0 -g -fprofile-instr-generate -fcoverage-mapping \
      $(shell pkg-config --cflags glib-2.0) \
      -o dhcp-wrapper_cov main.c $(shell pkg-config --libs glib-2.0) -lpcap

afl-fuzz:
	afl-fuzz -i seeds -o out -t 500 -- ./dhcp-wrapper @@

gen:
	for testcase in out/default/queue/id:*; do \
    [ -f "$testcase" ] && \
    LLVM_PROFILE_FILE="cov_data/$(basename $testcase).profraw" \
    timeout 30 ./dhcp-wrapper_cov "$testcase" \
    done

find:
	find cov_data -name "*.profraw" -print0 | \
    xargs -0 llvm-profdata-19 merge -sparse -o cov_data/merged.profdata

html:
	llvm-cov-19 show ./dhcp-wrapper_cov \
    		-instr-profile=cov_data/merged.profdata \
    		-format=html \
    		-output-dir=coverage_report/

test:
	./dhcp-wrapper seeds/dhcp_packet_00000_20251217145830.pcap