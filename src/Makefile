LLVM_PROFDATA=$(dirname $LLVM_CLANG)/llvm-profdata
LLVM_CLANG=$(shell afl-clang-fast -print-prog-name=clang)
CONNMAND_BIN = /home/bobro/Desktop/diplom/src/connman-1.32/src/connmand

build: afl cov

afl:
	afl-clang-fast -O0 -g $(shell pkg-config --cflags glib-2.0) \
  	-o dhcp-wrapper main.c $(shell pkg-config --libs glib-2.0) -lpcap -lsystemd

cov:
	clang -O0 -g -fprofile-instr-generate -fcoverage-mapping \
      $(shell pkg-config --cflags glib-2.0) \
      -o dhcp-wrapper_cov main.c $(shell pkg-config --libs glib-2.0) -lpcap -lsystemd

afl-fuzz:
	afl-fuzz -t 3000 -i seeds -o out -- ./dhcp-wrapper @@

gen:
	rm -rf cov_data
	mkdir -p cov_data
	for testcase in out/default/queue/id:*; do \
		[ -f "$$testcase" ] || continue; \
		sudo -E LLVM_PROFILE_FILE="cov_data/$$(basename $$testcase).profraw" \
		timeout 30 ./dhcp-wrapper_cov "$$testcase"; \
	done

html:
	sudo llvm-profdata merge -sparse cov_data/*.profraw -o cov_data/merged.profdata
	sudo rm -rf coverage_report
	mkdir -p coverage_report
	chmod 777 coverage_report
	sudo llvm-cov show $(CONNMAND_BIN) \
			-object ./dhcp-wrapper_cov \
    		-instr-profile=cov_data/merged.profdata \
    		-format=html \
    		-output-dir=coverage_report/

test:
	sudo ./dhcp-wrapper seeds/dhcp_packet_1.pcap