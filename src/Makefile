LLVM_PROFDATA=$(dirname $LLVM_CLANG)/llvm-profdata
LLVM_CLANG=$(shell afl-clang-fast -print-prog-name=clang)
CFLAGS = $(shell pkg-config --cflags glib-2.0)
LDFLAGS = $(shell pkg-config --libs glib-2.0)
PWD =$(shell pwd)
CONNMAND_BIN = /home/bobro/Desktop/diplom/src/connman-1.32/src/connmand

afl:
	afl-clang-fast -O0 -g -fsanitize=address $(CFLAGS) \
  	-o dhcp-wrapper main.c utils.c $(LDFLAGS) -lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	$(PWD)/connman-1.32/gdhcp/src_connmand-common.o

clang:
	clang -O0 -g -fprofile-instr-generate -fcoverage-mapping \
	-mllvm -runtime-counter-relocation \
      $(CFLAGS) \
      -o dhcp-wrapper_cov main.c utils.c $(LDFLAGS) -lpcap -lsystemd \
	  -I/usr/include/x86_64-linux-gnu/ \
	  $(PWD)/connman-1.32/gdhcp/src_connmand-common.o

afl-fuzz:
	sudo -E afl-fuzz -t 8000 -i seeds -o out -- ./dhcp-wrapper @@

gen:
	rm -rf cov_data
	mkdir -p cov_data
	sudo chmod -R 777 out/default/
	for testcase in out/default/queue/id:*; do \
		[ -f "$$testcase" ] || continue; \
		sudo -E LLVM_PROFILE_FILE="cov_data/$$(basename $$testcase)_%c_%m_%p.profraw" \
		timeout 30 ./dhcp-wrapper_cov "$$testcase" || true; \
	done
	

crash:
	for testcase in out/default/crashes/id:*; do \
		[ -f "$$testcase" ] || continue; \
		sudo -E LLVM_PROFILE_FILE="cov_data/$$(basename $$testcase)_%c_%m_%p.profraw" \
		timeout 30 ./dhcp-wrapper_cov "$$testcase" || true; \
	done

html:
	sudo llvm-profdata merge -sparse cov_data/*.profraw -o cov_data/merged.profdata
	sudo rm -rf coverage_report
	mkdir -p coverage_report
	sudo chmod 777 coverage_report
	sudo llvm-cov show $(CONNMAND_BIN) \
			-object ./dhcp-wrapper_cov \
    		-instr-profile=cov_data/merged.profdata \
    		-format=html \
    		-output-dir=coverage_report/

test:
	sudo ./dhcp-wrapper seeds/few_input.pcap

testv6:
	sudo ./dhcp-wrapper seeds/dhcpv6_packet_1.pcap

mutators:
	clang -shared -Wall -O3 \
	-I/home/bobro/Desktop/diplom/src/AFLplusplus/include/ \
	$(CFLAGS) $(LDFLAGS) \
	mutator_dhcpv4.c connman-1.32/gdhcp/common.c \
	-o mutator_dhcpv4.so
	clang -shared -Wall -O3 \
	-I/home/bobro/Desktop/diplom/src/AFLplusplus/include/ \
	$(CFLAGS) $(LDFLAGS) \
	mutator_dhcpv6.c connman-1.32/gdhcp/common.c \
	-o mutator_dhcpv6.so