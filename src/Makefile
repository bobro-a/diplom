LLVM_PROFDATA=$(dirname $LLVM_CLANG)/llvm-profdata
LLVM_CLANG=$(shell afl-clang-fast -print-prog-name=clang)
CFLAGS = $(shell pkg-config --cflags glib-2.0)
LDFLAGS = $(shell pkg-config --libs glib-2.0)
PWD =$(shell pwd)
CONNMAND_BIN = $(PWD)/connman-1.32/src/connmand
CONNMAND_BIN_2 =  $(PWD)/connman-2.0/src/connmand

afl:
	AFL_USE_ASAN=1 afl-clang-fast -O0 -g $(CFLAGS) \
  	-o dhcp-wrapper main.c utils.c $(LDFLAGS) \
	-lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	$(PWD)/connman-1.32/gdhcp/src_connmand-common.o \
	$(PWD)/connman-1.32/src/connmand-log.o \
	$(PWD)/connman-1.32/src/connmand-backtrace.o

afl2:
	afl-clang-fast -O0 -g -fsanitize=address $(CFLAGS) \
  	-o dhcp-wrapper main.c utils.c $(LDFLAGS) -lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	$(PWD)/connman-2.0/gdhcp/src_connmand-common.o \
	$(PWD)/connman-2.0/src/connmand-util.o \
	$(PWD)/connman-2.0/src/connmand-log.o \
	$(PWD)/connman-2.0/src/connmand-backtrace.o

clang:
	clang -O0 -g -fprofile-instr-generate -fcoverage-mapping \
	-mllvm -runtime-counter-relocation \
      $(CFLAGS) \
      -o dhcp-wrapper_cov main.c utils.c $(LDFLAGS) -lpcap -lsystemd \
	  -I/usr/include/x86_64-linux-gnu/ \
	  $(PWD)/connman-1.32/gdhcp/src_connmand-common.o \
	$(PWD)/connman-1.32/src/connmand-log.o \
	$(PWD)/connman-1.32/src/connmand-backtrace.o

afl-fuzz:
	sudo -E afl-fuzz -t 10000 -i seeds -o out -- ./dhcp-wrapper @@

gen:
	rm -rf cov_data
	mkdir -p cov_data
	sudo chmod -R 777 out/default/
	for testcase in out/default/queue/id:*; do \
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
	sudo ./dhcp-wrapper seeds/crash8.pcap

testv6:
	sudo ./dhcp-wrapper seeds6/ra_and_dhcp.pcap

mutators:
	clang -shared -Wall -fPIC -O3 \
	-I$(PWD)/AFLplusplus/include/ \
	-I$(PWD)/connman-1.32/include/ \
	-I/usr/include/dbus-1.0/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
	$(PWD)/connman-1.32/gdhcp/common.c \
	$(PWD)/connman-1.32/src/log.c \
	$(CFLAGS) $(LDFLAGS) \
	mutator_dhcpv4.c \
	-o mutator_dhcpv4.so

	clang -shared -Wall -fPIC -O3 \
	-I$(PWD)/AFLplusplus/include/ \
	-I$(PWD)/connman-1.32/include/ \
	-I/usr/include/dbus-1.0/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
	$(PWD)/connman-1.32/gdhcp/common.c \
	$(PWD)/connman-1.32/src/log.c \
	$(CFLAGS) $(LDFLAGS) \
	mutator_dhcpv6.c \
	-o mutator_dhcpv6.so

	clang -shared -Wall -fPIC -O3 \
	-I$(PWD)/AFLplusplus/include/ \
	-I$(PWD)/connman-1.32/include/ \
	-I/usr/include/dbus-1.0/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
	$(PWD)/connman-1.32/gdhcp/common.c \
	$(PWD)/connman-1.32/src/log.c \
	$(PWD)/AFLplusplus/src/afl-performance.c \
	$(PWD)/utils.c \
	$(CFLAGS) $(LDFLAGS) \
	pcap_mutator.c \
	-o pcap_mutator.so