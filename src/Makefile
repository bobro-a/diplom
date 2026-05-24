LLVM_PROFDATA=$(dirname $LLVM_CLANG)/llvm-profdata
LLVM_CLANG=$(shell afl-clang-fast -print-prog-name=clang)
CFLAGS = $(shell pkg-config --cflags glib-2.0)
LDFLAGS = $(shell pkg-config --libs glib-2.0)
PWD =$(shell pwd)
CONNMAND_BIN = $(PWD)/connman-1.32/src/connmand
CONNMAND_BIN_2 =  $(PWD)/connman-2.0/src/connmand
CONNMAN_PATH=$(PWD)/connman-1.32
CONNMAN_PATH_2=$(PWD)/connman-2.0

afl:
	AFL_USE_ASAN=1 afl-clang-fast -O0 -g $(CFLAGS) \
  	-o dhcp-wrapper main.c utils.c $(LDFLAGS) \
	-lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	$(CONNMAN_PATH)/gdhcp/src_connmand-common.o \
	$(CONNMAN_PATH)/src/connmand-log.o \
	$(CONNMAN_PATH)/src/connmand-backtrace.o

afl2:
	afl-clang-fast -O0 -g -fsanitize=address $(CFLAGS) \
  	-o dhcp-wrapper main.c utils.c $(LDFLAGS) -lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	$(PWD)/connman-2.0/gdhcp/src_connmand-common.o \
	$(PWD)/connman-2.0/src/connmand-util.o \
	$(PWD)/connman-2.0/src/connmand-log.o \
	$(PWD)/connman-2.0/src/connmand-backtrace.o

clang1:
	clang -O0 -g \
    -o dhcp-wrapper main.c utils.c -DHAVE_CONFIG_H $(LDFLAGS) $(CFLAGS) \
	-lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	-I$(CONNMAN_PATH)/include/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/dbus-1.0/ \
	-I$(CONNMAN_PATH)/gdhcp/ \
	-I$(CONNMAN_PATH)/src \
	-I$(CONNMAN_PATH) \
    $(CONNMAN_PATH)/gdhcp/common.c \
    $(CONNMAN_PATH)/src/log.c \
    $(CONNMAN_PATH)/src/backtrace.c

clang2-1:
	clang -O0 -g \
    -o dhcp-wrapper main.c utils.c -DHAVE_CONFIG_H $(LDFLAGS) $(CFLAGS) \
	-lpcap -lsystemd \
	-I/usr/include/x86_64-linux-gnu/ \
	-I$(CONNMAN_PATH_2)/include/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/dbus-1.0/ \
	-I$(CONNMAN_PATH_2)/gdhcp/ \
	-I$(CONNMAN_PATH_2)/src \
	-I$(CONNMAN_PATH_2) \
    $(CONNMAN_PATH_2)/gdhcp/common.c \
    $(CONNMAN_PATH_2)/src/log.c \
    $(CONNMAN_PATH_2)/src/backtrace.c \
	$(CONNMAN_PATH_2)/src/util.c

clang_cov:
	clang -O0 -g -fprofile-instr-generate -fcoverage-mapping \
	-mllvm -runtime-counter-relocation \
      $(CFLAGS) \
      -o dhcp-wrapper_cov main.c utils.c $(LDFLAGS) -lpcap -lsystemd \
	  -I/usr/include/x86_64-linux-gnu/ \
	  $(CONNMAN_PATH)/gdhcp/src_connmand-common.o \
	$(CONNMAN_PATH)/src/connmand-log.o \
	$(CONNMAN_PATH)/src/connmand-backtrace.o

MUTATOR = connman-2.0
OUT_DIR = out_$(MUTATOR)

afl-fuzz:
	AFL_SKIP_BIN_CHECK=1 AFL_NO_FORKSRV=1 sudo -E afl-fuzz -m none -t 10000 -i seeds_test -o $(OUT_DIR) -- ./dhcp-wrapper @@

COV_DATA = cov_data_$(MUTATOR)
gen:
	rm -rf $(COV_DATA) 2>/dev/null
	mkdir -p $(COV_DATA)
	sudo chmod -R 777 $(OUT_DIR)
	sudo chmod -R 777 $(COV_DATA)
	for testcase in $(OUT_DIR)/default/queue/id:*; do \
		[ -f "$$testcase" ] || continue; \
		sudo -E LLVM_PROFILE_FILE="$(COV_DATA)/$$(basename $$testcase)_%c_%m_%p.profraw" \
		timeout 30 ./dhcp-wrapper_cov "$$testcase" || true; \
	done

COVERAGE_REPORT = html_$(MUTATOR)
html:
	sudo llvm-profdata merge -sparse $(COV_DATA)/*.profraw -o $(COV_DATA)/merged.profdata
	sudo rm -rf $(COVERAGE_REPORT)
	mkdir -p $(COVERAGE_REPORT)
	sudo chmod 777 $(COVERAGE_REPORT)
	sudo llvm-cov show $(CONNMAND_BIN) \
			-object ./dhcp-wrapper_cov \
    		-instr-profile=$(COV_DATA)/merged.profdata \
    		-format=html \
    		-output-dir=$(COVERAGE_REPORT)/

test:
	sudo ./dhcp-wrapper seeds_test/few_input.pcap

testv6:
	sudo ./dhcp-wrapper seeds_test/ra_and_dhcp.pcap

mutators:
	clang -shared -Wall -fPIC -O3 \
	-I$(PWD)/AFLplusplus/include/ \
	-I$(CONNMAN_PATH)/include/ \
	-I/usr/include/dbus-1.0/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
	$(CONNMAN_PATH)/gdhcp/common.c \
	$(CONNMAN_PATH)/src/log.c \
	$(CFLAGS) $(LDFLAGS) \
	mutator_dhcpv4.c \
	-o mutator_dhcpv4.so

	clang -shared -Wall -fPIC -O3 \
	-I$(PWD)/AFLplusplus/include/ \
	-I$(CONNMAN_PATH)/include/ \
	-I/usr/include/dbus-1.0/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
	$(CONNMAN_PATH)/gdhcp/common.c \
	$(CONNMAN_PATH)/src/log.c \
	$(CFLAGS) $(LDFLAGS) \
	mutator_dhcpv6.c \
	-o mutator_dhcpv6.so

	clang -shared -Wall -fPIC -O3 -lpcap \
	-I$(PWD)/AFLplusplus/include/ \
	-I$(CONNMAN_PATH)/include/ \
	-I/usr/include/dbus-1.0/ \
	-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include/ \
	-I/usr/include/glib-2.0/ \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ \
	$(CONNMAN_PATH)/gdhcp/common.c \
	$(CONNMAN_PATH)/src/log.c \
	$(PWD)/AFLplusplus/src/afl-performance.c \
	$(PWD)/utils.c \
	$(CFLAGS) $(LDFLAGS) \
	pcap_mutator.c \
	-o pcap_mutator.so