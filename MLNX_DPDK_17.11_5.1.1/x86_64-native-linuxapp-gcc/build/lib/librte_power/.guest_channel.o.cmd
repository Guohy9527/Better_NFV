cmd_guest_channel.o = gcc -Wp,-MD,./.guest_channel.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX  -I/home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/x86_64-native-linuxapp-gcc/include -include /home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/x86_64-native-linuxapp-gcc/include/rte_config.h -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -I/home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/lib/librte_power -O3 -fno-strict-aliasing    -o guest_channel.o -c /home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/lib/librte_power/guest_channel.c 
