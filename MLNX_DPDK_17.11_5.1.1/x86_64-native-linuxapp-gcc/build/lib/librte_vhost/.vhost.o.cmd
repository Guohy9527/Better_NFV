cmd_vhost.o = gcc -Wp,-MD,./.vhost.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX  -I/home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/x86_64-native-linuxapp-gcc/include -include /home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/x86_64-native-linuxapp-gcc/include/rte_config.h -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -I/home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/lib/librte_vhost -O3 -D_FILE_OFFSET_BITS=64 -I vhost_user    -o vhost.o -c /home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/lib/librte_vhost/vhost.c 
