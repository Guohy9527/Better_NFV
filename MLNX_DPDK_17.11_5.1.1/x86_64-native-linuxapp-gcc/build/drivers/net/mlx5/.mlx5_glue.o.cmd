cmd_mlx5_glue.o = gcc -Wp,-MD,./.mlx5_glue.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX  -I/home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/x86_64-native-linuxapp-gcc/include -include /home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/x86_64-native-linuxapp-gcc/include/rte_config.h -O3 -std=c11 -Wall -Wextra -g -I. -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wno-strict-prototypes -Wno-error=cast-qual -DNDEBUG -UPEDANTIC -DMLX5_MR_CACHE_N=8 -DRTE_LIBRTE_MLX5_FLOW_CACHE    -o mlx5_glue.o -c /home/ghy/work/better_NFV/MLNX_DPDK_17.11_5.1.1/drivers/net/mlx5/mlx5_glue.c 