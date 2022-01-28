TOPDIR=/home/ds/hanr_client

#RTE_LIB=/home/gaoxing/software/dpdk/x86_64-native-linuxapp-gcc/
RTE_LIB=${RTE_SDK}/${RTE_TARGET}

CFLAGS="-march=native"

LIBS+= -L${RTE_LIB}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma -lpcap -lrocksdb



SRCS = hanr_rocksdb.c hanr_eid_cache.c hanr_client.c hanr_packet_generator.c hanr_parse_cmds.c hanr_client_tx.c hanr_client_rx.c hanr_msg.c\
		 ./T2_module/T2_module_plugins.c ./T1_module/T1_module_plugins.c ./T0_module/T0_module_plugins.c \

TARGET="hanr_client"

INCLUDE = -I${RTE_LIB}/include 

all:
	cc -O -gdwarf-2  ${CFLAGS} ${INCLUDE} -o ${TARGET} ${SRCS} ${LIBS}


.PHONY: clean
clean:
	rm -f *.o ${TARGET} 