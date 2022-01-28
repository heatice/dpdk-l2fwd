TOPDIR=/home/ubuntu/projects/hanr_client

#RTE_LIB=/home/gaoxing/software/dpdk/x86_64-native-linuxapp-gcc/
RTE_LIB=${RTE_SDK}/${RTE_TARGET}

CFLAGS="-march=native"

LIBS+= -L${RTE_LIB}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive
LIBS+= -Wl,--no-whole-archive -lrt -lm -ldl -lcrypto -pthread -lnuma -lpcap



SRCS = hanr_client.c hanr_packet_generator.c hanr_parse_cmds.c hanr_client_tx.c hanr_client_rx.c 

TARGET="hanr_client"

INCLUDE = -I${RTE_LIB}/include 

all:
	cc -O -gdwarf-2  ${CFLAGS} ${INCLUDE} -o ${TARGET} ${SRCS} ${LIBS}


.PHONY: clean
clean:
	rm -f *.o ${TARGET} 