PROG = nping
SRCS = \
	nping.c \
	libnet_init_custom.c \
	get_mac.c

#NO_SHARED = yes
.PATH: ${RELSRCTOP}/dist/packetfactory-libnet/src

SRCS += \
	libnet_build_tcp.c \
	libnet_build_ethernet.c \
        libnet_write.c \
	libnet_pblock.c \
	libnet_raw.c \
	libnet_build_ip.c \
	libnet_error.c \
	libnet_resolve.c \
	libnet_if_addr.c \
	libnet_link_bpf.c \
	libnet_checksum.c \
	libnet_build_udp.c
	


CFLAGS +=  -I${.CURDIR}/include -I${.CURDIR}

DPLIBS =\
        ${LIBPCAP} \
        ${LIBJXMLUTIL} \
        ${LIBJUNOS-NAME-TREE} \
        ${LIBJUNOS-PATRICIA} \
        ${LIBJUNOS-XMLUTIL} \
        ${LIBJUNOS-PATH} \
        ${LIBUI-ODL} \
        ${LIBISC} \
        ${LIBRTSOCK} \
        ${LIBJUNOS-LOG-TRACE} \
        ${LIBJUNOS-SYS-UTIL} \
        ${LIBJUNOS-UTIL}

.include <bsd.prog.mk>
