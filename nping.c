#include <stdio.h>

#include <stdlib.h>

#include <limits.h>

#include <math.h>

#include <poll.h>

#include <unistd.h>

#include <stdint.h>

#include <inttypes.h>

#include <time.h>

#include <sys/time.h>

#include <sys/types.h>

#include <sys/param.h>

#include <grp.h>

#include <libnet.h>

#include <pwd.h>

#include <pcap.h>

struct tcp_header{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_no;
	uint32_t seq_ack;
	uint8_t dof;
	uint8_t resrv;
	uint8_t flags;
	uint16_t win;
	uint16_t check;
	uint16_t urg_ptr;
};

#define libnet_timersub(tvp, uvp, vvp)                                  \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)

#define ETH_ALEN 6 



char enet_src[6] = {0x0d, 0x0e, 0x0a, 0x0d, 0x00, 0x00};
char enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u_char ip_src[4]   = {0x0a, 0x00, 0x00, 0x01};
u_char ip_dst[4]   = {0x0a, 0x00, 0x00, 0x02};
u_char fddi_src[6] = {0x00, 0x0d, 0x0e, 0x0a, 0x0d, 0x00};
u_char fddi_dst[6] = {0x00, 0x10, 0x67, 0x00, 0xb1, 0x86};
u_char tr_src[6]   = {0x00, 0x0d, 0x0e, 0x0a, 0x0d, 0x00};
u_char tr_dst[6]   = {0x00, 0x10, 0x67, 0x00, 0xb1, 0x86};
u_char org_code[3] = {0x00, 0x00, 0x00};

/* libnet varibles*/
char *payload;
u_short payload_s;
u_long src_ip, dst_ip;
u_short src_prt, dst_prt;
libnet_t *libnet;
int verbose = 0;  /* Increase with -v */

pcap_t *pcap = NULL;

/*function prototype*/
extern char* 
get_mac(char* ifname);

void 
usage(char *);

void 
do_libnet_init(const char *ifname, int recursive);

void 
strip_newline(char* s);

int 
sendTCPpacket(); /*Craft and send TCP packet*/

int 
sendUDPpacket(); /*Craft and send UDP packet*/

int  
pcapInit(struct bpf_program bp ,  char *ifname , int snaplen , int promisc , int to_ms , char* ebuf , char* dstip); /* intialize the libpcap library for capturing the packet */

void
pcap_recv_packets(pcap_t *pcap, uint32_t packetwait, pcap_handler func);

void 
pcap_callback(const char *unused, struct pcap_pkthdr *h, uint8_t *packet); /*call back function*/

void
getclock(struct timespec *ts);

void
fixup_timespec(struct timespec *tv);

double
timespec2dbl(const struct timespec *tv);

uint32_t
wait_time(double deadline, uint32_t packetwait);

int main(int argc, char *argv[])
{
    int c;
    char *cp;
    char erbuf[LIBNET_ERRBUF_SIZE];

    /* PACAP variables */
struct bpf_program bp;
int snaplen = 100;
int to_ms = 10;
int promisc = 0; /*promiscus mode */
double packetwait = 1; /* 1 sec wait */
double deadline = -1;

    const char *srcip_opt = NULL;
    const char *dstip_opt = NULL;
    const char *srcmac_opt = NULL;
    const char *ifname = NULL;	
    int  tcpMode = 1;
    int packetCount = 2;
    printf("libnet 1.1 packet shaping: TCP + options[link]\n");
	
    src_ip  = 0;
    dst_ip  = 0;
    src_prt = 0;
    dst_prt = 0;
    payload = NULL;
    payload_s = 0;
    while ((c = getopt(argc, argv, "TUvi:d:c:s:p:W:")) != EOF)
    {
        switch (c)
        {
            /*
             *  We expect the input to be of the form `ip.ip.ip.ip.port`.  We
             *  point cp to the last dot of the IP address/port string and
             *  then seperate them with a NULL byte.  The optarg now points to
             *  just the IP address, and cp points to the port.
             */
	    case 'c':
		 if (strchr(optarg, ':')){usage(" ");}
		packetCount = atoi(optarg);
		if(packetCount<0) packetCount = -1*packetCount;
		break;
	    case 'T':
		tcpMode = 1;
		break;
	    case 'U':
		tcpMode = 0;
		break;
            case 'd':
                if (!(cp = strrchr(optarg, '.')))
                {
                    usage(argv[0]);
                }
                *cp++ = 0;
                dst_prt = (u_short)atoi(cp);
		dstip_opt = optarg;              
		printf("%s\n" , dstip_opt); //DEBUG  
                break;
            case 's':
                if (!(cp = strrchr(optarg, '.')))
                {
                    usage(argv[0]);
                }
                *cp++ = 0;
                src_prt = (u_short)atoi(cp);
		srcip_opt = optarg;
		printf("%s\n" , srcip_opt); //DEBUG
                break;
            case 'p':
                payload = optarg;
                payload_s = strlen(payload);
                break;
	    case 'i':
		if (strchr(optarg, ':')) {
				fprintf(stderr, "arping: If you're trying to "
					"feed me an interface alias then you "
					"don't really\nknow what this programs"
					" does, do you?\nUse -I if you really"
					" mean it (undocumented on "
					"purpose)\n");
				exit(1);
		}
		ifname = optarg;
		printf("%s\n" , ifname); //DEBUG
		break;
		
	    case 'W':
			 if (strchr(optarg, ':')){usage(" ");}
                        packetwait = (unsigned)(1.0 * atof(optarg));
                        break;
	    case 'v':
		verbose++;
		break;
            default:
		usage("");
                exit(EXIT_FAILURE);
        }
    }
/*
* we have the ifname so do libnet inti and resolve all the fields form the *_opt varibales
*/
	if(ifname!=NULL)
	{
		do_libnet_init(ifname , 0);
	}
	if ((dst_ip = libnet_name2addr4(libnet, dstip_opt, LIBNET_RESOLVE)) == -1)
        {
                    fprintf(stderr, "Bad destination IP address: %s\n", optarg);
                    exit(EXIT_FAILURE);
        }
	if ((src_ip = libnet_name2addr4(libnet, srcip_opt, LIBNET_RESOLVE)) == -1)
        {
                    fprintf(stderr, "Bad source IP address: %s\n", optarg);
                    exit(EXIT_FAILURE);
        }
/*
* get mac address
*/
	if(ifname!=NULL){

		srcmac_opt  = (char*) get_mac(ifname); /*Get the mac address using rtscok of junos*/
		memcpy(enet_src, srcmac_opt, ETH_ALEN);
		for(int i=0;i<6;++i) //DEBUG
		printf("%x \t" , enet_src[i]);
		printf("\n");

	}
	else
	{
		 printf("No Interface found\n"); //DEBUG
		 exit(EXIT_FAILURE);
	}
/*
*pcap init
*/
	if(1 != pcapInit( bp,  ifname , snaplen , promisc ,  to_ms , erbuf , dstip_opt)){
		fprintf(stderr, "arping: pcapInit(%s): %s\n",
                                bpf_filter, pcap_geterr(pcap));
                        exit(1);	
	}


/*
* we have the srcip, dstip, src port, dst port, srcmac and dstmac , so craft and send the tcp packet
*/     

for(int i=0;i<packetCount;++i)
{
	if(tcpMode == 1)
	{	/* 0 for send SYN packet */
		if(sendTCPpacket(0)==-1)
		{
			printf("Cannot send the TCP pakcet. \n");
		}
		else
		{
			if(verbose >0){
				 printf("Sent TCP pakcet. \n");	
			}
		}
	}
	else if(tcpMode == 0)
		if(sendUDPpacket()==-1)
		{
                        printf("Cannot send the UDP pakcet. \n");
                }
		else
		{
                        if(verbose >0){
                                 printf("Sent UDP pakcet. \n");
                        }
                }

	  sleep(packetwait);
	 /*capture packet*/ 
//	pcap_recv_packets(pcap , packetwait , (pcap_handler)pcap_callback);
}
	libnet_destroy(libnet);
}

void
usage(char *name)
{
    fprintf(stderr,
        "usage: %s -s source_ip.source_port -d destination_ip.destination_port"
        " [-p payload]\n",
        name);
}

/**
 * Init libnet with specified ifname. Destroy if already inited.
 * If this function retries with different parameter it will preserve
 * the original error message and print that.
 * Call with recursive=0.
 */
void
do_libnet_init(const char *ifname, int recursive)
{
	char ebuf[LIBNET_ERRBUF_SIZE];
        ebuf[0] = 0;
	if (verbose > 1) {
                printf("arping: libnet_init(%s)\n", ifname ? ifname : "<null>");
	}
	if (libnet) {
		/* Probably going to switch interface from temp to real. */
        libnet_destroy(libnet);//DONE
		libnet = 0;
	}

        /* Try libnet_init() even though we aren't root. We may have
         * a capability or something. */
	/*
     	*  Initialize the library.  Root priviledges are required.
     	*/
	if (!(libnet = libnet_init( LIBNET_LINK,
				   (char*)ifname,
				   ebuf))) //DONE
    	{
                strip_newline(ebuf);
                if (!ifname) {
                        /* Sometimes libnet guesses an interface that it then
                         * can't use. Work around that by attempting to
                         * use "lo". */
                        do_libnet_init("lo", 1);
                        if (libnet != NULL) {
                                return;
                        }
                } else if (recursive) {
                        /* Continue original execution to get that
                         * error message. */
                        return;
                }
                fprintf(stderr, "arping: libnet_init(LIBNET_LINK, %s): %s\n",
                        ifname ? ifname : "<null>",
                        *ebuf ? ebuf : "<no error message>");
		printf("Use -i flag to select an interface \n");
                if (getuid() && geteuid()) {
                        fprintf(stderr,
                                "arping: you may need to run as root\n");
                }
		exit(1);
	}
}

/**
 * Some Libnet error messages end with a newline. Strip that in place.
 */
void
strip_newline(char* s) // DONE
{
        size_t n;
        for (n = strlen(s); n && (s[n - 1] == '\n'); --n) {
                s[n - 1] = 0;
        }
}


int  sendTCPpacket(int count)
{	
	int ack = 0;
	int c = -1;
	libnet_ptag_t tcp;

	tcp = libnet_build_tcp_options(
        	(uint8_t*)"\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
        	20,
        	libnet,
       	 	0);
    if (tcp == -1)
    {
        fprintf(stderr, "Can't build TCP options: %s\n", libnet_geterror(libnet));
        goto bad;
    }
/*
* set the flag like syn or ack
*/
    u_int8_t FLAG;
    if(ack) FLAG  = TH_ACK;
    else FLAG = TH_SYN;
    tcp = libnet_build_tcp(
        src_prt,                                    /* source port */
        dst_prt,                                    /* destination port */
        0x01010101,                                 /* sequence number */
        0x02020202,                                 /* acknowledgement num */
        FLAG,                                     /* control flags */
        32767,                                      /* window size */
        0,                                          /* checksum */
        10,                                          /* urgent pointer */
        LIBNET_TCP_H + 20 + payload_s,              /* TCP packet size */
        (uint8_t*)payload,                         /* payload */
        payload_s,                                  /* payload size */
        libnet,                                          /* libnet handle */
        0);                                         /* libnet id */
    if (tcp == -1)
    {
        fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(libnet));
        goto bad;
    }
	 tcp = libnet_build_ipv4(
	        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,/* length */
        	0,                                          /* TOS */
        	242,                                        /* IP ID */
       	 	0,                                          /* IP Frag */
        	64,                                         /* TTL */
        	IPPROTO_TCP,                                /* protocol */
        	0,                                          /* checksum */
        	src_ip,                                     /* source IP */
        	dst_ip,                                     /* destination IP */
        	NULL,                                       /* payload */
        	0,                                          /* payload size */
        	libnet,                                          /* libnet handle */
        	0);                                         /* libnet id */
    	if (tcp == -1)
    	{
        	fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(libnet));
        	goto bad;
    	}

    	tcp = libnet_build_ethernet(
        	enet_dst,                                   /* ethernet destination */
        	enet_src,                                   /* ethernet source */
        	ETHERTYPE_IP,                               /* protocol type */
        	NULL,                                       /* payload */
        	0,                                          /* payload size */
        	libnet,                                          /* libnet handle */
       	 	0);                                         /* libnet id */
    	if (tcp == -1)
    	{
        	fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(libnet));
        	goto bad;
    	}

     /*
     *  Write it to the wire.
     */
    c = libnet_write(libnet);
    	if (c == -1)
    	{
        	fprintf(stderr, "Write error: %s\n", libnet_geterror(libnet));
        	goto bad;
   	}
    	 else
   	{
       		fprintf(stderr, "Wrote %d byte TCP packet; check the wire.\n", c);
   	}
    return (EXIT_SUCCESS);
bad:
    return (EXIT_FAILURE);

}

int  sendUDPpacket()
{
	int c = -1;
	int build_ip = 1;
	libnet_ptag_t udp;
	udp = 0; /* this is very important to set the udp initial value to 0 to find the pblock*/
	udp = libnet_build_udp(
                src_prt,                               /* source port */
                dst_prt,                              /* destination port */
                LIBNET_UDP_H + payload_s,           /* packet size */
                0,                                  /* checksum */
                (uint8_t *)payload,                 /* payload */
                payload_s,                          /* payload size */
                libnet,                                  /* libnet handle */
                udp);                               /* libnet id */
            if (udp == -1)
            {
                fprintf(stderr, "Can't build UDP header (at port %d): %s\n", 
                        dst_prt, libnet_geterror(libnet));
                goto bad;
            }
        udp = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_UDP_H + payload_s,   /* length */
            0,                                          /* TOS */
            242,                                        /* IP ID */
            0,                                          /* IP Frag */
            64,                                         /* TTL */
            IPPROTO_UDP,                                /* protocol */
            0,                                          /* checksum */
            src_ip,                                     /* source IP */
            dst_ip,                                     /* destination IP */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            libnet,                                          /* libnet handle */
            0);
        if (udp == -1)
        {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(libnet));
            goto bad;
        }

        udp = libnet_build_ethernet(
            enet_dst,                                   /* ethernet dest */
            enet_src,                                   /* ethernet source */
            ETHERTYPE_IP,                               /* protocol type */
            NULL,                                       /* payload */
            0,                                          /* payload size */
            libnet,                                          /* libnet handle */
            0);
        if (udp == -1)
        {
            fprintf(stderr, "Can't build ethernet header: %s\n",
                    libnet_geterror(libnet));
            goto bad;
        }
            c = libnet_write(libnet); 
            if (c == -1)
            {
                fprintf(stderr, "write error: %s\n", libnet_geterror(libnet));
            }
            else
            {
               fprintf(stderr, "wrote %d byte UDP packet to port %d\n", c,dst_prt);
            }
   	return (EXIT_SUCCESS);
	bad:
    	return (EXIT_FAILURE);
}

int  pcapInit( struct  bpf_program  bp , char *ifname , int snaplen , int promisc , int to_ms , char* ebuf , char *dstip)
{
	if (!(pcap = pcap_open_live(ifname, 100, promisc, 10, ebuf))) {
                strip_newline(ebuf);
                fprintf(stderr, "arping: pcap_open_live(): %s\n", ebuf);
		exit(1);
	}
	if (pcap_setnonblock(pcap, 1, ebuf)) {
                strip_newline(ebuf);
		fprintf(stderr, "arping: pcap_set_nonblock(): %s\n", ebuf);
		exit(1);
	}
	if (verbose > 1) {
		printf("arping: pcap_get_selectable_fd(): %d\n",
		       pcap_get_selectable_fd(pcap));
	}
/* apply bpf filter */
	char bpf_filter[64];
	snprintf(bpf_filter, sizeof(bpf_filter), "tcp or udp");
	if (-1 == pcap_compile(pcap, &bp, bpf_filter, 0, -1)) {
                        fprintf(stderr, "arping: pcap_compile(%s): %s\n",
                                bpf_filter, pcap_geterr(pcap));
			exit(1);
	}
	if (-1 == pcap_setfilter(pcap, &bp)) {
                fprintf(stderr, "arping: pcap_setfilter(): %s\n",
                        pcap_geterr(pcap));
		exit(1);
	}
	return 1;
}

/**
 * try to receive a packet for 'packetwait' microseconds
 */
 void
pcap_recv_packets(pcap_t *pcap, uint32_t packetwait, pcap_handler func) // DONE
{
       struct timespec ts;
       struct timespec endtime;
       char done = 0;
       int fd;

       if (verbose > 3) {
               printf("nping: receiving packets...\n");
       }

       getclock(&ts);
       endtime.tv_sec = ts.tv_sec + (packetwait / 1000000);
       endtime.tv_nsec = ts.tv_nsec + 1000 * (packetwait % 1000000);
       fixup_timespec(&endtime);

       fd = pcap_get_selectable_fd(pcap);
       if (fd == -1) {
               fprintf(stderr, "nping: pcap_get_selectable_fd()=-1: %s\n",
                       pcap_geterr(pcap));
               exit(1);
       }

       for (;!done;) {
	       int trydispatch = 0;

	       getclock(&ts);
	       ts.tv_sec = endtime.tv_sec - ts.tv_sec;
	       ts.tv_nsec = endtime.tv_nsec - ts.tv_nsec;
	       fixup_timespec(&ts);
               if (verbose > 2) {
                       printf("nping: listen for replies for %ld.%09ld sec\n",
                              (long)ts.tv_sec, (long)ts.tv_nsec);
               }

               /* if time has passed, do one last check and then we're done.
                * this also triggers if not using monotonic clock and time
                * is set forwards */
	       if (ts.tv_sec < 0) {
		       ts.tv_sec = 0;
		       ts.tv_nsec = 1;
		       done = 1;
	       }

               /* if wait-for-packet time is longer than full period,
                * we're obviously not using a monotonic clock and the system
                * time has been changed.
                * we don't know how far we're into the waiting, so just end
                * it here */
               if ((ts.tv_sec > packetwait / 1000000)
                   || ((ts.tv_sec == packetwait / 1000000)
                       && (ts.tv_nsec/1000 > packetwait % 1000000))) {
		       ts.tv_sec = 0;
		       ts.tv_nsec = 1;
                       done = 1;
               }


	       /* try to wait for data */
	       {
                       fd_set fds;
		       int r;
                       struct timeval tv;
                       tv.tv_sec = ts.tv_sec;
                       tv.tv_usec = ts.tv_nsec / 1000;

                       FD_ZERO(&fds);
                       FD_SET(fd, &fds);

                       r = select(fd + 1, &fds, NULL, NULL, &tv);
		       switch (r) {
		       case 0: /* timeout */
                                               printf("Timeout\n");
                                               break;
		       case -1: /* error */
					if (errno != EINTR){
						 done = 1;
				       		fprintf(stderr,
					       		"nping: select() failed: %s\n" , strerror(errno));
					}
			       break;
		       default: /* data returned */
			       trydispatch = 1;
			       break;
		       }
	       }

	       if (trydispatch) {
		       int ret;
                       if (0 > (ret = pcap_dispatch(pcap, -1,
                                                    func,
                                                    NULL))) {
			       /* rest, so we don't take 100% CPU... mostly
                                  hmm... does usleep() exist everywhere? */
			       usleep(1);

			       /* weird is normal on bsd :) */
			       if (verbose > 3) {
				       fprintf(stderr,
					       "nping: select says ok, but "
					       "pcap_dispatch=%d!\n",
					       ret);
			       }
                       }else printf("%d Packet is captured...\n" , ret); //DEBUG
	       }
       }
}


/** handle incoming packet when using tcp mode.
 *
 * \param h       packet metadata
 * \param packet  packet data
 */
void
pcap_callback(const char *unused, struct pcap_pkthdr *h, uint8_t *packet){

	int offset = 22; // PFE stripping ether and adding ttp header
	struct libnet_ipv4_hdr *hip;
	struct tcp_header *tcp;
	hip = (void*) (packet+ offset);
	tcp = (void *) (packet + offset + LIBNET_IPV4_H);
//	printf ("Port %d appears to be closed\n", ntohs (tcp->src_port));
//	printf ("Port %d appears to be closed\n", ntohs (tcp->dst_port));
/*
 	 if (tcp->th_flags == 0x14)
    	{
     		 printf ("Port %d appears to be closed\n", ntohs (tcp->th_sport));
    	}
  	else
    	{
      	if (tcp->th_flags == 0x12)
      	{
      			 printf ("Port %d appears to be open\n", ntohs (tcp->th_sport));
      		}
    	}
*/
	return;
}


/**
 * idiot-proof clock_gettime() wrapper
 */
 void
getclock(struct timespec *ts) //ASSUMING DONE
{
        struct timeval tv; // defined on sys/time
        if (-1 == gettimeofday(&tv, NULL)) {
                fprintf(stderr, "arping: gettimeofday(): %s\n",
                        strerror(errno));
        }
        ts->tv_sec = tv.tv_sec;
        ts->tv_nsec = tv.tv_usec * 1000;
}

/**
 * while negative nanoseconds, take from whole seconds.
 * help function for measuring deltas.
 */
 void
fixup_timespec(struct timespec *tv) // DONE
{
	while (tv->tv_nsec < 0) {
		tv->tv_sec--;
		tv->tv_nsec += 1000000000;
	}
}
double
timespec2dbl(const struct timespec *tv) //DONE
{
        return tv->tv_sec + (double)tv->tv_nsec / 1000000000;
}

/**
 * return number of microseconds to wait for packets.
 */
 uint32_t
wait_time(double deadline, uint32_t packetwait) // DONE
{
        struct timespec ts;

        // If deadline not specified, then don't use it.
        if (deadline < 0) {
                return packetwait;
        }

        getclock(&ts);
        const double max_wait = deadline - timespec2dbl(&ts);
        if (max_wait < 0) {
                return 0;
        }
        if (max_wait > packetwait / 1000000) {
                return packetwait;
        }
        return max_wait * 1000000;
}

