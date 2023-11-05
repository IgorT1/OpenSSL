#include <linux/tcp.h>
#include "in_cksum.h"

int main(int argc, char *argv[])
{ 
  int sd;
  int port = atoi("1234");

  struct sockaddr_in servaddr;
  struct tcphdr tcp_hdr;
  struct sockaddr_in source;
    
  struct pseudo_hdr 
  {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char place_holder;
    unsigned char protocol;
    unsigned short length;
    struct tcphdr tcp;
  } pseudo_hdr;
 
	if((sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
    perror("socket() failed");
    exit(1);
  }
		
  bzero(&servaddr, sizeof(servaddr));
  
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  inet_aton("127.0.0.1", &servaddr.sin_addr); 
  
  inet_aton("127.0.0.1", &source.sin_addr);

  tcp_hdr.source = getpid();
  tcp_hdr.dest = htons(port);
  tcp_hdr.seq = htons(getpid() + port);
  tcp_hdr.ack_seq = 0;
  tcp_hdr.res1 = 0;
  tcp_hdr.doff = 5;
  tcp_hdr.fin = 0;
  tcp_hdr.syn = 1;
  tcp_hdr.rst = 0;
  tcp_hdr.psh = 0;
  tcp_hdr.ack = 0;
  tcp_hdr.urg = 0;
  tcp_hdr.ece = 0;
  tcp_hdr.cwr = 0;
  tcp_hdr.window = htons(128);
  tcp_hdr.check = 0;
  tcp_hdr.urg_ptr = 0;

  pseudo_hdr.source_address = source.sin_addr.s_addr; 
  pseudo_hdr.dest_address   = servaddr.sin_addr.s_addr;
  pseudo_hdr.place_holder   = 0;
  pseudo_hdr.protocol       = IPPROTO_TCP;
  pseudo_hdr.length         = htons(sizeof(struct tcphdr));
  
  bcopy(&tcp_hdr, &pseudo_hdr.tcp, sizeof(struct tcphdr));

  tcp_hdr.check = in_cksum((unsigned short *)&pseudo_hdr, sizeof(struct pseudo_hdr));		
		
	if (sendto(sd, &tcp_hdr, sizeof(struct tcphdr),
	         0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    perror("sendto() failed");
			
  printf("Close socket...\n");
  close (sd);
  return 0;
}

