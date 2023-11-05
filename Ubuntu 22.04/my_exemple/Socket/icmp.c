#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "in_cksum.h"
int main(int argc, char *argv[])
{
  int sd;
  const int on = 1;
  
  struct sockaddr_in servaddr;
  struct sockaddr_in source;
  
  char sendbuf[sizeof(struct iphdr) + sizeof(struct icmp) + 200];
  struct iphdr *ip_hdr = (struct iphdr *)sendbuf;
  struct icmp *icmp_hdr = (struct icmp *) (sendbuf + sizeof(struct iphdr));

  if ( (sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror("socket() failed");
    exit(-1);
  }

  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0) {
    perror("setsockopt() failed");
    exit(-1);
  }

  if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof(on)) < 0) {
    perror("setsockopt() failed");
    exit(-1);
  }

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  inet_aton("127.0.0.22", &servaddr.sin_addr);
  
  inet_aton("127.0.0.33", &source.sin_addr);
  
  ip_hdr->ihl = 5;
  ip_hdr->version = 4;
  ip_hdr->tos = 0;
  ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp) + 200);
  ip_hdr->id = 0;
  ip_hdr->frag_off = 0;
  ip_hdr->ttl = 33;
  ip_hdr->protocol = IPPROTO_ICMP;
  ip_hdr->check = 0;
  ip_hdr->check = in_cksum((unsigned short *)ip_hdr, sizeof(struct iphdr));
  ip_hdr->saddr = source.sin_addr.s_addr;
  ip_hdr->daddr = servaddr.sin_addr.s_addr;

  icmp_hdr->icmp_type = ICMP_ECHO;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_id = 1;
  icmp_hdr->icmp_seq = 1;
  icmp_hdr->icmp_cksum = 0;
  icmp_hdr->icmp_cksum = in_cksum((unsigned short *)icmp_hdr, sizeof(struct icmp) + 200);

  if (sendto(sd, sendbuf, sizeof(sendbuf), 0, 
	       (struct sockaddr *)&servaddr, sizeof(servaddr))  < 0) {
      perror("sendto() failed");
      exit(-1);
    }
  return 0;
}
