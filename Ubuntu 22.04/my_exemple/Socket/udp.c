#include <netinet/ip.h>
#include <netinet/udp.h>

#include "in_cksum.h"

int main(int argc, char *argv[])
{
  int sd;
  const int on = 1;
  
  int dport = atoi("44444"); 
  int sport = atoi("55555");
  
  struct sockaddr_in servaddr;
  struct sockaddr_in source;

  struct pseudohdr
  {
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char place_holder;
    unsigned char protocol;
    unsigned short length;
  } pseudo_hdr;

  char sendbuf[sizeof(struct iphdr) + sizeof(struct udphdr)];
  
  struct iphdr *ip_hdr = (struct iphdr *)sendbuf;
  
  struct udphdr *udp_hdr = (struct udphdr *) (sendbuf + sizeof(struct iphdr));
  
  unsigned char *pseudo_packet;
  
  if ( (sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
 {
    perror("socket() failed");
    exit(-1);
  }

  if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0)
 {
    perror("setsockopt() failed");
    exit(-1);
  }

  bzero(&servaddr, sizeof(servaddr));

  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(dport);
  inet_aton("127.0.0.222", &servaddr.sin_addr); 
  
  inet_aton("127.0.0.111", &source.sin_addr);

  ip_hdr->ihl = 5;
  ip_hdr->version = 4;
  ip_hdr->tos = 0;
  ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
  ip_hdr->id = 0;
  ip_hdr->frag_off = 0;
  ip_hdr->ttl = 255;
  ip_hdr->protocol = IPPROTO_UDP; //
  ip_hdr->check = 0;
  ip_hdr->check = in_cksum((unsigned short *)ip_hdr, sizeof(struct iphdr));
  
  ip_hdr->saddr = source.sin_addr.s_addr;
  ip_hdr->daddr = servaddr.sin_addr.s_addr;
  
  pseudo_hdr.source_address = source.sin_addr.s_addr;
  pseudo_hdr.dest_address = servaddr.sin_addr.s_addr;
  pseudo_hdr.place_holder = 0;
  pseudo_hdr.protocol = IPPROTO_UDP;
  pseudo_hdr.length = htons(sizeof(struct udphdr));
 
  udp_hdr->source = htons(sport);
  udp_hdr->dest = htons(dport);
  udp_hdr->len = htons(sizeof(struct udphdr));
  udp_hdr->check = 0;


  if ( (pseudo_packet = (char*)malloc(sizeof(pseudo_hdr) + 
        sizeof(struct udphdr))) == NULL) {
    perror("malloc() failed");
    exit(-1);
  }

  memcpy(pseudo_packet, &pseudo_hdr, sizeof(pseudo_hdr));
  
  memcpy(pseudo_packet + sizeof(pseudo_hdr), sendbuf + 
         sizeof(struct iphdr), sizeof(struct udphdr));
 
  if ( (udp_hdr->check = in_cksum((unsigned short *)pseudo_packet, 
        sizeof(pseudo_hdr) + sizeof(struct udphdr))) == 0)
    udp_hdr->check = 0xffff;

    if (sendto(sd, sendbuf, sizeof(sendbuf), 
	       0, (struct sockaddr *)&servaddr, sizeof(servaddr))  < 0) {
      perror("sendto() failed");
      exit(-1);
    }

  return 0;
}

