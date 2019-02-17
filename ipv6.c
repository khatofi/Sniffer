#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/ip_icmp.h>

void print_ipv6_addr(uint16_t *addr)
{	
    int nb0, ind0, newind, nb0max = 0;
    int i;

    for(i=0; i<8; i++)
    {
        if(addr[i] == 0 && nb0==0)
        {
		//printf("%i\n",i);
            newind = i;
            nb0++;
        }
        else if(addr[i] == 0)
        {
            nb0++;
        }
        else
	  {
		if(nb0>nb0max)
	{
			printf("%i %i\n",nb0,nb0max);
			nb0max=nb0;
			ind0=newind;
	} 
 		nb0=0;
	}
			
    }
		if(nb0>nb0max)
	{
			printf("%i %i\n",nb0,nb0max);
			nb0max=nb0;
			ind0=newind;
	}
	
printf("Indice i = %i\nnb0max = %i\n", ind0, nb0max);

    for(i=0; i<8; i++)
    {
        if(i==ind0)
        {
            printf("::");
            i = i+nb0max;
            if(i>=8)
                break;
            printf("%04x", htons(addr[i]));
        }
        else if(i==0)
            printf("%04x", htons(addr[i]));
        else
        {
            printf(":");
            printf("%04x", htons(addr[i]));
        }
    }
	printf("\n");
}

int main(void)
{
	uint16_t ipv6[8] = {0xffff,0xffff,0x0000,0x0000,0xffff,0x0000,0x0000,0x0000};
	print_ipv6_addr(ipv6);

}
