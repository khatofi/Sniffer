#include <pcap.h>
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
#include "bootp.h"

#define DNS_PORT 53
#define HTTP_PORT 80
#define BOOTP_SERVER_PORT 67
#define BOOTP_CLIENT_PORT 68
#define POP_PORT 110
#define SMTP_PORT 25
#define IMAP_PORT 143
#define FTP_CMD_PORT 20
#define FTP_DATA_PORT 21


int n_packet = 1;


struct ports
{
	uint16_t src;
	uint16_t dst;
	uint8_t ln; //Taille de l'en-tête (utile seulement pour TCP)
};

struct tlv
{
	uint8_t type;
	uint8_t taille;
	uint8_t * data;
};

int affiche_error(char * buferr);
void affiche_aide(void);

int affiche_error(char * buferr)
{
	printf("Erreur : %s\n", buferr);
	affiche_aide();
	exit(1);
}


void affiche_aide(void)
{
	printf("Usage : ./analyseur -i <interface> -o <fichier> -v <verbosité> -f <filtrage> -h\n"
		"Options\n"
		"   *-i : Analyse live, on fournit l'interface à observer\n"
		"   *-o : Analyse offline, on fournit le fichier contenant les trames à analyser\n"
		"   *-v : Verbosité, on indique le niveau de détails des informations à afficher pour chaque trame\n"
		"           1 : Une ligne par trame\n"
		"           2 : Une ligne par protocole\n"
		"           3 : Toutes les informations disponibles\n"
		"   *-f : Filtrage \n"
		"   *-h : Affichage de l'aide\n");
}


/*  Fonctions concernant les protocole de la couche 3 */

/*** Affiche les informations UDP contenues le paquet donné en argument***/
struct ports print_udp(const u_char * packet, u_char v)
{
	struct udphdr * udp = (struct udphdr *)(packet);
	struct ports udp_ports;

	switch(v)
	{
		case 1: 
			break;

		case 2:
			printf("Source UDP : %i (0x%02x) / " 
				"Destination UDP : %i (0x%02x)\n", htons(udp->source), htons(udp->source), 
													htons(udp->dest), htons(udp->dest));
			break;

		case 3:
			printf("Source UDP : %i (0x%02x)\n"
				"Destination UDP : %i (0x%02x)\n"
				"Taille : %i\n"
				"Checksum : %02x\n", htons(udp->source), htons(udp->source), htons(udp->dest), 
									htons(udp->dest), htons(udp->len), htons(udp->check));
	}

	udp_ports.src = htons(udp->source);
	udp_ports.dst = htons(udp->dest);
	udp_ports.ln = sizeof(struct udphdr);

	return udp_ports;
}

/*** Affiche les informations TCP contenues le paquet donné en argument***/
struct ports print_tcp(const u_char * packet, u_char v)
{
	struct tcphdr * tcp = (struct tcphdr *)(packet);


	//int taille_tcphdr_ss_option = sizeof(struct tcphdr);
	struct ports tcp_ports;

	tcp_ports.src = htons(tcp->source);
	tcp_ports.dst = htons(tcp->dest);
	tcp_ports.ln = tcp->th_off*4;

	switch(v)
	{
		case 1:
			break;

		case 2:
			printf(	"Source TCP : %u (0x%02x) / "
	       	"Destination TCP : %u (0x%02x)\n", htons(tcp->source), htons(tcp->source), 
			   									htons(tcp->dest), htons(tcp->dest));
			break;

		case 3:
			printf(	"Source TCP : %u (0x%02x)\n"
	       	"Destination TCP : %u (0x%02x)\n"
	       	"Numéro Séquence : 0x%04x\n"
	       	"Numéro Acquittement : 0x%04x\n"
			"Taille En-tête : %u\n"
			"Flags : 0x%01x\n"
			"Fenêtre : 0x%02x\n"
			"Checksum : 0x%02x\n"
			"Pointeur Urgent : 0x%02x\n", htons(tcp->source), htons(tcp->source), htons(tcp->dest), htons(tcp->dest), 
										htonl(tcp->th_seq), htonl(tcp->th_ack), tcp->th_off, tcp->th_flags,
										htons(tcp->th_win), htons(tcp->th_sum), htons(tcp->th_urp));
			break;
	}

	/*if(tcp_ports.ln-taille_tcphdr_ss_option)
		print_tcp_options(packet+taille_tcphdr_ss_option, taille_tcphdr_ss_option, tcp_ports.ln);*/

	return tcp_ports;
}

/*void print_tcp_options(const u_char * packet, uint8_t len_ss_opt, uint8_t len)
{
	int off = len_ss_opt;
	struct tlv tlv;
	while(len-off>0)
	{
		tlv.type=packet[off];
		tlv.taille = packet[off+1];
		tlv.data=malloc(tlv.taille);
		for(int i=0; i<tlv.taille; i++)
			tlv.data = packet[off+2+i];	
	}
	return;
}*/

/*** Affiche les informations ICMP contenues le paquet donné en argument***/
void print_icmp(const u_char * packet, u_char v)
{
	struct icmphdr * icmp = (struct icmphdr *)(packet);

	switch(v)
	{	
		case 1:
			break;

		case 2:
			printf("*TODO*\n"); //TODO

		case 3:
			printf("Type : %01x\n", icmp->type);
			printf("Code d'erreur : %01x\n", icmp->code);
			printf("Checksum : %02x\n", htons(icmp->checksum));
			//print_icmp_packet_mean(icmp->type,icmp->code);
	}

}

/* Fonctions affichant les différentes addresses MAC et IP */

/*** Permet d'indiquer après le numéro de protocole dans l'affichage des en-têtes
	 le nom du protocole correspondant respectivement pour les couche 3 et 4 ***/
void print_protocol_name_layer3(uint16_t prot)
{
	switch(prot)
	{
		case ETHERTYPE_IP:
			printf("(IPv4)\n");
			break;

		case ETHERTYPE_IPV6:
			printf("(IPv6)\n");
			break;

		case ETHERTYPE_ARP:
			printf("(ARP)\n");
			break;
	}
}

void print_protocol_name_layer4(uint8_t prot)
{
	switch(prot)
	{
		case IPPROTO_TCP:
			printf("(TCP)\n");
			break;

		case IPPROTO_UDP:
			printf("(UDP)\n");
			break;

		case IPPROTO_ICMP:
			printf("(ICMP)\n");
			break;
	}
}

/*** Fonction permettant un message de caractères ASCII de longueur len ***/
void print_message(const u_char * packet, int len)
{
	for(int i=0; i<len; i++)
		printf("%c", packet[i]);
	printf("\n");
}

/*** Affiche l'adresse MAC donnée en argument sous la forme A:B:C:D:E:F ***/
void print_mac_address(unsigned char * addr)
{
	for(int i=0; i<ETH_ALEN; i++)
	{
		if(i==0)
			printf("%02x", addr[0]);
		else
			printf(":%02x", addr[i]);
	}
	printf("\n");
}


/*** Affiche les informations Ethernet contenues le paquet donné en argument***/
uint16_t print_ethernet(const u_char * packet, u_char v)
{
	struct ether_header * ethernet = (struct ether_header*)(packet);

	switch(v)
	{
		case 1:
			break;

		case 2:
			printf("*TODO*\n"); //TODO
			break;

		case 3:
			printf("Destination Ethernet : ");
			print_mac_address(ethernet->ether_dhost);
			printf("Source Ethernet : ");
			print_mac_address(ethernet->ether_shost);
			printf("Protocole : ");
			printf("0x%04x ", htons(ethernet->ether_type));
			print_protocol_name_layer3(htons(ethernet->ether_type));
			break;
	}

	return(htons(ethernet->ether_type));
}


/* Fonctions concernant les protocoles de la couche 3*/

/*** Affiche l'adresse IPv4 sous forme A.B.C.D (en décimale) ***/
void print_ipv4_addr(uint32_t addr)
{
    unsigned char * ip_addr = (unsigned char *)(&addr);

    printf("%i.%i.%i.%i\n", ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
}

/*** Affiche l'adresse IPv6 sous forme A:B::C (en hexadécimale)
	 Remplace bien la plus grande série de zéros dans l'adresse par '::'***/
void print_ipv6_addr(uint16_t *addr)
{	
	int nb0, ind0, newind, nb0max = 0;
	int i;

	for(i=0; i<8; i++)
	{
		if(addr[i] == 0 && nb0==0)
		{
			newind = i;
			nb0++;
		}

		else if(addr[i] == 0)
			nb0++;

		else
		{
			if(nb0>nb0max)
			{
				nb0max=nb0;
				ind0=newind;
			} 
			nb0=0;
		}
		
	}
	if(nb0>nb0max)
	{
		nb0max=nb0;
		ind0=newind;
	}
	

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


/*** Affiche les informations IPv4 contenues le paquet donné en argument***/
uint8_t print_ipv4(const u_char * packet, u_char v)
{
	struct ip * ipv4 = (struct ip*)(packet);

	switch(v)
	{
		case 1:
			break;
			
		case 2:
			printf("*TODO*\n"); //TODO
			break;
		
		case 3:
			printf("Source IPv4 : ");
			print_ipv4_addr(ipv4->ip_src.s_addr);

			printf("Destination IPv4 : ");
			print_ipv4_addr(ipv4->ip_dst.s_addr);

			printf( "Numéro Identification : 0x%04x\n"
					"Fragment offset : 0x%04x\n"
					"Longueur totale : %u\n"
					"TTL : %u\n"
					"Version IP : 0x%01x\n"
					"Protocole : %01x ", htons(ipv4->ip_id), htons(ipv4->ip_off), htons(ipv4->ip_len), 
											ipv4->ip_ttl, ipv4->ip_v,ipv4->ip_p);									
			print_protocol_name_layer4(ipv4->ip_p);
			break;
	}

	return(ipv4->ip_p);
}

/*** Affiche les informations IPv6 contenues le paquet donné en argument***/
uint8_t print_ipv6(const u_char * packet, u_char v)
{
	struct ip6_hdr * ipv6 = (struct ip6_hdr*)(packet);

	switch(v)
	{		
		case 1:
			break;

		case 2:
			printf("*TODO*\n"); //TODO
			break;

		case 3:
			printf("Source IPV6 : ");
			print_ipv6_addr(ipv6->ip6_src.__in6_u.__u6_addr16);

			printf("Destination IPV6 : ");
			print_ipv6_addr(ipv6->ip6_dst.__in6_u.__u6_addr16);

			printf("Next Header : %02x ",ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
			print_protocol_name_layer4(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
			printf(	"Payload Length : %04x\n"
				"Hop Limit : %02x\n"
				"Version : %01x\n", htons(ipv6->ip6_ctlun.ip6_un1.ip6_un1_plen),
							ipv6->ip6_ctlun.ip6_un1.ip6_un1_hlim, (char)(ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow>>4));
			break;
	}

	return(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
}

/*** Affiche les informations ARP contenues le paquet donné en argument***/
uint16_t print_arp(const u_char * packet, u_char v)
{
	struct arphdr * arp = (struct arphdr*)(packet);
	unsigned int off = 0;

	switch(v)
	{	
		case 1:
			break;
				
		case 2:
			printf("*TODO*\n"); //TODO
			break;

		case 3:
			printf("Format of hardware address : %02x (Ethernet)\n"
				"Format of protocol address : %02x ", htons(arp->ar_hrd), htons(arp->ar_pro));
			print_protocol_name_layer3(htons(arp->ar_pro));
			printf(	"Length of hardware address : %02x\n"
				"Length of protocol address : %02x\n"
				"ARP opcode : %01x\n", arp->ar_hln, arp->ar_pln, htons(arp->ar_op));
			
			off+=sizeof(struct arphdr);

			printf("Sender MAC Address : ");
			print_mac_address((unsigned char *)(packet+off));
			off+=6;
			printf("Sender IP Address : ");
			print_ipv4_addr(*(uint32_t*)(packet+off));
			off+=4;
			printf("Target MAC Address : ");
			print_mac_address((unsigned char *)(packet+off));
			off+=6;
			printf("Target IP Address : ");
			print_ipv4_addr(*(uint32_t*)(packet+off));
			break;
	}
	return 0;
}


/* Fonctions concernant les protocoles de la couche Application*/

void print_http(const u_char * packet, int size, u_char v)
{
	char * http = (char *)packet;

	switch(v)
	{
		case 3:
			for(int i=0; i<size; i++)
			{
				if(http[i]<0x1f)
					printf(".");
				else
					printf("%c",http[i]);
			}
			break;

		default:
			break;

	}
}

unsigned int print_dns_question_section(const u_char * packet)
{
	unsigned int off = 0;
	uint8_t name_ln;

	printf("Nom de domaine : ");
	while(packet[off] != 0)	
	{
		name_ln = *(uint8_t*)(packet+off);
		for(int j=0; j<name_ln; j++)
			printf("%c", packet[off+1+j]);
		off+=name_ln+1;
		printf(".");
	}
	printf("\n");
	off+=1;
	uint16_t qtype = htons(*(uint16_t*)(packet+off));
	off+=2;
	uint16_t qclass = htons(*(uint16_t*)(packet+off));
	off+=2;
	printf(	"QType : %02x\n"
			"QClass : %02x\n", qtype, qclass);
	return(off);
}

unsigned int print_dns_ressource_record(const u_char * packet)
{
	unsigned int off = 0;
	uint8_t name_ln;
	uint16_t domain_name_question;

	printf("Nom de domaine : ");
	
	domain_name_question = htons(*(uint16_t*)packet);
	while(domain_name_question != 0xc00c && domain_name_question != 0xc011 && domain_name_question != 0xc03b && domain_name_question != 0xc058)	
	{
		name_ln = *(uint8_t*)(packet+off);
		for(int j=0; j<name_ln; j++)
			printf("%c", packet[off+1+j]);
		off+=name_ln+1;
		printf(".");
		domain_name_question = htons(*(uint16_t*)(packet+off));
	}
	printf("*TODO*\n");
	off+=2;
	uint16_t type = htons(*(uint16_t*)(packet+off));
	off+=2;
	uint16_t classe = htons(*(uint16_t*)(packet+off));
	off+=2;
	uint32_t ttl = htonl(*(uint32_t*)(packet+off));
	off+=4;
	uint16_t rdlen = htons(*(uint16_t*)(packet+off));
	off+=2;
	printf(	"Type : %02x\n"
			"Classe : %02x\n"
			"TTL : %04x\n"
			"Taille des données : %02x\n", type, classe, ttl, rdlen);
	printf("Contenu des données non détaillé\n");
	off+=rdlen;

	return off;
}

void print_dns(const u_char * packet, u_char v)
{
	int off = 0;

	uint16_t id = *(uint16_t*)(packet+off);
	off+=2;
	uint8_t dns_header_mult_field = *(uint8_t*)(packet+off);
	uint8_t QR = (dns_header_mult_field & (0b10000000))>>7;
	uint8_t op_code = (dns_header_mult_field & (0b01111000))>>3;
	off+=1;
	uint8_t rcode = *(uint8_t*)(packet+off) & (0xf);
	off+=1;
	uint16_t qdcount = htons(*(uint16_t*)(packet+off));
	off+=2;
	uint16_t ancount = htons(*(uint16_t*)(packet+off));
	off+=2;
	uint16_t nscount = htons(*(uint16_t*)(packet+off));
	off+=2;
	uint16_t arcount = htons(*(uint16_t*)(packet+off));
	off+=2;

	switch(v)
	{
		case 3:
			printf(	"ID DNS : 0x%02x\n"
					"QR : %01x", htons(id), QR);
			if(QR == 0)	
				printf(" (Question)\n");
			else	
				printf(" (Réponse)\n");
			printf(	"OP_Code : %01x\n"
					"RCode : %01x\n"
					"QDCount : %02x\n"
					"ANCount : %02x\n"
					"NSCount : %02x\n"
					"ARCount : %02x\n\n", op_code, rcode, 
										qdcount, ancount, nscount, arcount);

			if(qdcount)
				printf("---------Question Section---------\n");
				for(int i=0; i<qdcount; i++)
					off+=print_dns_question_section(packet+off);
				printf("----------------------------------\n\n");
			
			if(ancount || nscount || arcount)
				
				for(int i=0; i<ancount; i++)
				{
					printf("---------Answer Section---------\n");
					off+=print_dns_ressource_record(packet+off);
					printf("---------------------------------\n\n");
				}
				
				for(int i=0; i<nscount; i++)
				{
					printf("---------Authority Records Section---------\n");
					off+=print_dns_ressource_record(packet+off);
					printf("-------------------------------------------\n\n");
				}
				
				for(int i=0; i<arcount; i++)
				{
					printf("---------Additional Records Section---------\n");
					off+=print_dns_ressource_record(packet+off);
					printf("--------------------------------------------\n\n");
				}
				break;

			default:
				break;

	}


}

void print_bootp_options(uint8_t * packet)
{
	uint8_t type;
	uint8_t len;
	unsigned int off=0;

	if(htonl(*(uint32_t*)packet) != 0x63825363)
	{
		printf("No Options DHCP");
		return;
	}
			
	printf("Option DHCP :\n");

	off+=4;

	while((type=*(uint8_t*)(packet+off))!=TAG_END)
	{
		printf("	");
		off+=1;
		len = *(uint8_t*)(packet+off);
		off+=1;
		switch(type)
		{
			case TAG_SUBNET_MASK:
				printf("Subnet Mask : ");
				print_ipv4_addr(*(uint32_t*)(packet+off));
				off+=len;
				break;

			case TAG_GATEWAY:
				printf("Router : \n");
				for(int i=0; i<(len/4); i++)
				{
					printf("		");
					print_ipv4_addr(*(uint32_t*)(packet+off));
					off+=4;
				}
				break;

			case TAG_DOMAIN_SERVER:
				printf("Domain Name Server : \n");
				for(int i=0; i<(len/4); i++)
				{
					printf("		");
					print_ipv4_addr(*(uint32_t*)(packet+off));
					off+=4;
				}
				break;			

			case TAG_HOST_NAME:
				printf("Host Name : ");
				print_message(packet+off, len);
				off+=len;
				break;

			case TAG_DOMAIN_NAME:
				printf("Domain Name : ");
				print_message(packet+off, len);
				off+=len;
				break;

			case 28:
				printf("Broadcast Address : ");
				print_ipv4_addr(*(uint32_t*)(packet+off));
				off+=len;
				break;

			case 50:
				printf("Requested IP Address : ");
				print_ipv4_addr(*(uint32_t*)(packet+off));
				off+=len;
				break;

			case 51:
				printf("IP Address lease time : %u\n", htonl(*(uint32_t*)(packet+off)));
				off+=len;
				break;

			case 53:
				printf("DHCP Message Type : ");
				switch(*(uint8_t*)(packet+off))
				{
					case 1:
						printf("Discover");
						break;
					case 2:
						printf("Offer");
						break;
					case 3:
						printf("Request");
						break;
					case 5:
						printf("Ack");
						break;
					case 7:
						printf("Release");				
				}
				printf("\n");
				off+=1;
				break;

			case 54:
				printf("Server Identifier : ");
				print_ipv4_addr(*(uint32_t*)(packet+off));
				off+=len;
				break;
			default:
				printf("Unknown option\n");
				off+=len;
		}
	}	
}

void print_bootp(const u_char * packet, u_char v)
{
	struct bootp * bootp = (struct bootp *)packet;

	switch(v)
	{
		case 3:
			printf("Type Message : ");
			if(bootp->bp_op == 1)
				printf("Boot Request (1)\n");
			else
				printf("Boot Reply (2)\n");
			printf("Hardware Type : ");
			if(bootp->bp_htype == 1)
				printf("Ethernet (0x01)\n");
			else
				printf("Hardware non reconnu (%01x)\n", bootp->bp_htype);

			printf(	"Longueur de l'Adresse Hardware : %01x\n"
					"Hops : %01x\n"
					"Transaction ID: 0x%04x\n"
					"Temps écoulé (secondes) : %02x\n"
					"Flags : 0x%02x\n"
					"Adresse IP Client : ", bootp->bp_hlen , bootp->bp_hops, 
					htonl(bootp->bp_xid), htons(bootp->bp_secs),
					htons(bootp->bp_unused));
			print_ipv4_addr(bootp->bp_ciaddr.s_addr);
			printf("Ton Adresse IP : ");
			print_ipv4_addr(bootp->bp_yiaddr.s_addr);
			printf("Adresse IP Serveur : ");
			print_ipv4_addr(bootp->bp_siaddr.s_addr);
			printf("Adresse IP Passerelle : ");
			print_ipv4_addr(bootp->bp_giaddr.s_addr);
			printf("Adresse Hardware Client : ");
			if(bootp->bp_htype == 1)
				print_mac_address(bootp->bp_chaddr);
			else
				printf("Adresse Hardware non reconnu\n");
			printf(	"Nom du serveur : *TODO* \n"
					"Nom du fichier de boot : *TODO*\n");
			print_bootp_options(bootp->bp_vend);
			break;

		default:
			break;
	}
}

void print_pop(const u_char * packet, int size, u_char v)
{
	char * pop = (char *)packet;

	switch(v)
	{
		case 3:
			for(int i=0; i<size; i++)
			{
				if(pop[i]<0x1f)
					printf(".");
				else
					printf("%c",pop[i]);
			}
			break;

		default:
			break;
	}
}

void print_smtp(const u_char * packet, int size, u_char v)
{
	char * smtp = (char *)packet;

	switch(v)
	{
		case 3:
			for(int i=0; i<size; i++)
			{
				if(smtp[i]<0x1f)
					printf(".");
				else
					printf("%c",smtp[i]);
			}
			break;

		default:
			break;
	}

}

void print_imap(const u_char * packet, int size, u_char v)
{
	char * imap = (char *)packet;

	switch(v)
	{
		case 3:
			for(int i=0; i<size; i++)
			{
				if(imap[i]<0x1f)
					printf(".");
				else
					printf("%c",imap[i]);
			}
			break;

		default:
			break;
	}

}

void print_ftp(const u_char * packet, int size, u_char v)
{
	char * ftp = (char *)packet;

	switch(v)
	{
		case 3:
			for(int i=0; i<size; i++)
			{
				if(ftp[i]<0x1f)
					printf(".");
				else
					printf("%c",ftp[i]);
			}
			break;

		default:
			break;
	}
}

void print_packet(const u_char * packet, int len)
{
	for(int i=0; i<len; i++)
		printf("%02x ", packet[i]);
	printf("\n\n");
}

void packet_handler(u_char * args, const struct pcap_pkthdr* header, const u_char * packet)
{
	uint16_t couche_reseau_protocole;
	uint8_t couche_transport_protocole;
	uint16_t application_port = 0;
	int offset = 0;
	int taille_paquet = header->len;
	struct ports ports_couche3;

	printf("N°%i\n",n_packet);
	//printf("Taille du paquet : %i\n\n", taille_paquet);
	//print_packet(packet,taille_paquet);
	
	if( *args == 1)
		printf("Ethernet ");
	else
		printf("----------ETHERNET----------\n");
	couche_reseau_protocole = print_ethernet(packet, *args);
	offset += sizeof(struct ether_header);
	
	switch(couche_reseau_protocole)
	{

		case ETHERTYPE_IP:
			if(*args == 1)
				printf("IPv4 ");
			else
				printf("----------IPv4----------\n");
			
			couche_transport_protocole = print_ipv4(packet+offset, *args);			
			offset += sizeof(struct ip);
			break;

		case ETHERTYPE_IPV6:
			if(*args == 1)
				printf("IPv6 ");
			else
				printf("----------IPv6----------\n");
			couche_transport_protocole = print_ipv6(packet+offset, *args);
			offset += sizeof(struct ip6_hdr);
			break;

		case ETHERTYPE_ARP:
			if(*args == 1)
				printf("ARP ");
			else
				printf("----------ARP----------\n");
			couche_transport_protocole = print_arp(packet+offset, *args);
			offset += sizeof(struct arphdr);
			break;
	}
	switch(couche_transport_protocole)
	{
		case 0:
			//TODO
			break;

		case IPPROTO_TCP:
			if(*args == 1)
				printf("TCP ");
			else
				printf("----------TCP----------\n");
			ports_couche3 = print_tcp(packet+offset, *args);
			offset += ports_couche3.ln;
			break;

		case IPPROTO_UDP:
			if(*args == 1)
				printf("UDP ");
			else
				printf("----------UDP----------\n");
			ports_couche3 = print_udp(packet+offset, *args);
			offset += ports_couche3.ln;
			break;

		case IPPROTO_ICMP:
			if(*args == 1)
				printf("ICMP ");
			else
				printf("----------ICMP----------\n");
			print_icmp(packet+offset, *args);
			break;
	}

	if(ports_couche3.src<ports_couche3.dst)
		application_port=ports_couche3.src;
	else	
		application_port=ports_couche3.dst;
	
	int size = taille_paquet-offset;
	packet+=offset;

	if(!size)
		application_port = 0;

	switch(application_port)
	{
		case 0:	
			break;

		case HTTP_PORT:
			if(*args == 1)
				printf("HTTP ");
			else
				printf("----------HTTP----------\n");
			print_http(packet, size, *args);
			break;

		case DNS_PORT:
			if(*args == 1)
				printf("DNS ");
			else
				printf("----------DNS----------\n");
			print_dns(packet, *args);
			break;

		case BOOTP_SERVER_PORT:
			if(*args == 1)
				printf("BOOTP ");
			else
				printf("----------BOOTP----------\n");
			print_bootp(packet, *args);
			break;

		case BOOTP_CLIENT_PORT:
			if(*args == 1)
				printf("BOOTP ");
			else
				printf("----------BOOTP----------\n");
			print_bootp(packet, *args);
			break;

		case POP_PORT:
			if(*args == 1)
				printf("POP ");
			else
				printf("----------POP----------\n");
			print_pop(packet,size, *args);
			break;
		
		case SMTP_PORT:
			if(*args == 1)
				printf("SMTP ");
			else
				printf("----------SMTP----------\n");
			print_smtp(packet,size-2, *args);
			break;
		
		case IMAP_PORT:
			if(*args == 1)
				printf("IMAP ");
			else
				printf("----------IMAP----------\n");
			print_imap(packet,size-2, *args);
			break;

		case FTP_CMD_PORT:
			if(*args == 1)
				printf("FTP ");
			else
				printf("----------FTP----------\n");
			print_ftp(packet,size-2, *args);
			break;
		
		case FTP_DATA_PORT:
			if(*args == 1)
				printf("FTP ");
			else
				printf("----------FTP----------\n");
				print_ftp(packet,size-2, *args);
			break;	
	}
	printf("\n\n");
	n_packet++;
	return;
}

int main(int argc, char ** argv)
{

	char * interface = NULL;
	char * buferr = malloc(60);
	int resultat;
	int c;
	u_char verbosite = 3;
	pcap_t * capture;
	struct bpf_program * filtre = calloc(1,sizeof(struct bpf_program));
	bpf_u_int32 net = 0;

	while((c=getopt(argc, argv, "i:o:f:v:h")) != EOF)
	{
		switch(c)
		{
			case 'i':
				interface = optarg;
				if(interface == NULL)
					affiche_error(buferr);
				capture = pcap_open_live(interface,1514,1,0,buferr);
				if(capture == NULL)
					affiche_error(buferr);
				break;

			case 'o':
				capture = pcap_open_offline(optarg,buferr);
				if(capture == NULL)
					affiche_error(buferr);
				break;

			case 'f':
				if(pcap_compile(capture, filtre, optarg, 0, net) == -1)
				{
					fprintf(stderr, "Couldn't parse filter %s: %s\n", optarg, pcap_geterr(capture));
					affiche_aide();
					return 0;
				}
				printf("Etablissement du filtre\n");
				pcap_setfilter(capture, filtre);
				printf("Filtre établi\n");		
				break;

			case 'v':
				verbosite = atoi(optarg);
				if(verbosite<1 || verbosite>3)
				{
					affiche_error("Argument verbosite ne convient pas");
					affiche_aide();
				}
				break;

			case 'h':
				affiche_aide();
				return 0;
		}
	}
	resultat = pcap_loop(capture, -1, packet_handler, &verbosite);
	return resultat;
}


