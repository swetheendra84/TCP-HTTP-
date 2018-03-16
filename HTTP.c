#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>
#include<stdlib.h>
struct sniff_ip {
        u_char  ip_vhl;                 
        u_char  ip_tos;                 
        u_short ip_len;                 
        u_short ip_id;                  
        u_short ip_off;                 
        #define IP_RF 0x8000            
        #define IP_DF 0x4000            
        #define IP_MF 0x2000            
        #define IP_OFFMASK 0x1fff       
        u_char  ip_ttl;                
        u_char  ip_p;                   
        u_short ip_sum;                 
        struct  in_addr ip_src,ip_dst;  
};

typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;               
        u_short th_dport;               
        uint32_t th_seq;                 
        uint32_t th_ack;                 
        u_char  th_offx2;               
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                
        u_short th_sum;                 
        u_short th_urp;                 
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
# define LEN 50000
int count=0;
int seq,ack;
unsigned int numerator,sent;
struct samp
{
	unsigned int port;
	char *ip;
	int begin;
	int end;
	int no;
	int sum;
	int total;
	int freq;
	int cnt;
	unsigned int tot;
	int time1[LEN];
	unsigned int seq[LEN];
	int packlen[LEN];
	unsigned int received;
	int number;
	int starttime;
	int endtime;
	int once;
};
struct samp s[50];
struct tm *ts;

unsigned int reverseBits(unsigned int x)
{
return
(x>>24) |
((x>>8) & 0x0000ff00) |
((x<<8) & 0x00ff0000) |
(x<<24);
}


void
print_hex_ascii_line(const u_char *payload, int len, int offset,const struct sniff_tcp *tcp)
{

        int i;
        int gap;
        const u_char *ch;
        ch = payload;

	if(strstr(payload,"HTTP")==NULL)
        {
	}
        else 
        {
        if(strstr(payload,"GET")==NULL)
        {
                printf("--------------HTTP GET REQUEST --------------- \n");
                printf("\n");
        }
        else
        {
                printf("--------------HTTP RESPONSE --------------- \n");
                printf("\n");
        }
        printf("\n");
        seq=reverseBits(tcp->th_seq);
        ack=reverseBits(tcp->th_ack);
	printf("Source port %u Destination port %u Sequence NUmber %u Acknowledge Number %u \n",tcp->th_sport,tcp->th_dport,seq,ack);
        printf("\n");
        char *p=strstr(payload,"HTTP/1.0");
        if(p!=NULL)
        {
                printf("Protocol used is HTTP/1.0 \n");
        }
        else
        {
                p=strstr(payload,"HTTP/1.1");
                if(p!=NULL)
                {
                        printf("Protocol used is HTTP/1.1 \n");
                }
                else
                {
                        printf("Protocol used is HTTP/2.0 \n");
                }
        }
	}
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
                        printf("%c",*ch);
                else
                        printf(".");
                ch++;
        }
        printf("\n");
return;
}

void
printpayload(const u_char *payload, int len,const struct sniff_tcp *tcp)
{
        int len_rem = len;
        int line_width = 30;
        int line_len;
        int offset = 0;
        const u_char *ch = payload;

        if (len <= 0)
                return;

        if (len <= line_width) {
                print_hex_ascii_line(ch, len, offset,tcp);
                return;
        }

	for ( ;; ) {
                line_len = line_width % len_rem;
                print_hex_ascii_line(ch, line_len, offset,tcp);
                len_rem = len_rem - line_len;
                ch = ch + line_len;
                offset = offset + line_width;
                if (len_rem <= line_width) {
                        print_hex_ascii_line(ch, len_rem, offset,tcp);
                        break;
                }
        }

return;
}


int countflows(int srcport,char *ipaddr,int dstport)
{
	int i;
	if(srcport<0)
	return count;
	for(i=0;i<50;i++)
	{
		if(s[i].port==srcport||s[i].port==dstport)
		return count;
		if(s[i].port==-1)
		break;
	}
	s[i].port=srcport;
	count++;
}
int total;
unsigned int mark;
void calc(const struct sniff_tcp *tcp,char *ip,const struct pcap_pkthdr *hdr,int j,int k,int seq,int ack)
{
		int l;	
		for(l=0;l<=k;l++)
        	{
		if((s[j].seq[l]+1)==ack)
		{
			s[j].cnt++;
			ts=localtime(&hdr->ts.tv_sec);
			s[j].tot=s[j].tot+(ts->tm_sec-s[j].time1[l]);
		}
		}
		for(l=0;l<k;l++)
		{
		if(seq==s[j].seq[l])
		{
			s[j].received++;
			break;
		}
        	}

}


void fun(u_char *args,const struct pcap_pkthdr *hdr,const u_char *packet)
{
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	int  size;
	char buf[255];
	mark=hdr->ts.tv_sec;
	ip=(struct sniff_ip *)(packet+14);
	size=IP_HL(ip)*4;
	if(size<20)
	{
		return;
	}
	char *ipaddr=(char *)malloc(20);
	int flag=0;
	sprintf(ipaddr,"%s",inet_ntoa(ip->ip_src));
	tcp = (struct sniff_tcp*)(packet + 14 + size);
	int tcpsize=TH_OFF(tcp)*4;
	if(tcpsize<20)
	{
		return;
	}
	uint16_t srcport=ntohs(tcp->th_sport);
	uint16_t dstport=ntohs(tcp->th_dport);
	int seqno=reverseBits(tcp->th_seq);
	int ackno=reverseBits(tcp->th_ack);
	countflows(srcport,ipaddr,dstport);
		int j;
		if(strcmp(ipaddr,"128.208.2.198")==0)
		{
			for(j=0;j<50;j++)
                        {
                                if(s[j].port==dstport)
                                break;
                        }
	
		}
		else
		{
			for(j=0;j<50;j++)
			{
				if(s[j].port==srcport)
				break;
			}
		}
			if(j==50)
				return;
			if(s[j].once)
        		{
                	s[j].starttime=hdr->ts.tv_sec;
                	s[j].once--;
		        }
			s[j].number++;
	int k;
        for(k=0;k<LEN;k++)
        {
                if(s[j].time1[k]==0)
                break;
        }
		numerator=numerator+hdr->len;
		s[j].time1[k]=hdr->ts.tv_sec;
		s[j].seq[k]=seqno; 
		const char *payload=(u_char *)(packet+14+size+tcpsize);
        	int payload_size=ntohs(ip->ip_len)-(size+tcpsize);
	        s[j].sum=s[j].sum+payload_size;
	        s[j].total=s[j].total+tcp->th_win;
	        s[j].freq++;
		int paylen=hdr->len-14-size-tcpsize;
		s[j].packlen[k]=paylen;
		calc(tcp,ipaddr,hdr,j,k,seqno,ackno);
		s[j].endtime=hdr->ts.tv_sec;
		sent++;
		if(payload_size>0)
        	{
                	printpayload(payload,payload_size,tcp);
        	}
		mark=(long)(mark-hdr->ts.tv_sec);
        	return;
}

int main(int argc,char *argv[])
{
	char buffer[1024];
	pcap_t *handle;
	char *file=NULL;
	if(argc!=2)
	{
		printf("Invalid Number of arguments \n");
		return(0);
	}
	handle=pcap_open_offline(argv[1],buffer);
	if(handle==NULL)
	{
		printf("opening file failed %s",buffer);
		return(0);
	}
	int j;
	for(j=0;j<50;j++)
		{
		s[j].port=-1;
		s[j].end=-1;
		s[j].no=2;
		s[j].sum=0;
		s[j].total=0;
		s[j].freq=0;
		s[j].tot=0;
		s[j].cnt=0;
		s[j].received=0;
		s[j].starttime=0;
		s[j].endtime=0;
		s[j].once=1;
		for(int l=0;l<LEN;l++)
		{
			s[j].packlen[l]=0;
			s[j].time1[l]=0;
			s[j].seq[l]=0;
		}
		}
	pcap_loop(handle,-1,fun,NULL);
	printf("Total Number of packets are %d \n",sent);
	printf("Total Raw Bytes is %u \n",numerator);
	printf("indicator of time %f \n",(mark *1.0)/sent);
	return(0);
}














