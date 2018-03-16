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
int numerator=0;
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
	unsigned int sent;
	unsigned int received;
	int number;
	int numerator;
	int starttime;
	int endtime;
	int once;
};
struct samp s[50];
struct tm *ts;
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
int cot=5;
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

unsigned int reverseBits(unsigned int x)
{
return
(x>>24) |
((x>>8) & 0x0000ff00) |
((x<<8) & 0x00ff0000) |
(x<<24);
}


void fun(u_char *args,const struct pcap_pkthdr *hdr,const u_char *packet)
{
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	int  size;
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
	                if(s[j].no>0 &&s[j].no<3)
                        {
			printf("\t \t Flow  %d \n",j);
			printf("\n");
                        printf("Seq No: %u ",seqno);
                        printf("Ack No: %u ",ackno);
                        printf("Receive window size %u ",tcp->th_win);
                        printf("\n");
			printf("\n");
			printf("-------------------------------------------------------------\n");
                        s[j].no--;
                        }
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
		s[j].numerator=s[j].numerator+hdr->len;
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
		s[j].sent++;
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
		s[j].sent=0;
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
	pcap_close(handle);
	printf("\n");
	printf("Number of Connection Inititations from 130.245.145.12 are %d \n\n",count);
for(j=0;j<count;j++)
	{
	if(s[j].sum==0)
	break;
	printf("\t \t Flow  %d \n",j);
        printf("\n");
	printf("Empirical Throughput Efficiency is %f \n",(s[j].numerator*1.0)/(s[j].endtime-s[j].starttime));
	printf("-------------------------------------------------------------\n");
	}
	for(j=0;j<count;j++)
	{
	if(s[j].freq==0)
	break;
	printf("\t \t Flow  %d \n",j);
        printf("\n");
	printf("Theoritical Throughput is %f\n",s[j].total/(s[j].freq *1.0));
	printf("-------------------------------------------------------------\n");
	}	
	for(j=0;j<count;j++)
        {
      	unsigned int lost=s[j].received;
	float per=lost*1.0/(s[j].sent);
        printf("\n");
        printf("Loss rate is %f\n",per);
        printf("-------------------------------------------------------------\n");
        }
	for(j=0;j<count;j++)
        {
	if(s[j].cnt==0)
        break;
        printf("\t \t Flow  %d \n",j);
        printf("\n");
        printf("RTT is %d",(s[j].tot/s[j].cnt));
        printf("-------------------------------------------------------------\n");
        }

	return(0);
}














