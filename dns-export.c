/*
 * ISA
 * Zdroje muj projekt do IPK a konstra TCP dokumentace ze stranek predmentu
 * vypracoval David Dejmal xdejma00
 * 2018
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#define BUFSIZE 128

/**Poznamky:
 *
 * every end of main must end like this:
 * dealloc(pcapFile,syslog_ip,interface);
 *
 *
**/
void dealloc(char* pcap,char* syslog,char* interface);

/**
 * format local time to
 * YYYY-MM-DDTHH:MM:SS.SSSZ
 * and save to pointer
 * **/
void getFormatTime(char* timestamp);
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_body);
void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
void TypeDNS(char* typ,int value1,int value0);
void get_name(const u_char *packet_body,char * text,int pozice);

int main (int argc,char * argv[]) {

/*	printf("argc:%d\n",argc);
	for(int i=1;i<argc;i++)
	{
		printf("argv[%d]:%s\n",i,argv[i]);
	}

	
*/

    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

/****************************** PARSING ARGUMENTS ***********************
[-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]
-r string.pcap -i string -s ip string -t int
*/


	int runTime=60;
	char*  interface = NULL;
	char* pcapFile = NULL;
	char* syslog_ip = NULL;

	bool rFlag=false;
	bool iFlag=false;
	bool sFlag=false;
	bool tFlag=false;

	char lastOpt='x';

	if(argc%2==0)	//pouze lichy pocet parametru
	{
		fprintf(stderr,"Spatny pocet argumentu!");
		dealloc(pcapFile,syslog_ip,interface);
		return 1;
	}

 	for(int i=1;i<argc;i++)	
	{
		//zkontroluje prepinace
		if(strcmp(argv[i],"-r")==0)
		{
			rFlag=true;
			lastOpt='r';
			continue;
		}
		if(strcmp(argv[i],"-i")==0)
		{
			iFlag=true;
			lastOpt='i';
			continue;
		}
		if(strcmp(argv[i],"-s")==0)
		{
			sFlag=true;
			lastOpt='s';
			continue;			
		}
		if(strcmp(argv[i],"-t")==0)
		{
			tFlag=true;
			lastOpt='t';
			continue;			
		}

		/*
		printf("\nlastOpt:%c",lastOpt);
		printf("\nargv:%s",argv[i]);
		*/

		//propoji parametry
		switch(lastOpt)
		{
			case 'x':
				fprintf(stderr,"\nChybne zadane parametry!");
				dealloc(pcapFile,syslog_ip,interface);
				return 1;

			case 'i':	//prekopiruje argument do potrebne promene
			{
				interface=(char*)malloc(sizeof(char)*strlen(argv[i]));
				strcpy(interface,argv[i]);
				//printf("\n-i = %s",interface);
				lastOpt='x';
				break;
			}
			case 's':
			{
				syslog_ip=(char*)malloc(sizeof(char)*strlen(argv[i]));
				strcpy(syslog_ip,argv[i]);
				//printf("\n-s = %s",syslog_ip);
				lastOpt='x';
				break;
			}
			case 't':
			{	char* helppointer;
				runTime=strtol(argv[i],&helppointer,10);
				if((strcmp(helppointer,"")!=0)||(runTime<0))
				{
					fprintf(stderr,"Prepinac -t musi obsahovat kladne cislo!\n");
					dealloc(pcapFile,syslog_ip,interface);
					return 1;
				}
				//printf("\n-t = %d",runTime);
				break;
			}
			case 'r':
			{
				pcapFile=(char*)malloc(sizeof(char)*strlen(argv[i]));
				strcpy(pcapFile,argv[i]);
				//printf("\n-r = %s",pcapFile);
				break;
			}
		}



	}

	if(iFlag && rFlag) //-r a -i se vzajemne vylucuji
	{
		fprintf(stderr,"Prepinace i a r se vzajemne vylucuji!\n");
		dealloc(pcapFile,syslog_ip,interface);
		return 1;
	}

	if((iFlag || rFlag)==false) // musi byt zadan -r nebo -i
	{
		fprintf(stderr,"Musite zadat bud soubor -r nebo interface -i!\n");
		dealloc(pcapFile,syslog_ip,interface);
		return 1;
	}
/***********************************END OF PARSING ARGUMENTS************************************/

	if(rFlag)
	{
    		pcap_t *handle = pcap_open_offline(pcapFile, error_buffer);    
		struct bpf_program filter;
    		char filter_exp[] = "port 53";
    		bpf_u_int32 ip;

  		if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        		fprintf(stderr,"Spatny filtr: %s\n", pcap_geterr(handle));
			dealloc(pcapFile,syslog_ip,interface);
        		return 1;
    		}
    		if (pcap_setfilter(handle, &filter) == -1) {
        		fprintf(stderr,"Spatne nastaveny filtr:%s\n", pcap_geterr(handle));
			dealloc(pcapFile,syslog_ip,interface);
        		return 1;
    		}

		pcap_loop(handle, 0, packet_handler, NULL);

	}
	if(iFlag)
	{
 		pcap_t *handle;

    		/* Open device for live capture */
    		handle = pcap_open_live(interface,BUFSIZ,0,runTime,error_buffer);
    		if (handle == NULL) {
         		fprintf(stderr, "Could not open interface %s: %s\n", interface, error_buffer);
         	return 2;
     		}
     
    		pcap_loop(handle, 0, packet_handler, NULL);
	
	
	}	

 

/***********time stampg and end *************************************/
	char cas[25];
	getFormatTime(cas);
	printf("\nCAS:%s",cas);
	if(tFlag||sFlag)
	{
		printf("muhehe");
	}

	dealloc(pcapFile,syslog_ip,interface);
}

void packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body)
{
	//printf("Flags:%02x\n",packet_body[44]);
	char typ[]="UNKNOWN";
	char dotaz[258];  //max lenght of dns name
	int lenght=0;
	int answers;
	int counter=0;
	int pozice=44;
	int pointer=42;
	char name[258];
	//it is response - first bit of flags is 1
	if(packet_body[pozice]>=0x80)
	{
		//printf("Type:%02x %02x\n",packet_body[83],packet_body[84]);
		answers = 256 * packet_body[pozice+4] + packet_body[pozice+5];
		printf("Answer count:%d\n",answers);
		pozice=54;
		for(int i=pozice;;i++)
		{	
			pozice++;	
			if(packet_body[i]==0x00)
			{
				break;
			}		
		}
		printf("Pozice:%d hodnota:%02x\n",pozice,packet_body[pozice+1]);
		TypeDNS(typ,packet_body[pozice],packet_body[pozice+1]);
		printf("Type:%s\n",typ);
		if(strcmp(typ,"UNKNOWN")==0)
		{
			return;
		}
		if(answers==1)
		{
			pozice=pozice+4;
			pointer=((packet_body[pozice]-0xc0)*256+packet_body[pozice+1])+pointer;
			printf("Pointer:%02x %02x = %d\n",packet_body[pozice],packet_body[pozice+1],pointer);	
			//printf("Pointer cil:%02x\n",packet_body[pointer]);
			get_name(packet_body,name,pointer);
			//pozice=pozice+2;
			printf("Name:%s",name);

		}
		print_packet_info(packet_body, *packet_header);
	}
    	return;
}

void get_name(const u_char *packet_body,char * text,int pozice)
{
int counter=0;
int lenght=0;
for(unsigned int i=pozice;counter>=0;i++)
	{		
		if(packet_body[i]==0x00)
		{
			break;
		}
		if(counter==0)
		{
			counter=packet_body[i]+1;
			if(lenght!=0)
			{
				text[lenght]='.';
			}
			else
			{
				lenght--;
			}
		}
		else
		{	
			text[lenght]=packet_body[i];
		
		}
		counter--;
		lenght++;
	}
}


void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    	printf("Packet total length %d\n\n", packet_header.len);
}


void TypeDNS(char* typ,int value1,int value0)
{
	int value;
	value = value1 *256 + value0;
	switch(value)
	{
		case 1:strcpy(typ,"A");break;
		case 28:strcpy(typ,"AAAA");break;
		case 5:strcpy(typ,"CNAME");break;
		case 15:strcpy(typ,"MX");break;
		case 2:strcpy(typ,"NS");break;
		case 6:strcpy(typ,"SOA");break;
		case 16:strcpy(typ,"TXT");break;
		case 99:strcpy(typ,"SPF");break;
		case 32768:strcpy(typ,"DNSSEC");break;
	}
	printf("Vlaue:%d\n",value);
}


void getFormatTime(char* timestamp)
{
	time_t t;
	char buffer[25];
	char bufferMili[3];
	struct tm* tm_first;
	struct timeval now;

	//vrati a nastyluje pocet sekund
	time(&t);
	tm_first = localtime(&t);
	strftime(buffer, 21, "%Y-%m-%dT%H:%M:%S.", tm_first);
	strcpy(timestamp,buffer);
	//potrebne pro milisekundy
	gettimeofday(&now, NULL);
	sprintf(bufferMili,"%ld",now.tv_usec/1000);
	//append na konec rezezce
	strcat(timestamp,bufferMili);
	strcat(timestamp,"Z");


}

void dealloc(char* pcap,char* syslog,char* interface)
{
	printf("\n\n*******************DEALLOC**********************\n");
	if(pcap!=NULL)
	{
		printf("-r\n");
		free(pcap);
	}
	if(syslog!=NULL)
	{
		printf("-s\n");
		free(syslog);
	}
	if(interface!=NULL)
	{
		printf("-i\n");
		free(interface);
	}
}
