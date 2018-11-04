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
#include <signal.h>
#include <unistd.h>

#define BUFSIZE 128

typedef struct prvek
{
	struct prvek *pNext;
	char * string;
	int count;
}Prvek;

Prvek *root;
int runTime;
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
void get_name(const u_char *packet_body,char * text,int pozice,int index,bool ptr,char* type);
void smaz_vse();
bool add_prvek(char * req,char* typ,char *answer);
void signal_handler(int signum);
void alarm_handler();

int main (int argc,char * argv[]) {

	signal(SIGINT, signal_handler);	//TODO change to sigusr1
	signal(SIGALRM, alarm_handler);

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


	runTime=60;
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
	if(rFlag && tFlag) // musi byt zadan -r nebo -t
	{
		fprintf(stderr,"Prepinace r a t se vzajemne vylucuji!\n");
		dealloc(pcapFile,syslog_ip,interface);
		return 1;
	}
/***********************************END OF PARSING ARGUMENTS************************************/
	
	alarm(runTime);

	if(rFlag)
	{
    		pcap_t *handle = pcap_open_offline(pcapFile, error_buffer);    
		struct bpf_program filter;
    		char filter_exp[] = "port 53 and udp";
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

		if(sFlag)
		{
			printf("\n\n------------SENDING-------------\n\n");	//syslog send
		}
		else
		{
			printf("\n\nZpracovani dokonceno!\n");	//printf vse
		}

	}
	if(iFlag)
	{
 		pcap_t *handle;
     		struct bpf_program filter;
    		char filter_exp[] = "port 53 and udp";
    		bpf_u_int32 ip;

    		/* Open device for live capture */
    		handle = pcap_open_live(interface,BUFSIZ,0,runTime,error_buffer);
    		if (handle == NULL) {
         		fprintf(stderr, "Could not open interface %s: %s\n", interface, error_buffer);
         	return 2;
     		}


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
		
		//podle Time send to syslog
	
	}	

 

/***********time stampg and end *************************************/
	smaz_vse();

	char cas[25];
	getFormatTime(cas);
	printf("\nCAS:%s",cas);
	dealloc(pcapFile,syslog_ip,interface);
}

void packet_handler(u_char *args,const struct pcap_pkthdr *packet_header,const u_char *packet_body)
{

	char typ[]="UNKNOWN";
	char response[258];  //max lenght of dns name
	int answers;
	int pozice=44;
	char name[258];
	int dataLenght;
	//it is response - first bit of flags is 1
	if(packet_body[pozice]>=0x80)
	{
		print_packet_info(packet_body, *packet_header);
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
		//printf("Pozice:%d hodnota:%02x\n",pozice,packet_body[pozice+1]);
		pozice=pozice+4;

		for(int i=1;i<=answers;i++)
		{
			strcpy(typ,"UNKNOWN");
			printf("Answer no:%d\n",i);
			get_name(packet_body,name,pozice,0,true,typ);
			//printf("Name:%s\n",name);
			pozice=pozice+2;

			TypeDNS(typ,packet_body[pozice],packet_body[pozice+1]);
			//printf("Type:%s\n",typ);
			pozice=pozice+8;
			dataLenght=256 * packet_body[pozice] + packet_body[pozice+1];
			printf("Data lenght:%d\n",dataLenght);
			pozice=pozice+2;
			if(strcmp("UNKNOWN",typ)==0)
			{	
				printf("Type:UNKNOWN - SKIPED\n");
				pozice=pozice+dataLenght;
				continue;
			}
			get_name(packet_body,response,pozice,0,false,typ);
			//printf("response:%s\n",response);
			pozice=pozice+dataLenght;
			printf("%s %s %s\n",name,typ,response);
			if(add_prvek(name,typ,response)==false)
			{
				fprintf(stderr,"Problem s alokovanim pameti!");
			}

		}

	}
    	return;
}

void get_name(const u_char *packet_body,char * text,int pozice,int index,bool ptr,char* type)
{
	int counter=0;
	int lenght=index;
	int pointer;
	if(lenght==0)
	{
		memset(text, 0, 258);
	}
	if(ptr)
	{
		pointer=((packet_body[pozice]-0xc0)*256+packet_body[pozice+1])+42;
	//	printf("Pointer:%02x %02x = %d\n",packet_body[pozice],packet_body[pozice+1],pointer);
	}
	else
	{
		pointer=pozice;
	}
	if(strcmp("TXT",type)==0)
	{
		int count=packet_body[pointer];
		printf("TXT lenght:%d\n",count);
		pointer++;
		text[0]='\"';
		lenght++;
		for(int i=pointer;i<pointer+count;i++)
		{
			text[lenght]=packet_body[i];	
			lenght++;
		}
		text[lenght]='\"';
		text[lenght+1]='\0';
		return;
	}
	if(strcmp("A",type)==0)
	{
		//printf("IP 4-");
		char buffer[5];
		memset(buffer,0,5);
		for(int i = pointer;i<pointer+4;i++)
		{
			if(i==pointer+3)
			{
				sprintf(buffer,"%d",packet_body[i]);
			}
			else
			{
				sprintf(buffer,"%d.",packet_body[i]);
			}
			strcat(text,buffer);
		}
		//printf("\n");
		return;
	}
	if(strcmp("AAAA",type)==0)
	{
		char buffer[7];
		memset(buffer,0,7);
		//printf("IP 6-");
		for(int i = pointer;i<pointer+16;i=i+2)
		{
			if(i==pointer+14)
			{
				sprintf(buffer,"%02x%02x",packet_body[i],packet_body[i+1]);
			}
			else
			{
				sprintf(buffer,"%02x%02x:",packet_body[i],packet_body[i+1]);
			}
			strcat(text,buffer);
		}
		inet_pton(AF_INET6,text,&text);
		return;
	}
	if(strcmp("MX",type)==0)
	{
		if(ptr==false)
		{
			pointer=pointer+2;
		}
	}
	for(unsigned int i=pointer;counter>=0;i++)
	{		
		if(packet_body[i]==0x00)
		{
			break;
		}
		if(packet_body[i]>=0xc0)
		{
			//printf("PTR\n");
			get_name(packet_body,text,i,lenght,true,type);
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
    	printf("Packet total length %d\n---------------------------------------------------\n", packet_header.len);
}


void TypeDNS(char* typ,int value1,int value0)
{
	int value;
	value = value1 *256 + value0;
	switch(value)
	{
		case 1:strcpy(typ,"A");break;		//ok
		case 28:strcpy(typ,"AAAA");break;	//format
		case 5:strcpy(typ,"CNAME");break;	//ok
		case 15:strcpy(typ,"MX");break;		//ok
		case 2:strcpy(typ,"NS");break;		//TODO asi ide chce testovat
		case 6:strcpy(typ,"SOA");break;		//Problem
		case 16:strcpy(typ,"TXT");break;	//ok
		case 99:strcpy(typ,"SPF");break;	//ok
		case 32768:strcpy(typ,"DNSSEC");break;	//nenasel
		case 12:strcpy(typ,"PTR");break;		//ok
	}
	//printf("Vlaue:%d\n",value);
}



bool add_prvek(char * req,char* typ,char *answer)
{
	Prvek *Head = root;
	char * superstr;
	int lenght=0;

	lenght = strlen(req)+ strlen(typ) + strlen(answer) + 3;
	superstr=(char*)malloc(sizeof(char)*lenght);
	if(superstr==NULL)
	{
		return false;
	}
	strcpy(superstr,req);
	strcat(superstr," ");
	strcat(superstr,typ);
	strcat(superstr," ");
	strcat(superstr,answer);

	if(root==NULL)	//pro prazdny seznam
	{
		root=(Prvek*)malloc(sizeof(Prvek));
		if(root==NULL)
		{
			return false;
		}
		root->count=1;
		root->string=superstr;
		root->pNext=NULL;
	}
	else
	{
		if(strcmp(Head->string,superstr)==0)
		{
			Head->count++;
			return true;
		}
		while(Head->pNext!=NULL)	//nenaslo v seznamu a vlozi nakonec
		{

			Head=Head->pNext;
		}
		Head->pNext=(Prvek*)malloc(sizeof(Prvek));
		if(Head->pNext==NULL)
		{
			return false;
		}
		Head->pNext->count=1;
		Head->pNext->string=superstr;
		Head->pNext->pNext=NULL;
	}
	return true;
}

void smaz_vse()
{
	Prvek *m_pHead = root;
	Prvek *tmp;
	while (m_pHead != NULL){	//projde cely seznam a od zacatku ho zacne odalokovávat a odesilat
	tmp = m_pHead;
	m_pHead =m_pHead->pNext;
	printf("%s %d\n",tmp->string,tmp->count);

//tady send tmp

	free(tmp->string);
	free(tmp);
	}
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

void signal_handler(int signum)
{
	Prvek *m_pHead = root;
	Prvek *tmp;
	while (m_pHead != NULL){	//projde cely seznam a od zacatku ho zacne odalokovávat a odesilat
	tmp = m_pHead;
	m_pHead =m_pHead->pNext;
	printf("%s %d\n",tmp->string,tmp->count);
	}
	exit(signum); //TODO delete this
}

void alarm_handler()
{

	printf("\n\nALARM ALARM!!!!\n\n");
	alarm(runTime);
}
