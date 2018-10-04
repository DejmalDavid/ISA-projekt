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

int main (int argc,char * argv[]) {

/*	printf("argc:%d\n",argc);
	for(int i=1;i<argc;i++)
	{
		printf("argv[%d]:%s\n",i,argv[i]);
	}

*/
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
		printf("Spatny pocet argumentu!");
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
				printf("\nChybne zadane parametry!");
				dealloc(pcapFile,syslog_ip,interface);
				return 1;

			case 'i':	//prekopiruje argument do potrebne promene
			{
				interface=(char*)malloc(sizeof(char)*strlen(argv[i]));
				strcpy(interface,argv[i]);
				printf("\n-i = %s",interface);
				lastOpt='x';
				break;
			}
			case 's':
			{
				syslog_ip=(char*)malloc(sizeof(char)*strlen(argv[i]));
				strcpy(syslog_ip,argv[i]);
				printf("\n-s = %s",syslog_ip);
				lastOpt='x';
				break;
			}
			case 't':
			{	char* helppointer;
				runTime=strtol(argv[i],&helppointer,10);
				if((strcmp(helppointer,"")!=0)||(runTime<0))
				{
					printf("Prepinac -t musi obsahovat kladne cislo!\n");
					dealloc(pcapFile,syslog_ip,interface);
					return 1;
				}
				printf("\n-t = %d",runTime);
				break;
			}
			case 'r':
			{
				pcapFile=(char*)malloc(sizeof(char)*strlen(argv[i]));
				strcpy(pcapFile,argv[i]);
				printf("\n-r = %s",pcapFile);
				break;
			}
		}



	}
/***********************************END OF PARSING ARGUMENTS************************************/

	char cas[25];
	getFormatTime(cas);
	printf("\nCAS:%s",cas);

	dealloc(pcapFile,syslog_ip,interface);
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
