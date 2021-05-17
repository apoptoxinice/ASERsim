#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>


struct timer_set
{
	int id;
	struct tm time;
	char cmd[128];
	int stats;
};
struct timer_set timer_list[5];



int cmp_time(struct tm *tm1,struct tm *tm2)
{
    if(tm1->tm_hour == tm2->tm_hour && tm1->tm_min == tm2->tm_min && tm1->tm_sec == tm2->tm_sec)
    {
        return 1;    
    }
    
    return 0;    
}


#if 1
void check_loop(char *host_name)
{
 #if 1
    time_t rawtime;
	struct tm *timeinfo;
	int i;
    char sys_cmd[100];

	time(&rawtime);
	//printf("rawtime = %lu\n",rawtime);
	timeinfo = localtime(&rawtime);
	//printf("current date/time is %s\n",asctime(timeinfo));
	//printf("tm_sec = %d\n",timeinfo->tm_sec);
	//printf("tm_min = %d\n",timeinfo->tm_min);
	//printf("tm_hour = %d\n",timeinfo->tm_hour);
#endif
    for(i=0;i<5;i++)
	{
		if(timer_list[i].id == 0)
			continue;
        memset(sys_cmd,0,sizeof(sys_cmd));

        if(cmp_time(&if_list[i].up_time,timeinfo))/*need set up*/
        {
	        printf("current date/time is %s\n",asctime(timeinfo));
            if(if_list[i].stats == 0)
            {
                sprintf(sys_cmd,"ip link set dev %s up",if_list[i].ifname); 
            }else{
                printf("waring: %s already up\n",if_list[i].ifname);    
			    continue;
            }
        }
		else{
			continue;
        }


	    printf("%s\n",sys_cmd);
        system(sys_cmd);
	}


#if 1
	if(timeinfo->tm_sec == 0)
	{	
		memset(sys_cmd,0,sizeof(sys_cmd));
		sprintf(sys_cmd,"/root/T3/up_down/show_ipv6_route.sh >> /var/log/quagga/route/%s.log",host_name); 
		system(sys_cmd);
	}
#endif

    
}
#endif
static int strsplit(char *string, int stringlen,
		char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		goto einval_error;

	for (i = 0; i < stringlen; i++)
	{   
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart)
		{   
			tokstart = 0;
			tokens[tok++] = &string[i];
		}   
		if (string[i] == delim)
		{   
			string[i] = '\0';
			tokstart = 1;
		}   
	}   
	return tok;

einval_error:
	return -1; 
}


int main(int argc ,char **argv)
{

	memset(if_list,0,sizeof(if_list));

	printf("this is %s\n",argv[1]);
	printf("id is %s\n",argv[2]);

	char cmd[128];
	char buf[150];
	char buf_ip[150];
	char *token;
	int nb_token;
	int i;
	int num = 0;
	char *str_fld[5];

	//sprintf(cmd,"cat /root/T3/up_down/set_time.txt | sed -n '%d,1p'",atoi(argv[2]));
	sprintf(cmd,"cat /root/T3/up_down/set_time.txt | grep %s",argv[1]);
	
	FILE *ptr = NULL;

	if((ptr = popen(cmd,"r"))==NULL)
	{
		printf("poenp error \n");
		return 0;	
	}

	memset(buf,0,sizeof(buf));

	if(fgets(buf,sizeof(buf),ptr)!= NULL)
	{

		pclose(ptr);
		//printf("buf :%s\n",buf);	
#if 1
		token = strtok(buf,"#");
		while(token!=NULL)
		{
			printf("token : %s\n",token);	
#if 1
			nb_token = strsplit(token, sizeof(buf), str_fld, 4, ' ');
			for (i = 0; i < nb_token; i++)
			{
				if (i == 0)
				{
					//printf("%s\n",str_fld[i]);
					strcpy(if_list[num].ifname, str_fld[i]);
					get_ifinterface_stats_ifindex(if_list[num].ifname,&if_list[num].stats,&if_list[num].ifindex);
					
				}
				else if (i == 1)
				{
					printf("%s\n",str_fld[i]);
					//if_list[num].up_time = atoi(str_fld[i]);
                    sscanf(str_fld[i],"%d:%d:%d",&if_list[num].up_time.tm_hour,&if_list[num].up_time.tm_min,&if_list[num].up_time.tm_sec);
				}
				else if (i == 2)
				{
					printf("%s\n",str_fld[i]);
					//if_list[num].down_time = atoi(str_fld[i]);
                    sscanf(str_fld[i],"%d:%d:%d",&if_list[num].down_time.tm_hour,&if_list[num].down_time.tm_min,&if_list[num].down_time.tm_sec);
				}else{
					printf("error\n");
				}

			}
#endif

			token = strtok(NULL,"#");
			num++;
		}
#endif


	}


	show_if_list();


    while(1)
    {
        check_loop(argv[1]);
        sleep(1);    
    }

	return 0;
}
