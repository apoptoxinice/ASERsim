#include<stdio.h>
#include<stdlib.h>
#include<string.h>

typedef unsigned char uint8_t;

typedef struct CronLine 
{
	char cl_Mins[60];	/* 0-59                                 */
	char cl_Hrs[24];	/* 0-23                                 */
	char cl_Days[32];	/* 0-31                                 */
	char cl_Mons[12];	/* 0-11                                 */
	char cl_Dow[7];		/* 0-6, beginning sunday                */
} CronLine;
static char *ParseField(char *user, char *ary, int modvalue, int off,const char *const *names, char *ptr);


//寻找满足crond条件的时间点
uint8_t GetWakeUpTimePoint(CronLine *pline,struct data_time_str *p_data)
{
		if((pline->cl_Mins[p_data->min] == 1)
						&& (pline->cl_Hrs[p_data->hour] == 1)
						&& (pline->cl_Days[p_data->day] == 1)
						&& (pline->cl_Mons[p_data->month] == 1)
						&& (pline->cl_Dow[p_data->week] == 1))
		{
				printf("%04d年%02d月%02d日  %02d:%02d:00   星期%d\r\n",
								p_data->year,p_data->month,p_data->day,
								p_data->hour,p_data->min,p_data->week);
				return 1;
		}
		return 0;
}

int main()
{
		CronLine line = {0};
		char *ptr;
		/*buf：Crontab表达式*/
		char buf[] = "0 0 1,20 * * "; //0 18 * * * //10 5 */5 * *
		ptr = ParseField("Mins", line.cl_Mins, 60, 0, NULL, buf);
		ptr = ParseField("Hrs", line.cl_Hrs, 24, 0, NULL, ptr);
		ptr = ParseField("Days", line.cl_Days, 32, 0, NULL, ptr);
		ptr = ParseField("Mons", line.cl_Mons, 12, -1, MonAry, ptr);
		ptr = ParseField("Week", line.cl_Dow, 7, 0, DowAry, ptr);
		if (ptr == NULL) 
		{
				printf("It's over\r\n");
		}

		/*
		   uint8_t min;
		   uint8_t hour;
		   uint8_t day;
		   uint8_t month;
		   uint16_t year;
		 */
		//先定义个时间初始值
		//struct data_time_str CalcDataTime = {34,9,30,8,2019,4}; 
		//获取当前时间
		SYSTEMTIME st;
		GetLocalTime(&st);
		struct data_time_str CalcDataTime = {0};
		CalcDataTime.year = st.wYear;
		CalcDataTime.month = st.wMonth;
		CalcDataTime.day = st.wDay;
		CalcDataTime.hour = st.wHour;
		CalcDataTime.min = st.wMinute;

		uint32_t cnt = 0; //做个循环限制 
		uint8_t getcnt = 0; //记录找到唤醒时间的次数 
		while((cnt < 0xFFFFFFFF) && (getcnt <= 10))
		{
				cnt++;
				UpdateTimeBuf(&CalcDataTime);
				if(GetWakeUpTimePoint(&line,&CalcDataTime))
				{
						getcnt++;
				}			
		}

		system("pause");
		return 0;
}

