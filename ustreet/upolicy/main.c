#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include "policy.h"

//#define TEST 1

int is_synced = 0;

#ifdef HOST
extern char *optarg; 

int init(int argc, char *argv[]) 
{ 
    char c; 
    //int i,optlen; 
    //int slashcnt; 
     i_host[0]  =  '\0'; 
     i_port[0]  =  '\0'; 
     while ((c = getopt(argc, argv, "h:p:?")) != EOF) { 
         if (c == '?') 
             return -1; 
         switch (c) {  
         case 'h': 
             if(!optarg)
			{
				printf("%s, %d...\n", __FUNCTION__, __LINE__);
				return -1;
 			}
             strcpy(i_host, optarg); 
             break; 
         case 'p': 
             if(!optarg)
			{
				printf("%s, %d...\n", __FUNCTION__, __LINE__);
				return -1;
 			}

             strcpy(i_port, optarg); 
             break; 
         default: 
			printf("%s, %d...\n", __FUNCTION__, __LINE__);
             return -1; 
         } 
     } 
     /*  
      * there is no default value for hostname, port number,  
      * password or uri 
      */ 
     if (i_host[0] == '\0' || i_port[0] == '\0') 
         return -1; 

     return 1; 
} 
#else
int init(int argc, char *argv[]) 
{ 
    char c; 

     i_host[0]  =  '\0'; 
     i_port[0]  =  '\0'; 

	if(argc != 5)
		return -1;

	if(strcmp(argv[1], "-h") == 0)
	{
             strcpy(i_host, argv[2]); 
	}
	else if(strcmp(argv[1], "-p") == 0)
	{
             strcpy(i_port, argv[2]); 
	}

	if(strcmp(argv[3], "-h") == 0)
	{
             strcpy(i_host, argv[4]); 
	}
	else if(strcmp(argv[3], "-p") == 0)
	{
             strcpy(i_port, argv[4]); 
	}
     return 1; 
} 
#endif 
void print_usage() 
{ 
    char *usage[] = 
    { 
        "Usage:", 
        "    -h    host name", 
        "    -p    port", 
         "example:", 
         "    -h 127.0.0.1 -p 4001", 
     };    
     int i; 
  
     for (i = 0; i < sizeof(usage) / sizeof(char*); i++) 
         printf("%s\n", usage[i]); 
      
     return; 
} 
int main(int argc, char **argv) 
{ 
	// init

	// connect to the management server

	// policy sync & ZigBee short Addr update

	// upgrade check

	// open ZigBee

	// policy execute
	
	// rcv_msg_thread: thread is used to poll the msg, parse, and handle them
	// register_thread: send register msg when the register is not ok
	// keep_conn_thread: connect the server automatically if the sock_fd is not accessed
	pthread_t rcv_msg_thread, wd_thread, register_thread, keep_conn_thread;
	// ctrl_policy_thread: execute the ctrl msg/policy
	pthread_t ctrl_policy_thread = 0;
	// usr_dft_policy_thread: execute the usr or default policy
	pthread_t usr_dft_policy_thread = 0;

	//pthread_cond_init(&zb_cond, NULL);
	//pthread_mutex_init(&zb_mutex, NULL);
#if 0
	struct sched_param param;

  	pthread_attr_t attr_rcv_msg;
	pthread_attr_t attr_wd;
	pthread_attr_t attr_register;
	pthread_attr_t attr_keep_conn;
	pthread_attr_t attr_ctrl_policy;
  	pthread_attr_t attr_usr_dft_policy;

	pthread_attr_init(&attr_wd);
  	pthread_attr_init(&attr_rcv_msg);
	pthread_attr_init(&attr_register);
	pthread_attr_init(&attr_keep_conn);
	pthread_attr_init(&attr_ctrl_policy);
	pthread_attr_init(&attr_usr_dft_policy);

  	param.sched_priority = 12;
 	pthread_attr_setschedpolicy(&attr_wd,SCHED_RR);
 	pthread_attr_setschedparam(&attr_wd,&param);
 	pthread_attr_setinheritsched(&attr_wd,PTHREAD_EXPLICIT_SCHED);//要使优先级其作用必须要有这句话

 	param.sched_priority = 11;
 	pthread_attr_setschedpolicy(&attr_rcv_msg,SCHED_RR);
 	pthread_attr_setschedparam(&attr_rcv_msg,&param);
 	pthread_attr_setinheritsched(&attr_rcv_msg,PTHREAD_EXPLICIT_SCHED);
 
 	param.sched_priority = 10;
 	pthread_attr_setschedpolicy(&attr_ctrl_policy,SCHED_RR);
 	pthread_attr_setschedparam(&attr_ctrl_policy,&param);
 	pthread_attr_setinheritsched(&attr_ctrl_policy,PTHREAD_EXPLICIT_SCHED);

 	param.sched_priority = 6;
 	pthread_attr_setschedpolicy(&attr_register,SCHED_RR);
 	pthread_attr_setschedparam(&attr_register,&param);
 	pthread_attr_setinheritsched(&attr_register,PTHREAD_EXPLICIT_SCHED);

 	param.sched_priority = 5;
 	pthread_attr_setschedpolicy(&attr_usr_dft_policy,SCHED_RR);
 	pthread_attr_setschedparam(&attr_usr_dft_policy,&param);
 	pthread_attr_setinheritsched(&attr_usr_dft_policy,PTHREAD_EXPLICIT_SCHED);

 	param.sched_priority = 15;
 	pthread_attr_setschedpolicy(&attr_keep_conn,SCHED_RR);
 	pthread_attr_setschedparam(&attr_keep_conn,&param);
 	pthread_attr_setinheritsched(&attr_keep_conn,PTHREAD_EXPLICIT_SCHED);
#endif
    	int retries = 5;
	int ret = 0;

    	time_t now;
    	struct tm tm_now;
	int cur_date = 0;
	int cur_min = 0;
	
	int is_alarmed = 0;
	int is_sync_status = 0;

	/* parse command line etc ... */ 
	if (init(argc, argv) < 0) 
		{ 
		print_usage(); 
		exit(1); 
	} 
  
	// init the default value
	g_control_id = 0x1010;
	g_sync_policy_hh = 12;
	g_sync_policy_mm = 0;

	read_ustreet_conf();

    init_mul_timer();
	init_crc32_table();

	time(&now);
	localtime_r(&now, &tm_now);

	signal(SIGPIPE,SIG_IGN);
	signal(SIGCHLD,SIG_IGN);

	/*
#ifndef TEST
	extern void init_zigbee_conn(void);

	init_zigbee_conn();
#endif
	*/
	cur_date = tm_now.tm_mday;

	PRINTF("%s, begin read default policy..., yday = %d\n", __FUNCTION__, tm_now.tm_yday);
	read_def_policy(tm_now.tm_yday);


	// create & start the keep connection thread
    if (pthread_create(&keep_conn_thread, NULL, keep_connection, NULL) != 0) 
	{
		printf("failed to create thread feeddog\n");
		return (-1);
    }


    /* make connection to the server */ 
    sock_fd = tcp_connect(i_host, (unsigned short)atoi(i_port)); 
    PRINTF("sock_fd = %d\n", sock_fd);

    //unregister_control_point(g_control_id);
    //sync_policy_from_server(g_control_id);
    //send_alarm_to_server(g_control_id, "abcd", 2);
    //send_light_status_to_server(g_control_id, "abcd", 1);

	// create & start the recv msg thread
    if (pthread_create(&rcv_msg_thread, NULL, thread_state_machine, NULL) != 0) {
		printf("failed to create thread recv packets\n");
		return (-1);
    }
#ifdef RELEASE
    if (pthread_create(&wd_thread, NULL, thread_feed_watchdog, NULL) != 0) {
		printf("failed to create thread watchdog\n");
		return (-1);
    }
#endif
	current_status = LC_STATUS_OFFLINE;
	g_cur_policy_type = POLICY_TYPE_DFT;

	if (pthread_create(&register_thread, NULL, thread_register_main, NULL) != 0) 
	{
		printf("failed to create thread register\n");
		return (-1);
	}
	PRINTF("%s, %d: tid = %x\n", __FUNCTION__, __LINE__, register_thread);

	if (pthread_create(&ctrl_policy_thread, NULL, execute_ctrl_policy, NULL) != 0) {
		printf("failed to create thread ctrl_policy\n");
	}
	// will handle following tasks:
	// register
	// execute the ctrl/usr/dft policy
	while(1)
	{
		time(&now);
		localtime_r(&now, &tm_now);

		if((cur_date != tm_now.tm_mday) && tm_now.tm_hour == g_sync_policy_hh && tm_now.tm_min == g_sync_policy_mm)
		{
			cur_date = tm_now.tm_mday;

			PRINTF("%s, begin read default policy..., yday = %d\n", __FUNCTION__, tm_now.tm_yday);
			read_def_policy(tm_now.tm_yday);
		}
		if(sock_fd != -1)
		{	
			sleep(1);
			// sync_policy_from_server(g_control_id);

			//break;
	
			if(current_status == LC_STATUS_ONLINE || current_status == LC_STATUS_REGOK || current_status == LC_STATUS_SYNCOK)
			{
				time(&now);
				localtime_r(&now, &tm_now);
			
				//PRINTF("=========cur_date = %d, now datetime: %s===========\n", cur_date, asctime(tm_now));
				if(((cur_date != tm_now.tm_mday) && tm_now.tm_hour == g_sync_policy_hh && tm_now.tm_min == g_sync_policy_mm) || is_synced == 0)
				{
					is_synced = 1;

					PRINTF("%s, begin sync policy, g_control_id = 0x%x, cur_date = %d, [%02d]...\n", __FUNCTION__, g_control_id, cur_date, tm_now.tm_yday);

					read_def_policy(tm_now.tm_yday);

					cur_date = tm_now.tm_mday;
	
					sync_policy_from_server(g_control_id, tm_now.tm_yday);
					
				}

				if((((tm_now.tm_min % 1) == 0) && (cur_min != tm_now.tm_min)) || is_alarmed == 0)
				{
					is_alarmed = 1;
					update_light_status(g_control_id, LIGHT_STATE_UNKNOWN);
				}
				if((((tm_now.tm_min % 2) == 0) && (cur_min != tm_now.tm_min)) || is_sync_status == 0)
				{
					is_sync_status = 1;

					update_light_status(g_control_id, LIGHT_STATE_ON);
				}
				cur_min = tm_now.tm_min;

			}
			else
			{
				retries--;
			}

		}
		if(usr_dft_policy_thread == 0)
		{
			if (pthread_create(&usr_dft_policy_thread, NULL, execute_policy, NULL) != 0) {
					printf("failed to create thread usr_dft_policy\n");
			}
		}
	}
    return 0; 
} 

