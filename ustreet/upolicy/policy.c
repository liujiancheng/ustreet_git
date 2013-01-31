#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

#include <errno.h> 
#include <fcntl.h> 
#include <time.h>

#include "policy.h"
#include "util.h"
#include "mul_timer.h"

#define DEBUG	1

pthread_mutex_t g_policy_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_light_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_is_switching;

extern pthread_mutex_t g_sockfd_mutex;
extern int is_synced;

// temp policy, highest prioty 
LIST_HEAD(g_ctrl_policy_list);
LIST_HEAD(g_ctrl_light_list);

// usr policy, it will be updated daily, 12:00 sync from data server
LIST_HEAD(g_usr_policy_list);
LIST_HEAD(g_usr_light_list);

// default policy, save in the flash, update the memory from flash daily, at 12:00.
LIST_HEAD(g_dft_policy_list);
LIST_HEAD(g_dft_light_list);

void print_usage(void); 

//extern int turn_on_light(unsigned short light_addr);
//extern int turn_off_light(unsigned short light_addr);
extern int turn_on_all_light(void);
extern int turn_off_all_light(void);
static void remove_light_from_ctrl_list(node_mac_addr_T *node_addr);

void switch_to_usr_policy()
{
	g_is_switching = 1;
}
void clear_switch_flag()
{
	g_is_switching = 0;
}

int is_switching_to_usr_policy()
{
	if(g_is_switching == 1)
		return 1;
	return 0;
}


int sync_policy_from_server(unsigned short control_id, unsigned short yday)
{
	int data_len = 0;
	int snd_len = 0;

	struct msg_header_T sync_msg_hdr;
	struct msg_sync_policy_T sync_msg;
	
	memset(&sync_msg_hdr, 0, sizeof(struct msg_header_T));
	memset(&sync_msg, 0, sizeof(struct msg_sync_policy_T));

	sync_msg.control_id = control_id;
	sync_msg.yday = yday;

	sync_msg_hdr.msg_type = LC_POLICY_SYNC_ALL;
	sync_msg_hdr.msg_len = sizeof(struct msg_sync_policy_T);
	
	memcpy(sync_msg_hdr.msg_data, &sync_msg, sizeof(struct msg_sync_policy_T));
	
	// send msg to server
	data_len = 8;

	sync_msg_hdr.crc32 = msg_crc_generateCRC32(&sync_msg_hdr);
	data_len += 4;

	snd_len = send_data_to_server((char *)&sync_msg_hdr, data_len);
	PRINTF("[SYNC_POLICY]: %s, %d, [%d],snd_len = %d,...\n", __FUNCTION__, __LINE__, yday, snd_len);
	
	return snd_len;
}

void flush_policy(enum policy_type_e policy_type)
{
	int pos = 0;
	struct list_head *lpos,*n, *p, *pTypeList;
	msg_policy_T *pPolicy, *tmp_policy;

	time_t cur_time;
    
    	cur_time = time(NULL);

	pthread_mutex_lock(&g_policy_mutex);

	// make the decision that which policy list will be used.
	if(policy_type == POLICY_TYPE_CTRL)
	{
		g_cur_policy_type = POLICY_TYPE_USR;
		pTypeList = &g_ctrl_policy_list;
	}
	else if(policy_type == POLICY_TYPE_USR)
	{
		pTypeList = &g_usr_policy_list;
	}
	else if(policy_type == POLICY_TYPE_DFT)
	{
		pTypeList = &g_dft_policy_list;
	}

	// flush the list
	list_for_each_safe(lpos, n, pTypeList)
	{
		tmp_policy = list_entry(lpos, msg_policy_T, list);

		//if(cur_time > tmp_policy->stop_time)
		if(1)
		{
			//printf("[FREE] %s, node_addrs 0x%x\n", __FUNCTION__, tmp_policy->node_addrs);
			//printf("[FREE] %s 0x%x\n", __FUNCTION__, tmp_policy);
			remove_light_from_ctrl_list(tmp_policy->node_addrs);

			free(tmp_policy->node_addrs);
			free(tmp_policy);

			list_del(lpos);
		}
	}
	// unlock the g_usr_policy_list
	pthread_mutex_unlock(&g_policy_mutex);
}
static int current_has_usr_policy(void)
{
	int pos = 0;
	struct list_head *lpos,*n, *p, *pTypeList;
	msg_policy_T *pPolicy, *tmp_policy;

	time_t cur_time;
    
    	cur_time = time(NULL);

	pthread_mutex_lock(&g_policy_mutex);

	// make the decision that which policy list will be used.
	pTypeList = &g_usr_policy_list;

	// flush the list
	list_for_each_safe(lpos, n, pTypeList)
	{
		tmp_policy = list_entry(lpos, msg_policy_T, list);

		if(cur_time >= tmp_policy->start_time && cur_time <= tmp_policy->stop_time)
		{
			// unlock the g_usr_policy_list
			pthread_mutex_unlock(&g_policy_mutex);
			return 1;
		}
	}
	// unlock the g_usr_policy_list
	pthread_mutex_unlock(&g_policy_mutex);
	return 0;
}

void remove_policy_from_ctrl_list(msg_policy_T *pPolicy)
{
	int pos = 0;
	struct list_head *lpos,*n, *p, *pTypeList;
	msg_policy_T *tmp_policy;

	time_t cur_time;
    
    	cur_time = time(NULL);

	pthread_mutex_lock(&g_policy_mutex);

	pTypeList = &g_ctrl_policy_list;

	// flush the list
	list_for_each_safe(lpos, n, pTypeList)
	{
		tmp_policy = list_entry(lpos, msg_policy_T, list);

		if(pPolicy == tmp_policy)
		{
			//printf("[FREE] %s, node_addrs 0x%x\n", __FUNCTION__, tmp_policy->node_addrs);
			//printf("[FREE] %s 0x%x\n", __FUNCTION__, tmp_policy);
			free(tmp_policy->node_addrs);
			free(tmp_policy);

			list_del(lpos);
		}
	}
	// unlock the g_usr_policy_list
	pthread_mutex_unlock(&g_policy_mutex);
}

// temp, usr, default policy has identical format, it can be parsed in this function. 
int parse_policy(enum policy_type_e policy_type, unsigned char *rcv_data, int rcv_len)
{
	msg_policy_T *pPolicy, *tmp_policy;
	unsigned short light_num, light_state;

	int pos = 0;
	struct list_head *lpos,*n, *p, *pTypeList;
	short count = 0;

	int i = 0;

	// sanity check
	if(!rcv_data || rcv_len <= 0)
		return 0;

	// flush the list
	if(policy_type != POLICY_TYPE_CTRL)
		flush_policy(policy_type);


	pthread_mutex_lock(&g_policy_mutex);

	// make the decision that which policy list will be used.
	if(policy_type == POLICY_TYPE_CTRL)
	{
		pTypeList = &g_ctrl_policy_list;
	}
	else if(policy_type == POLICY_TYPE_USR)
	{
		pTypeList = &g_usr_policy_list;
	}
	else if(policy_type == POLICY_TYPE_DFT)
	{
		pTypeList = &g_dft_policy_list;
	}
#ifdef DEBUG
	for(i = 0; i < rcv_len; i++)
	{
		PRINTF("%02x ", rcv_data[i]);
		if(i%16 == 0 && (i!=0))
			PRINTF("\n");
	}
#endif
	// lock the g_usr_policy_list

	/*
	list_for_each_safe(lpos, n, pTypeList)
	{
		tmp_policy = list_entry(lpos, msg_policy_T, list);

		free(tmp_policy->light_addr);
		free(tmp_policy);

		list_del(lpos);
	}
	*/
	while(pos < rcv_len)
	{
#ifdef DEBUG
		PRINTF("\n============ pos = %d===========\n", pos);

		for(i = pos; i < pos + 16; i++)
		{
			PRINTF("%02x ", rcv_data[i]);
		}
		PRINTF("\n");
#endif
		pPolicy = (msg_policy_T *)malloc(sizeof(msg_policy_T));
		if(!pPolicy)
		{
			printf("policy malloc memory error!\n");
			count = 0;
			break;
		}
		//printf("[MALLOC] %s: 0x%x\n", __FUNCTION__, pPolicy);
		// light_num
		light_num = rcv_data[pos] | (rcv_data[pos+1] << 8);

		printf("%s: light_num = %d\n", __FUNCTION__, light_num);
		// normal behavior, 1 - 256 lights, 0xFFFF all of lights
 		if((light_num == 0  || light_num > MAX_LIGHT_NUM) && light_num != 0xFFFF)
		{
			printf("[PARSE_POLICY]: policy has error!\n");
			count = 0;
			break;
		}
		pPolicy->light_num = light_num;
		pos += 2;

		// light_state
		light_state = rcv_data[pos] | (rcv_data[pos+1] << 8);
		pPolicy->light_state = light_state;
		pos += 2;

		printf("%s: light_state = %d\n", __FUNCTION__, light_state);

		// start_time
		memcpy(&(pPolicy->start_time), (rcv_data + pos), sizeof(time_t));
		pos += sizeof(time_t);
		printf("%s: start_time = 0x%x\n", __FUNCTION__, pPolicy->start_time);

		// stop_time
		memcpy(&(pPolicy->stop_time), (rcv_data + pos), sizeof(time_t));
		pos += sizeof(time_t);
		printf("%s: stop_time = 0x%x\n", __FUNCTION__, pPolicy->stop_time);

		// light_addr
		// All of lights
		if(light_num >= 1)
		{
			pPolicy->node_addrs = (node_mac_addr_T *)malloc(light_num * sizeof(node_mac_addr_T));
			memcpy(pPolicy->node_addrs, (rcv_data + pos), (light_num * sizeof(node_mac_addr_T)));
			pos += (light_num * sizeof(node_mac_addr_T));

			//printf("[MALLOC] %s: node_addrs 0x%x\n", __FUNCTION__, pPolicy->node_addrs);

			printf("%s: mac_addrs = 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", __FUNCTION__, pPolicy->node_addrs[0].mac_addr[0],pPolicy->node_addrs[0].mac_addr[1],pPolicy->node_addrs[0].mac_addr[2],pPolicy->node_addrs[0].mac_addr[3],pPolicy->node_addrs[0].mac_addr[4], pPolicy->node_addrs[0].mac_addr[5],pPolicy->node_addrs[0].mac_addr[6],pPolicy->node_addrs[0].mac_addr[7]);

			memcpy(pPolicy->light_ids, (rcv_data + pos), (light_num));
			pos += (light_num * 1);
		}

		// next policy
		list_add_tail(&pPolicy->list, pTypeList);
		//cur_pos += pos;
		count++;
	}
#if 0 //def DEBUG
	list_for_each(p, pTypeList)
	{
		tmp_policy = list_entry(p, msg_policy_T, list);
		i++;
	}
	PRINTF("i = %d\n", i);

#endif
	// unlock the g_usr_policy_list
	pthread_mutex_unlock(&g_policy_mutex);

	// update the light state
	update_policy_per_light(policy_type);

	if(policy_type == POLICY_TYPE_USR && count != 0)
	{
		current_status = LC_STATUS_SYNCOK;
	}

	return count;

}

void thread_feed_watchdog(void)
{
	while(1)
	{
		system("echo 1 > /dev/watchdog");
		sleep(1);
	}
}
/*
1) register ok
2) sync policy from server
   online
3) execute the policy
*/
void thread_state_machine(void)
{
	int rcv_len = 0;
	struct msg_header_T msg;
	int count = 0;

	time_t cur_time;
	struct tm local_time;
	static int tm_sec = 0;
	int i = 0;
	char *pMsg;
	pthread_cond_t cond;
	pthread_mutex_t mutex;

	pthread_cond_init(&cond, NULL);
	pthread_mutex_init(&mutex, NULL);

	while(1)
	{
		cur_time = time(NULL);
		localtime_r(&cur_time,&local_time);
		//system("echo 1 > /dev/watchdog");

		//printf("%s...\n", __FUNCTION__);
		if(sock_fd != -1)
		{
			rcv_len = recv_data_from_server((char *)&msg, sizeof(msg));
			//printf("%s, rcv_len = %d... errno = %d, tm_sec = %d\n", __FUNCTION__, rcv_len, errno, local_time.tm_sec);
	
			if(rcv_len == -1 || rcv_len == 0)
			{
				if(local_time.tm_sec % 10 == 0)
				{
					pthread_mutex_lock(&g_sockfd_mutex);
					// reconnect it
					sock_fd = tcp_connect(i_host, (unsigned short)atoi(i_port));
			
					// printf("error: %s\n",strerror(errno));
	
					PRINTF("[RECONNECT]: %s, %d, sock_fd = %d, tm_sec = %d\r\n", __FUNCTION__, __LINE__, sock_fd, local_time.tm_sec);
				
	
					pthread_mutex_unlock(&g_sockfd_mutex);
					sleep(1);
				}
				
				//current_status = LC_STATUS_OFFLINE;
				//g_cur_policy_type = POLICY_TYPE_DFT;
				continue;
			}
			else if(rcv_len == SOCKET_NO_DATA)
			{
				//sleep(1);
				usleep(10000);
				continue;
			}
			PRINTF("[POLICY]: rcv_len = %d, msg_type = %d, msg_len = %d\r\n",
				rcv_len, msg.msg_type, msg.msg_len);

			pMsg = (char *)&msg;

			for(i = 0; i < rcv_len; i++)
			{
				PRINTF("%02x ", pMsg[i] & 0xFF);
				if(i%16 == 0 && (i!=0))
					PRINTF("\n");
			}
			if(is_crc_correct(&msg) == CRC_ERROR)
			{
				printf("\n[POLICY] CRC check error\n");
				continue;
			}
			else
			{
			}
	
			switch(msg.msg_type)
			{
			case LC_REG_OK:
				PRINTF("[LC_REG_OK]: %s\n", __FUNCTION__);
				current_status = LC_STATUS_REGOK;
				break;
			case LC_REG_NOK:
				current_status = LC_STATUS_OFFLINE;
				g_cur_policy_type = POLICY_TYPE_DFT;
				break;
			case LC_UNREG_OK:
				current_status = LC_STATUS_OFFLINE;
				g_cur_policy_type = POLICY_TYPE_DFT;
				break;
			case LC_UNREG_NOK:
				current_status = LC_STATUS_OFFLINE;
				g_cur_policy_type = POLICY_TYPE_DFT;
				break;
			case LC_POLICY_SYNC_ALL_OK:
			{
				PRINTF("LC_POLICY_SYNC_ALL_OK...\n");

				if(g_cur_policy_type == POLICY_TYPE_DFT)
					switch_to_usr_policy();

				count = parse_policy(POLICY_TYPE_USR, msg.msg_data, rcv_len - 8);
				if(count == 0)
				{
					printf("[LC_POLICY_SYNC_ALL_OK]: %s, parse_policy error!\n", __FUNCTION__);
				}
				break;
			}
			case LC_POLICY_SYNC_ALL_NOK:
				PRINTF("LC_POLICY_SYNC_ALL_NOK...\n");
				current_status = LC_STATUS_SYNCNOK;
				g_cur_policy_type = POLICY_TYPE_DFT;
				break;
			case LC_ALARM_RES:
				current_status = LC_ALARM_RES;
				break;
			case POLICY_MSG_ALL_ON_OFF:
			case POLICY_MSG_SOME_ON_OFF:
			{
				PRINTF("POLICY_MSG_SOME_ON_OFF....\n");
				count = parse_policy(POLICY_TYPE_CTRL, msg.msg_data, rcv_len - 8);
				if(count == 0)
				{
					printf("[POLICY_MSG_ALL_ON_OFF]: %s, parse_policy error!\n", __FUNCTION__);
				}
				else
				{
					g_cur_policy_type = POLICY_TYPE_CTRL;
				}
				break;
			}
			case POLICY_MSG_CLEAR_CTRL_POLICY:
			{
				PRINTF("POLICY_MSG_CLEAR_CTRL_POLICY....\n");

				flush_policy(POLICY_TYPE_CTRL);
				//g_cur_policy_type = POLICY_TYPE_USR;
				break;
			}

			case POLICY_MSG_GET_STATUS:
				break;
			default:
				printf("%s, %d: msg.msg_type = 0x%x, error\n", __FUNCTION__, __LINE__, msg.msg_type);		
			}
		}
		else
		{
			struct timeval now;
			struct timespec outtime;
  			
			pthread_mutex_lock(&mutex);
#if 1
			if(current_has_usr_policy() == 0)
			{
				g_cur_policy_type = POLICY_TYPE_DFT;
				current_status = LC_STATUS_OFFLINE;
				is_synced = 0;
			}

			//sleep(10);
			//PRINTF("%s, %d...\n", __FUNCTION__, __LINE__);
			//if(local_time.tm_sec % 10 == 0 && (tm_sec != local_time.tm_sec))
			{
				pthread_mutex_lock(&g_sockfd_mutex);
				// reconnect it
				sock_fd = tcp_connect(i_host, (unsigned short)atoi(i_port));
	
				PRINTF("[RECONNECT]: %s, %d, sock_fd = %d, tm_sec = %d\r\n", __FUNCTION__, __LINE__, sock_fd, local_time.tm_sec);
				pthread_mutex_unlock(&g_sockfd_mutex);
				tm_sec = local_time.tm_sec;
				//sleep(1);
			}
			gettimeofday(&now, NULL);
			outtime.tv_sec = now.tv_sec + 10; // RECONNECT_FREQUENCY;

			pthread_cond_timedwait(&cond, &mutex, &outtime);
			pthread_mutex_unlock(&mutex);

			continue;
#else
			if(is_reconnecting != 1)
			{
				is_reconnecting = 1;
			}
#endif
		}
	}
}

int policy_to_light_node(struct list_head *pLightList, msg_policy_T *pPolicy)
{
	int light_num = 0, light_idx = 0;
	light_node_T *pLight;

	//PRINTF("%s, %d...\n", __FUNCTION__, __LINE__);
	if(!pLightList || !pPolicy || !pPolicy->node_addrs)
		return 0;

	light_num = pPolicy->light_num;

	//PRINTF("%s, %d, light_num = %d...\n", __FUNCTION__, __LINE__, light_num);

	for(light_idx = 0; light_idx < light_num; light_idx++)
	{
		pLight= (light_node_T *)malloc(sizeof(light_node_T));
		if(!pLight)
		{
			printf("light node malloc memory error!\n");
			break;
		}
		//printf("[MALLOC] %s: 0x%x\n", __FUNCTION__, pLight);
		pLight->node_idx = light_idx;
		memcpy(&pLight->node_addr, &pPolicy->node_addrs[light_idx], sizeof(node_mac_addr_T));
		pLight->pPolicy = pPolicy;

    		PRINTF("%s, %d, idx = %d, light_addr = 0x%02x %02x %02x %02x %02x %02x %02x %02x...\n", __FUNCTION__, __LINE__, pLight->node_idx, pLight->node_addr.mac_addr[0], pLight->node_addr.mac_addr[1], pLight->node_addr.mac_addr[2], pLight->node_addr.mac_addr[3], pLight->node_addr.mac_addr[4], pLight->node_addr.mac_addr[5], pLight->node_addr.mac_addr[6], pLight->node_addr.mac_addr[7]);

		list_add_tail(&pLight->list,pLightList);
	}
	return light_num;
}
int update_policy_per_light(enum policy_type_e policy_type)
{
	msg_policy_T *pPolicy;
	light_node_T *pLight;

	struct list_head *p, *lpos, *n;
	struct list_head *pPolicyList, *pLightList;

	pthread_mutex_lock(&g_policy_mutex);
	pthread_mutex_lock(&g_light_mutex);

	if(policy_type == POLICY_TYPE_CTRL)
	{
		pPolicyList = &g_ctrl_policy_list;
		pLightList = &g_ctrl_light_list;
	}
	else if(policy_type == POLICY_TYPE_USR)
	{
		pPolicyList = &g_usr_policy_list;
		pLightList = &g_usr_light_list;
	}
	else if(policy_type == POLICY_TYPE_DFT)
	{
		pPolicyList = &g_dft_policy_list;
		pLightList = &g_dft_light_list;
	}
	// lock light_list

	// flush the list
	list_for_each_safe(lpos, n, pLightList)
	{
		pLight = list_entry(lpos, light_node_T, list);
		//printf("[FREE] %s: 0x%x\n", __FUNCTION__, pLight);

		free(pLight);
		list_del(lpos);
	}
	// lock policy list
	list_for_each(p, pPolicyList)
	{
		pPolicy = list_entry(p, msg_policy_T, list);

		// go through the light list
		policy_to_light_node(pLightList, pPolicy);
	}
	// unlock policy list
	// unlock light list
	pthread_mutex_unlock(&g_light_mutex);
	pthread_mutex_unlock(&g_policy_mutex);

	return 0;
}

void dump_policy_list(struct list_head *pTypeList)
{
#ifdef DEBUG
	struct list_head *p;
	msg_policy_T *pPolicy;
	char s_time[256], e_time[256];

	// lock policy list
	list_for_each(p, pTypeList)
	{
		pPolicy = list_entry(p, msg_policy_T, list);

		if(pPolicy != NULL)
		{
			strcpy(s_time, ctime(&pPolicy->start_time));
			strcpy(e_time, ctime(&pPolicy->stop_time));
	
			printf("[DUMP]: light_num = %d, light_state = %d, start_time = %s, stop_time = %s\n", pPolicy->light_num, pPolicy->light_state, s_time, e_time);
			// go through the light list
			//policy_to_light_node(pLightList, pPolicy);
		}
	}
	printf("%s...\r\n", __FUNCTION__);

#endif
}
void dump_light_list(struct list_head *pLightList)
{
#ifdef DEBUG
	struct list_head *p;
	light_node_T *pLight;
	msg_policy_T *pPolicy;
	char s_time[256], e_time[256];

	// lock policy list
	list_for_each(p, pLightList)
	{
		pLight = list_entry(p, struct _light_node_T, list);
		if(!pLight)
		{
			break;
		}
		if(!(pLight->pPolicy))
		{
			break;
		}
		pPolicy = pLight->pPolicy;
		strcpy(s_time, ctime(&pPolicy->start_time));
		strcpy(e_time, ctime(&pPolicy->stop_time));

		PRINTF("[DUMP]: ID = %d, Addr = 0x%04x, start_time = %s, stop_time = %s\n", pLight->node_idx, pLight->node_addr, s_time, e_time);
	}

#endif
}

static void get_format_time(char *tstr)
{
    time_t t;
    
    t = time(NULL);
    strcpy(tstr, ctime(&t));
    tstr[strlen(tstr)-1] = '\0';
    
    return;
}
static void get_hh_mm_ss_str(time_t *time_val, char *time_str)
{
	struct tm time_local;
	
	localtime_r(time_val, &time_local);
	sprintf(time_str, "%02d:%02d:%02d", time_local.tm_hour, time_local.tm_min, time_local.tm_sec);
	
	return;
}
static void remove_light_from_ctrl_list(node_mac_addr_T *node_addr)
{
	struct list_head *lpos,*n;
	light_node_T *pLight;

	PRINTF("[CTRL]: %s, %d...\n", __FUNCTION__, __LINE__);
	// flush the list
	list_for_each_safe(lpos, n, &g_ctrl_light_list)
	{
		pLight = list_entry(lpos, light_node_T, list);

		if(memcmp(&pLight->node_addr, node_addr, sizeof(node_mac_addr_T)) == 0)
			free(pLight);

		list_del(lpos);
	}
}
static int search_light_in_ctrl_list(node_mac_addr_T *node_addr)
{
	struct list_head *p;
	light_node_T *pLight;

	// needn't lock the g_ctrl_light_list
	list_for_each(p, &g_ctrl_light_list)
	{
		pLight = list_entry(p, light_node_T, list);
		if(pLight != NULL)
		{
			if(memcmp(&pLight->node_addr, node_addr, sizeof(node_mac_addr_T)) == 0) //  || pLight->light_addr == 0xFFFF)
			{
				return LIGHT_IS_CTRL_BY_TEMP;
			}
		}
	}
	return LIGHT_IS_CTRL_BY_USR;
}

void execute_ctrl_policy()
{
	// create a thread, 5 or 10 seconds, poll the start_time/stop_time, take action to on/off the light
	struct list_head *p;
	light_node_T *pLight;
	msg_policy_T *pPolicy;
	char c_time[256], s_time[256], e_time[256];


	time_t cur_time;

#ifdef DEBUG
	char tstr[200];

    	get_format_time(tstr);

    	PRINTF("[CTRL]: %s, execute_ctrl_policy is here.\n", tstr);
#endif

	g_cur_policy_type = POLICY_TYPE_CTRL;

	while(1)
	{
		cur_time = time(NULL);
	
		// lock the g_ctrl_light_list
		pthread_mutex_lock(&g_light_mutex);
		list_for_each(p, &g_ctrl_light_list)
		{
			pLight = list_entry(p, light_node_T, list);
			if(pLight != NULL)
			{
				pPolicy = pLight->pPolicy;
				cur_time = time(NULL);

				get_hh_mm_ss_str(&cur_time, c_time);
				strcpy(s_time, ctime(&pPolicy->start_time));
				strcpy(e_time, ctime(&pPolicy->stop_time));

				//PRINTF("[CTRL] ID:%d, Addr:0x%04x, state:%d --> %d, time: 0x%x --> 0x%x\n", pLight->light_idx, pLight->light_addr, pLight->light_cur_state, pPolicy->light_state, pPolicy->start_time, pPolicy->stop_time);
				PRINTF("[CTRL] ID:%d, [%02x%02x%02x%02x], state:%d --> %d, cur_time = %s, time: %s --> %s\n", pLight->node_idx, pLight->node_addr.mac_addr[0], pLight->node_addr.mac_addr[1], pLight->node_addr.mac_addr[2], pLight->node_addr.mac_addr[3],pLight->light_cur_state, pPolicy->light_state, c_time, s_time, e_time); 
	
				if( (cur_time >= pPolicy->start_time) &&
				(cur_time < pPolicy->stop_time))
				{
					//if(pLight->light_cur_state != pPolicy->light_state)
					if(1)
					{
						//break;
						// light on or off 
						PRINTF("[CTRL] ID:%d, %s\n", pLight->node_idx, (pPolicy->light_state == LIGHT_STATE_ON)? "Turn on":"Turn off");
		
						pLight->light_cur_state = pPolicy->light_state;
						// send cmd to zigbee node
						// all of lights will be turn on or off
						if(memcmp(&pLight->node_addr, "fffff", sizeof(node_mac_addr_T)) == 0)
						{
							PRINTF("[CTRL]: All of lights will be %s\n", (pPolicy->light_state == LIGHT_STATE_ON)? "Turn on":"Turn off");

							if(pPolicy->light_state == LIGHT_STATE_ON)
							{
								turn_on_all_light();
							}
							else
							{
								turn_off_all_light();
							}
						}
						else
						{
							if(pPolicy->light_state == LIGHT_STATE_ON)
							{
								turn_on_one_light(1, &pLight->node_addr);
							}
							else
							{
								turn_off_one_light(1, &pLight->node_addr);
							}
							// remove_light_from_ctrl_list(pLight->light_addr);
							// restore to dft or usr_policy
						}
					}
					else
					{
						//PRINTF("[CTRL] ID:%d, Addr = 0x%04x: %s\n", pLight->node_idx, pLight->node_addr, (pPolicy->light_state == LIGHT_STATE_ON)? "Is on":"Is off");
					}
				}
				else if(cur_time >= pPolicy->stop_time)
				{
					if(pLight->light_cur_state == pPolicy->light_state)
					{
						// light on or off 
						//PRINTF("[CTRL] ID:%d, Addr = 0x%x: %s\n", pLight->node_idx, pLight->node_addr, (pPolicy->light_state == LIGHT_STATE_ON)? "Please Turn off":"Turn on");
	
						pLight->light_cur_state = (pPolicy->light_state == LIGHT_STATE_ON)? LIGHT_STATE_OFF:LIGHT_STATE_ON;
						// send cmd to zigbee node
						if(pPolicy->light_state == LIGHT_STATE_ON)
							turn_off_one_light(1, &pLight->node_addr);
						else
							turn_on_one_light(1, &pLight->node_addr);
						PRINTF("[CTRL]: %s, remove from light ctrl list.\n", __FUNCTION__);
						// remove_light_from_ctrl_list(&pLight->node_addr);
						// remove policy from ctrl policy list
						remove_policy_from_ctrl_list(pPolicy);
						// restore to dft or usr_policy
					}
					//PRINTF("[CTRL]: %s, ctrl policy is timeout.\n", __FUNCTION__);
				}

			}
		}
		// unlock the g_ctrl_light_list
		pthread_mutex_unlock(&g_light_mutex);
		sleep(1);
	}
}

void do_execute_policy(enum policy_type_e policy_type)
{
	// create a thread, 5 or 10 seconds, poll the start_time/stop_time, take action to on/off the light
	struct list_head *p;
	light_node_T *pLight;
	struct list_head *pTypeList;
	msg_policy_T *pPolicy;
	char c_time[256], s_time[256], e_time[256];
	unsigned short real_state;
	char mac_addr[8];

	time_t cur_time;

#ifdef  DEBUG
	char tstr[200];

    	get_format_time(tstr);

    	PRINTF("%s: execute [%s] policy is here.\n", tstr, (policy_type == POLICY_TYPE_USR)?"USR":"DFT");
#endif
	cur_time = time(NULL);

	pthread_mutex_lock(&g_policy_mutex);

	// make the decision that which policy list will be used.
	if(policy_type == POLICY_TYPE_USR)
	{
		pTypeList = &g_usr_light_list;
	}
	else if(policy_type == POLICY_TYPE_DFT)
	{
		pTypeList = &g_dft_light_list;
	}
	else
	{
		return;
	}
	g_cur_policy_type = policy_type;

	//PRINTF("%s, %d...\n", __FUNCTION__, __LINE__);
	// lock the g_usr_light_list
	pthread_mutex_lock(&g_light_mutex);
	//del_a_timer(tm_hdlr[1]);

	list_for_each(p, pTypeList)
	{
		//PRINTF("%s, %d...\n", __FUNCTION__, __LINE__);
		//reset_zigbee();

		pLight = list_entry(p, light_node_T, list);
		if(pLight != NULL)
		{
			pPolicy = pLight->pPolicy;
			cur_time = time(NULL);

			if(is_switching_to_usr_policy())
			{
				clear_switch_flag();
				break;
			}
			get_hh_mm_ss_str(&cur_time, c_time);
			get_hh_mm_ss_str(&pPolicy->start_time, s_time);
			get_hh_mm_ss_str(&pPolicy->stop_time, e_time);
			//PRINTF("%s, %d, start_time = 0x%x, stop_time = 0x%x...\n", __FUNCTION__, __LINE__, pPolicy->start_time, pPolicy->stop_time);
			
			// check if this light is being controlled by administrator or temp
			if(search_light_in_ctrl_list(&pLight->node_addr) == LIGHT_IS_CTRL_BY_TEMP)
			{
				PRINTF("[%s]: This light 0x%04x is being controlled by administrator...\n", (policy_type == POLICY_TYPE_USR)?"USR":"DFT", pLight->node_addr);

				pLight->light_cur_state = 0;

				continue;
			}
			
			//PRINTF("[%s] ID:%d, state:%d --> %d, cur_time = 0x%x, time: 0x%x --> 0x%x\n", (policy_type == POLICY_TYPE_USR)?"USR":"DFT", pLight->node_idx, pLight->light_cur_state, pPolicy->light_state,cur_time, pPolicy->start_time, pPolicy->stop_time); 
			PRINTF("[%s] ID:%d, [%02x%02x%02x%02x], state:%d --> %d, cur_time = %s, time: %s --> %s\n", (policy_type == POLICY_TYPE_USR)?"USR":"DFT", pLight->node_idx, pLight->node_addr.mac_addr[0], pLight->node_addr.mac_addr[1], pLight->node_addr.mac_addr[2], pLight->node_addr.mac_addr[3],pLight->light_cur_state, pPolicy->light_state, c_time, s_time, e_time); 
		
			if( (cur_time >= pPolicy->start_time) &&
			(cur_time < pPolicy->stop_time))
			{
				//real_state = get_light_state(&pLight->node_addr, pPolicy->light_ids[pLight->node_idx]);
				real_state = LIGHT_STATE_UNKNOWN;

				//if(pLight->light_cur_state != pPolicy->light_state)
				if(real_state != pPolicy->light_state)
				{
					// light on or off 
					///PRINTF("[%s] ID:%d: %s\n", (policy_type == POLICY_TYPE_USR)?"USR":"DFT", pLight->node_idx, /*pLight->node_addr, */(pPolicy->light_state == LIGHT_STATE_ON)? "Turn on":"Turn off");

					pLight->light_cur_state = pPolicy->light_state;
					// send cmd to zigbee node
					if(pPolicy->light_state == LIGHT_STATE_ON)
					{
						turn_on_one_light(pPolicy->light_ids[pLight->node_idx], pLight->node_addr.mac_addr);
					}
					else
					{
						turn_off_one_light(pPolicy->light_ids[pLight->node_idx], pLight->node_addr.mac_addr);
					}
					sleep(1);	// Add delay between two light's control
					
				}
				else
				{
					PRINTF("[%s] ID:%d %s\n", (policy_type == POLICY_TYPE_USR)?"USR":"DFT", pLight->node_idx, (pPolicy->light_state == LIGHT_STATE_ON)? "is on":"isoff");
				}
			}

			else if(cur_time >= pPolicy->stop_time)
			{
#if 0 // do nothing if timeout
				if(pLight->light_cur_state == pPolicy->light_state)
				{
					// light on or off 
					PRINTF("[%s] ID:%d: %s\n", (policy_type == POLICY_TYPE_USR)?"USR":"DFT", pLight->node_idx, (pPolicy->light_state == LIGHT_STATE_ON)? "Please Turn off":"Turn on");

					pLight->light_cur_state = (pPolicy->light_state == LIGHT_STATE_ON)? LIGHT_STATE_OFF:LIGHT_STATE_ON;
					// send cmd to zigbee node
					if(pPolicy->light_state == LIGHT_STATE_ON)
					{
						turn_off_one_light(pPolicy->light_ids[pLight->node_idx], pLight->node_addr.mac_addr);
					}
					else
					{
						turn_on_one_light(pPolicy->light_ids[pLight->node_idx], pLight->node_addr.mac_addr);
					}
				}
#endif
			}
		}

	}

	// unlock the g_usr_light_list
	pthread_mutex_unlock(&g_light_mutex);
	pthread_mutex_unlock(&g_policy_mutex);
}


void execute_policy(void)
{
	// temp policy
	while(1)
	{
		if(current_status == LC_STATUS_SYNCOK)
		{
			// usr policy
			do_execute_policy(POLICY_TYPE_USR);
		}
		else
		{
			// default policy
			do_execute_policy(POLICY_TYPE_DFT);
		}
		sleep(POLICY_FREQUENCY);
	}
}
#if 0
void read_def_policy(int tm_yday)
{
	char *policy_buf = NULL;
	FILE *fp;
	int fd;
	int len = 0;
	int f_len = 0;
	struct stat s_buf;

	fp = fopen(DEF_POLICY_FILE, "r");
	if(!fp)
	{
		printf("open %s error\n", DEF_POLICY_FILE);
		return;
	}
	fd = fileno(fp);

	fstat(fd, &s_buf);
	f_len = s_buf.st_size;

	policy_buf = (char *) malloc(f_len + 1);
	if(!policy_buf)
	{
		printf("malloc policy_buf error\n");
		return;
	}	

	// read file
	len = fread(policy_buf, 1, f_len, fp);
	if(len != f_len)
	{
		printf("fread error\n");
	}
	parse_def_policy(policy_buf, len, tm_yday);

	free(policy_buf);
	policy_buf = NULL;

	fclose(fp);
}
#else
void read_def_policy(int tm_yday)
{
	FILE *fp;
	int fd;
	int len = 0;
	struct stat s_buf;
	char policy_block[40960];
	char *date_start;
	char date_string[16];
	int policy_len = 0;

	fp = fopen(DEF_POLICY_FILE, "r");
	if(!fp)
	{
		printf("open %s error\n", DEF_POLICY_FILE);
		return;
	}
	fd = fileno(fp);

	fstat(fd, &s_buf);
	//f_len = s_buf.st_size;

	memset(date_string, 0, sizeof(date_string));
	sprintf(date_string, "[%03d]",tm_yday);

	printf("%s... date_string = %s\n",__FUNCTION__, date_string);
	while(!feof(fp))
	{
		// read file
		memset(policy_block, 0, sizeof(policy_block));
		len = fread(policy_block, 1, sizeof(policy_block), fp);
		date_start = strstr(policy_block, date_string);
		if(date_start != NULL)
		{
			policy_len = len - (date_start - policy_block);
			printf("Found it....%d\n", policy_len);
			break;
		}
	}
	parse_def_policy(date_start, policy_len, tm_yday);

	fclose(fp);
}
#endif
int parse_def_policy(char *policy_buf, int len, int tm_yday)
{
	char *date_start;
	char *date_stop, date[4];
	char *policy_start,*policy_stop;
	char *no_space;
	int date_num = 0;

	one_def_policy_T one_policy;
	msg_policy_T *pPolicy;

	struct list_head *pTypeList;
	int i = 0;

	if(!policy_buf)
	{
		printf("%s, policy_buf is null\n", __FUNCTION__);
		return -1;
	}
	no_space = (char *)malloc(len);

	memcpy(no_space, policy_buf, len);
	
	no_space = remove_space(no_space);
	
	date_start = no_space;

	// flush the list
	flush_policy(POLICY_TYPE_DFT);

	while(*date_start != '\0')
	{
		memset(date, 0, sizeof(date));
		date_start = strstr(date_start, "[");
	
		// find a date
		if(date_start)
		{
			//printf("date_start = %s\n", date_start);
			date_stop = strstr(date_start,"]");
			if(!date_stop)
				break;
			memcpy(date, (date_start + 1), (date_stop - date_start - 1));
			date_num = atoi(date);
#if 0
			PRINTF("date = %s, date_num = %d\n", date, date_num);
#endif
			// read a policy
			policy_start = date_stop + 2;
			while(policy_start)
			{
				memset(&one_policy, 0, sizeof(one_policy));
				policy_stop = strstr(policy_start, "\n");
				if(!policy_stop)
					break;

				if((policy_stop - policy_start) && (date_num == tm_yday))
				{
					memcpy(&one_policy, policy_start, (policy_stop - policy_start));
					//printf("policy_start = %s, one_policy = %s\n", policy_start, one_policy);
					one_policy.light_num[3] = '\0';
					one_policy.light_state[1] = '\0';
					one_policy.start_time[8] = '\0';
					one_policy.stop_time[8] = '\0';
#if 0
					PRINTF("one_policy:  num = %s\n", one_policy.light_num);
					PRINTF("           state = %s\n", one_policy.light_state);
					PRINTF("      start_time = %s\n", one_policy.start_time);
					PRINTF("       stop_time = %s\n", one_policy.stop_time);
#endif
					pthread_mutex_lock(&g_policy_mutex);

					pTypeList = &g_dft_policy_list;

					pPolicy = (msg_policy_T *)malloc(sizeof(msg_policy_T));
					if(!pPolicy)
					{
						printf("policy malloc memory error!\n");
						break;
					}
					//printf("[MALLOC] %s: 0x%x\n", __FUNCTION__, pPolicy);

					pPolicy->light_num = atoi(one_policy.light_num);
					pPolicy->light_state = atoi(one_policy.light_state);
					pPolicy->start_time = format_time(date_num, one_policy.start_time);
					pPolicy->stop_time = format_time(date_num, one_policy.stop_time);
					// stop on the next day
					if(pPolicy->stop_time < pPolicy->start_time)
					{
						pPolicy->stop_time = format_time(date_num + 1, one_policy.stop_time);
					}
					pPolicy->node_addrs = (node_mac_addr_T *)malloc(pPolicy->light_num * sizeof(node_mac_addr_T));
					//printf("[MALLOC] %s: node_addrs 0x%x\n", __FUNCTION__, pPolicy->node_addrs);

					if(strncmp(one_policy.mac_addr, "ffffffffffffffff", 16) != 0)
					{
						node_addrs_split(one_policy.mac_addr, pPolicy->node_addrs, pPolicy->light_ids);
					}
					else
					{
						memset(pPolicy->node_addrs[0].mac_addr, 0xff, 8);
						pPolicy->light_ids[0] = 0;
					}
					// next policy
					list_add_tail(&pPolicy->list, pTypeList);

					pthread_mutex_unlock(&g_policy_mutex);
				}
				policy_start = policy_stop + 1;
				while(*policy_start == ' ')
					policy_start++;
				if(*policy_start == '[')
					break;
			}
			if(!policy_start)
				break;
			date_start = policy_start;
		}
		else
		{
			break;
		}
	}
	// update the light state
	update_policy_per_light(POLICY_TYPE_DFT);

	//dump_policy_list(&g_dft_policy_list);
	//dump_light_list(&g_dft_light_list);

	if(no_space)
	{
		free(no_space);
		no_space = NULL;
	}
	return 0;
}
