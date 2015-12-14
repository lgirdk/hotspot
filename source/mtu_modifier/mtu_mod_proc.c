/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

#include <linux/kernel.h>	
#include <linux/module.h>
#include <linux/proc_fs.h>	
#include <linux/namei.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <asm/uaccess.h>

#ifndef MTU_MODIFIER_FILE_NAME
#define MTU_MODIFIER_FILE_NAME	"mtu_mod"
#endif

static unsigned char parameters[1024];
static struct proc_dir_entry *mtu_mod_proc_file = NULL;

extern struct net init_net;

extern void mtu_mod_create_node(char *pBrName,char segmentFlag, char icmpFlag, int mtu,unsigned int gwIp);
extern void mtu_mod_remove_node(char *pBrName);
extern void mtu_mod_update_node(char *pBrName, char segmentFlag, char icmpFlag, int mtu, unsigned int gwIp);
extern void mtu_mod_show_node(char *pBrName);

/************************************************************/

/*the end of the value can be a space, a tab, a new line, or the end of the string*/
int extract_nvp_value(char *buffer,char *pKey, char *pValue, int strSize)
{
	char *pStart, *p;
	int len;
	
	*pValue = 0;
	pStart = strstr(buffer, pKey);
	len = strlen(pKey);
	if((pStart == NULL)|| (pStart[len] != '='))
		return(-1);
	p = pStart = pStart + len + 1;
	while(1){
		if((*p==0)||(*p==' ')||(*p=='	')||(*p=='\n'))
			break;
		p++;
	}
	len = p - pStart;
	if((len+1)>strSize)
		return(-1);
	memcpy(pValue, pStart, len);
	pValue[len] = 0;
	return(0);
}

static int mtu_mod_read_proc(char *buffer, char **buffer_location,
	      off_t offset, int buffer_length, int *eof, void *data)
{
	return(0);
}

static int mtu_mod_write_proc(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	char brName[32], mtuStr[8],icmpStr[2], segStr[2], ipaddr[16];
	int len, mtu=0, icmpFlag=0, segFlag=0;
	unsigned int gwIp;

	if(count >= sizeof(parameters))
		len = sizeof(parameters) - 1;
	else
		len = count;
	parameters[len] = 0;
	if ( copy_from_user(parameters, buffer, len) )
		return -EFAULT;
	printk(KERN_INFO "input string is %s\n", parameters);
	if(extract_nvp_value(parameters,"br", brName,sizeof(brName))){
		printk(KERN_ERR "Please specify the name of the bridge\n");
		return -1;
	}
	extract_nvp_value(parameters, "segment", segStr,sizeof(segStr));
	if((segStr[0]=='y') ||(segStr[0]=='Y'))
		segFlag = 1;
	extract_nvp_value(parameters, "icmp", icmpStr,sizeof(icmpStr));
	if((icmpStr[0]=='y') ||(icmpStr[0]=='Y'))
		icmpFlag = 1;
	extract_nvp_value(parameters, "mtu", mtuStr,sizeof(mtuStr));
	mtu = (int)simple_strtoul(mtuStr, NULL, 10);
	extract_nvp_value(parameters, "gw", ipaddr,sizeof(ipaddr));
	gwIp = in_aton(ipaddr);

	if(strstr(parameters,"add")){
		mtu_mod_create_node(brName,segFlag, icmpFlag, mtu, gwIp);
	}else if(strstr(parameters,"del")){
		mtu_mod_remove_node(brName);
	}else if(strstr(parameters,"update")){
		mtu_mod_update_node(brName,segFlag, icmpFlag, mtu, gwIp);
	}else if(strstr(parameters,"show")){
		mtu_mod_show_node(brName);
	}

	return(count);
}

static const struct file_operations mtu_mod_proc_file_fops = {
 .owner = THIS_MODULE,
 .write = mtu_mod_write_proc,
 .read  = mtu_mod_read_proc,
};

int init_mtu_mod_proc(void)
{
	if(mtu_mod_proc_file)
		return(-1);
	
	/* create the /proc file */
	mtu_mod_proc_file = proc_create(MTU_MODIFIER_FILE_NAME, 0644, init_net.proc_net, &mtu_mod_proc_file_fops);
	if (mtu_mod_proc_file == NULL){
		remove_proc_entry(MTU_MODIFIER_FILE_NAME, NULL);
		printk(KERN_EMERG "Error: Could not initialize %s\n",MTU_MODIFIER_FILE_NAME);
		return -ENOMEM;
	}

	return(0);
}

void deinit_mtu_mod_proc(void)
{
	if(mtu_mod_proc_file){
		remove_proc_entry(MTU_MODIFIER_FILE_NAME, init_net.proc_net);
		mtu_mod_proc_file = NULL;
	}
}
