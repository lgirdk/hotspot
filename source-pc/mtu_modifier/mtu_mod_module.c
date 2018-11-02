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

extern int init_mtu_mod_proc(void);
extern void deinit_mtu_mod_proc(void);
extern void mtu_mod_node_init(void);
extern void mtu_mod_node_deinit(void);

/************************************************************/

int mtu_mod_init(void)
{
	mtu_mod_node_init();
	if(init_mtu_mod_proc()){
		return(-1);
	}

	printk(KERN_INFO "MTU Modifier loaded\n");
	return(0);
}

void mtu_mod_clean(void)
{
	deinit_mtu_mod_proc();
	mtu_mod_node_deinit();
	printk(KERN_INFO "MTU Modifier unloaded\n");
}

module_init(mtu_mod_init);
module_exit(mtu_mod_clean);

MODULE_LICENSE("GPL") ; 

