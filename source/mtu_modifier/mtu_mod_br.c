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
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/version.h>
#include <net/ip.h>
#include <net/dst.h>

#ifndef MTU_MOD_IF_NAME_SIZE
#define MTU_MOD_IF_NAME_SIZE 32
#endif

typedef struct{
    struct list_head node;
    char brName[MTU_MOD_IF_NAME_SIZE];
    unsigned char segFlag;
    unsigned char icmpTooBigFlag;
    unsigned char mtu[2];
    unsigned char pGw[4];
}mtu_mod_node_t;

static void mtu_mod_flush_nodes(void);
static unsigned int mtu_mod_hook(unsigned int hook, struct sk_buff *skb, 
    const struct net_device *indev, const struct net_device *outdev,
    int (*kfn)(struct sk_buff *));

static struct list_head gMtuModBrList;
static spinlock_t   lock;
static struct nf_hook_ops mtu_mod_ops={
 .hook = (nf_hookfn *)mtu_mod_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
 .owner = THIS_MODULE,
#endif
 .pf = PF_BRIDGE,
 .hooknum = NF_BR_FORWARD,  /*before deliver a SKB to the destination port*/
 .priority = NF_BR_PRI_FIRST,
};

extern __sum16 ip_fast_csum(const void *iph, unsigned int ihl);
extern __sum16 ip_compute_csum(const void *buff, int len);

/***********************************************************************/

static void mtu_mod_lock(void)
{
    spin_lock_bh(&lock);
}

static void mtu_mod_unlock(void)
{
    spin_unlock_bh(&lock);
}

void mtu_mod_node_init(void)
{
    INIT_LIST_HEAD(&gMtuModBrList);
    spin_lock_init(&lock);
    (void)nf_register_hook(&mtu_mod_ops);
}

void mtu_mod_node_deinit(void)
{
    nf_unregister_hook(&mtu_mod_ops);
    mtu_mod_flush_nodes();
}

static mtu_mod_node_t *mtu_mod_search_node(char *pBrName)
{
    mtu_mod_node_t *pNode;
    int found=0;

    list_for_each_entry(pNode,&gMtuModBrList,node){
        if(strcmp(pBrName,pNode->brName)==0){
            found=1;
            break;
        }
    }

    if(found)
        return(pNode);
    return(NULL);
}

int mtu_mod_get_setting(char *pBrName,int *pSegFlag, int *pIcmpFlag, unsigned char *pMtu, unsigned char *pGw)
{
    mtu_mod_node_t *pNode;

    mtu_mod_lock();

    pNode = mtu_mod_search_node(pBrName);
    if(pNode){
        *pSegFlag = (int)pNode->segFlag;
        *pIcmpFlag = (int)pNode->icmpTooBigFlag;
        memcpy(pMtu, pNode->mtu, 2);
        memcpy(pGw, pNode->pGw, 4);
    }

    mtu_mod_unlock();

    if(pNode)
        return(0);
    return(-1);
}

void mtu_mod_create_node(char *pBrName,char segmentFlag, char icmpFlag, int mtu, unsigned int gwIp)
{
    mtu_mod_node_t *pNode;

    if(strlen(pBrName) >= MTU_MOD_IF_NAME_SIZE)
        return;
    mtu_mod_lock();

    pNode = mtu_mod_search_node(pBrName);
    if(pNode == NULL){
        pNode = kmalloc(sizeof(mtu_mod_node_t), GFP_KERNEL);
        if(pNode==NULL){
            mtu_mod_unlock();
            printk(KERN_ERR "Failed to allocate memory for bridge %s\n", pBrName);
            return;
        }
        strcpy(pNode->brName, pBrName);
        list_add_tail(&pNode->node, &gMtuModBrList);
    }
    pNode->mtu[0] = (mtu>>8) & 0xFF;
    pNode->mtu[1] = mtu & 0xFF;
    pNode->segFlag = segmentFlag;
    pNode->icmpTooBigFlag = icmpFlag;
    memcpy(pNode->pGw, &gwIp, 4);

    mtu_mod_unlock();
}

void mtu_mod_remove_node(char *pBrName)
{
    mtu_mod_node_t *pNode;

    mtu_mod_lock();

    pNode = mtu_mod_search_node(pBrName);
    if(pNode){
        list_del(&pNode->node);
        kfree(pNode);
    }

    mtu_mod_unlock();
}

void mtu_mod_update_node(char *pBrName, char segmentFlag, char icmpFlag, int mtu, unsigned int gwIp)
{
    mtu_mod_create_node(pBrName,segmentFlag, icmpFlag, mtu, gwIp);
}

void mtu_mod_show_node(char *pBrName)
{
    mtu_mod_node_t *pNode;

    mtu_mod_lock();
    
    pNode = mtu_mod_search_node(pBrName);
    if(pNode){
        printk("br->%s, seg %d, icmp %d, mtu %d, gwIp %d.%d.%d.%d\n", 
            pNode->brName,pNode->segFlag,pNode->icmpTooBigFlag,
            (pNode->mtu[0]<<8) | pNode->mtu[1], 
            pNode->pGw[0],pNode->pGw[1],pNode->pGw[2],pNode->pGw[3]);
    }

    mtu_mod_unlock();
}

static void mtu_mod_flush_nodes(void)
{
    mtu_mod_node_t *pNode, *pNode1;

    mtu_mod_lock();

    list_for_each_entry_safe(pNode,pNode1,&gMtuModBrList,node){
        list_del(&pNode->node);
        kfree(pNode);
    }
    
    mtu_mod_unlock();
}

static unsigned char icmpPktTemp[]={
    0x45,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x40,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x03,0x04,0x00,0x00,0x00,0x00,0x00,0x00
};

static void mtu_mod_send_icmp_too_big_frame(const struct net_device *pInDev, struct sk_buff *pSkb, unsigned char mtu[2], unsigned char gw[4])
{
    unsigned char *pSrc = eth_hdr(pSkb)->h_dest, *pDst, *pIp, *pIcmp;
    struct sk_buff *icmpSkb;
    unsigned short checksum;
    int len, ipLen, icmpLen;

    if(eth_hdr(pSkb)->h_dest[0] & 1)/*don't send icmp too big for multicast or broadcast packets*/
        return;
    icmpSkb = alloc_skb(256, GFP_ATOMIC); /*256 is big enough to construct the icmp too-big frame*/
    if(icmpSkb==NULL)
        return;
    skb_reserve(icmpSkb, 64);
    skb_reset_mac_header(icmpSkb);
    pDst = icmpSkb->data;
    
    /*To construct the Ethernet header first*/
    memcpy(pDst, eth_hdr(pSkb)->h_source, 6);  /*exchange the source MAC & dest MAC in original packet*/
    memcpy(&pDst[6], eth_hdr(pSkb)->h_dest, 6);
    *(unsigned short*)&pDst[12] = eth_hdr(pSkb)->h_proto;
    pDst += 14;
    if((pSrc[12]==0x81)&&(pSrc[13]==0)){/*vlan tag*/
        memcpy(pDst, &pSrc[14], 2);
        pDst += 2;
        pSrc += 18; /*pSrc points to the ip header of the original packet*/
    }else
        pSrc += 14;

    /*To construct the ICMP packet*/
    icmpSkb->data = pIp = pDst;
    skb_reset_network_header(icmpSkb);
    pIcmp = pDst + 20;
    memcpy(pDst, icmpPktTemp,sizeof(icmpPktTemp));
    pDst += sizeof(icmpPktTemp); /*pDst points to the data of ICMP packet*/
    memcpy(&pIp[12], gw, 4); /*Set source IP to wlan Gw's IP address*/
    memcpy(&pIp[16], &pSrc[12], 4); /*Set dest IP*/

    /*copy the original IP header + 8 bytes to new packet*/
    len = ((pSrc[0] & 0xF) << 2) + 8;
    if(len>(192-(pDst-icmpSkb->data))){ /*192=256(total size)-64(reserve)*/
        kfree_skb(icmpSkb);
        return;
    }
    memcpy(pDst, pSrc, len);
    pDst += len;

    /*calculate the icmp & ip checksum*/
    ipLen = pDst - pIp;
    pIp[2] = (ipLen >> 8) & 0xFF;
    pIp[3] = ipLen & 0xFF;
    checksum = ip_fast_csum(pIp,5);
    memcpy(&pIp[10],&checksum,2);
    icmpLen = pDst - pIcmp;
    memcpy(&pIcmp[6],mtu,2);
    checksum = ip_compute_csum(pIcmp,icmpLen);
    memcpy(&pIcmp[2],&checksum,2);

    /*assign necessary fields for icmp skb*/
    skb_put(icmpSkb, pDst - skb_mac_header(icmpSkb));
    icmpSkb->data = skb_mac_header(icmpSkb);
    icmpSkb->dev = pInDev;
    icmpSkb->protocol = htons(ETH_P_IP);

    /*send this skb out*/
    dev_queue_xmit(icmpSkb);
}

static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
    to->pkt_type = from->pkt_type;
    to->priority = from->priority;
    to->protocol = from->protocol;
    skb_dst_drop(to);
    skb_dst_copy(to, from);
    to->dev = from->dev;
    to->mark = from->mark;
    
    IPCB(to)->flags = IPCB(from)->flags;
    nf_copy(to, from);
    skb_copy_secmark(to, from);
    
}

static void
br_ip_fragment(struct sk_buff *skb,
               const struct net_device *indev,
               const struct net_device *outdev,
               int mtu,
               int (*output)(struct sk_buff *))
{
    struct iphdr *iph;
    int ptr;
    struct sk_buff *skb2;
    struct ethhdr *eth2;
    unsigned int hlen, left, len, encap_len;
    int offset;
    __be16 not_last_frag;
    unsigned short iph_tot_len;
    
    iph = ip_hdr(skb);          /* point to the ip header */
    hlen = iph->ihl * 4;        /* ip header length */
    
    IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

    iph_tot_len = ntohs(iph->tot_len);
    left = iph_tot_len - hlen; /* original ip payload size */
    mtu -= hlen;                /* ip payload MTU */
    ptr = hlen;                 /* where to start from copying data */

    /* reserve vlan and gre header length */
    encap_len = VLAN_HLEN + 8;  /* GRE: 4 bytes are optional */
    
    offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
    not_last_frag = iph->frag_off & htons(IP_MF);

    
    /* Keep copying data until we run out */
    while (left > 0){
        len = left;
        if (len > mtu)
            len = mtu;          /* ip payload mtu */
        if (len < left)         /* fragments align on a 8-byte boundary except for the last one */
            len &= ~7;

        printk(KERN_DEBUG "%s (%d): tot_len %d left %d mtu %d len %d hlen %d\n", __func__, __LINE__, 
                          iph_tot_len, left, mtu, len, hlen);
        
        /* allocate buffer */
        if ((skb2 = alloc_skb(len+hlen+ETH_HLEN+encap_len, GFP_ATOMIC)) == NULL){
            printk(KERN_ERR "%s: no memory for new fragments!\n", __func__);
            return;
        }
        
        ip_copy_metadata(skb2, skb);
        skb_reserve(skb2, encap_len);

        /* encap ethernet header */
        skb_put(skb2, ETH_HLEN);
        skb_reset_mac_header(skb2);
        eth2 = eth_hdr(skb2);
        memcpy(eth2, eth_hdr(skb), ETH_HLEN);
                
        skb_put(skb2, len+hlen);
        skb_set_network_header(skb2, ETH_HLEN);
        skb2->transport_header = skb2->network_header + hlen;

        
        /* copy the packet header into new buffer */
        skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);
        
        /* copy a block of the ip datagram */
        if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
            BUG();
        left -= len;
        
        /* fill in the new header fields */
        iph = ip_hdr(skb2);
        iph->frag_off = htons(offset >> 3);
        
        
        if (left > 0 || not_last_frag)
            iph->frag_off |= htons(IP_MF);
        ptr += len;
        offset += len;
        
        iph->tot_len = htons(len + hlen);
        ip_send_check(iph);
        
        skb2->dev = (struct net_device *)outdev;

        printk(KERN_DEBUG "Deliver fragments to %s!\n", outdev->name);
        output(skb2);
    }
}
               

static unsigned int mtu_mod_hook(unsigned int hook, struct sk_buff *skb, 
    const struct net_device *indev, const struct net_device *outdev,
    int (*kfn)(struct sk_buff *))
{
    struct net_device *brDev;
    unsigned char mtu[2],gwIp[4];
    int icmpFlag, segFlag;
    unsigned short totalLen;

    //>>zqiu: indev and outdev could be null
    if(!indev || !outdev){
		printk(KERN_ERR "COMCAST ERROR:: indev  %s outdev  %s\n", indev?indev->name:"null",  outdev?outdev->name:"null" ); 
		return (NF_DROP);
	}
    //<<

    if(skb->protocol != htons(ETH_P_IP))
        return(NF_ACCEPT);
    brDev = (struct net_device *)(indev);
    /*if MTU modification is not enabled on this bridge, just return*/
    if(mtu_mod_get_setting(brDev->name, &segFlag, &icmpFlag, mtu,gwIp)){
        return(NF_ACCEPT);
    }
    totalLen = (skb->data[2] <<8 ) | skb->data[3];
    if(totalLen <= ((mtu[0]<<8)|mtu[1])){/*not bigger than the max size of an frame*/
        return(NF_ACCEPT);
    }
    if(icmpFlag){
        mtu_mod_send_icmp_too_big_frame(indev,skb,mtu,gwIp);
    }
    if(segFlag) {
        br_ip_fragment(skb,indev,outdev,(mtu[0]<<8)|mtu[1],dev_queue_xmit);
        return (NF_DROP);
    }
    return(NF_ACCEPT);
}
