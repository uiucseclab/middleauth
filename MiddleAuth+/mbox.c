#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>


/* Controlling variables */
bool IP_in_UDP_ENCAP = true;


/* NetFilter hooks */
static struct nf_hook_ops nf_hook_in;
static struct nf_hook_ops nf_hook_out;

// Addresses
char redirect_ip[15] = "192.168.30.109";
char middlebox_ip[15] = "192.168.200.61";
unsigned int middlebox_networkip;
unsigned int redirect_networkip;



// ip address convertion
unsigned int ip_str_to_num(const char *buf)
{
  unsigned int tmpip[4] = {0};
  unsigned int tmpip32 = 0;
  sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);
  tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];
  return tmpip32;
}


/* Hook function for inbound packets */
// 1. Redirect packets from client to the service provider 
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *iph = NULL;
  struct tcphdr *tcph=NULL;
  int tcplen;

  if (!in) return NF_ACCEPT;

  iph = ip_hdr(skb);
  if (unlikely(iph == NULL)) return NF_ACCEPT;


  /* Packets destinated to the mbox will be redirected to the service provider*/
  if(iph->daddr == middlebox_networkip)
  {
    if(iph->protocol == IPPROTO_TCP)
    {
      // obtains the tcp header
      tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

      // irrelevant packets
      // 9877 is the port listened by the service provider
      if (ntohs(tcph->dest) != 9877) return NF_ACCEPT;

      // redirect packet to the service provider
      iph->daddr = redirect_networkip;

      /*
      // Here we can add additional data into the packet to serve as network capabilities
      // 1. Additional data should be appended into the payload. We cannot add these data in front of the skb_buff since that the front space stores the packet headers, which are crutial for TCP/IP
      // 2. We need to check the tailroom before appending new data into the skb_buff.
      // 3. A module at the service provider needs to strip the added data to deliever original data context
      
      // Check whether the skb_buff has at least 40 bytes and make sure the skb_buff has not been paged.
      // The pagement of the skb_buff can be avoided once we disable the TSO offloading
      if (skb_tailroom(skb) >= 40 && skb->data_len == 0) {

	secure = network_capabilities	
    
	// append the capabilities to the data payload
	secure = skb_put(skb, 40);
      }
      */

      // recompute tcp checksum
      // This is very important, otherwise the packet will be dropped due to checksum error
      tcplen = skb->len - ip_hdrlen(skb);
      tcph->check = 0; 
      tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

      // recompute the IP checksum
      skb->ip_summed = CHECKSUM_NONE;
      ip_send_check(iph);

      //printk(KERN_INFO "Packet length after PRE_ROUTING: %u\n", ntohs(iph->tot_len));
    }
  }

  return NF_ACCEPT;                                                              
}



/* Hook function for outbound traffic */
// 1. Encapsulate the packets destinated to the victim
// 2. Redirect the packets from the vicimt to the client
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *iph = NULL;
  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
  int original_ip_len;
  unsigned int source_ip;
  unsigned int dest_ip;
  unsigned int tot_payload_len;
  unsigned int tcplen;


  // for capability feedback
  unsigned int res1 = 0;
  struct iTable *temp2;
  char getcapability[40];
  struct capability *cap2;

  //TODO for adding capability
  unsigned char *secure;
  unsigned char encryptioncode[36] = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
  char room[40];
  struct capability *cap = room;  
  // iTable header
  struct iTable *temp;

  if (!out) return NF_ACCEPT;

  /*strip IP header*/
  iph = ip_hdr(skb);
  if (unlikely(iph == NULL)) return NF_ACCEPT;


  /* Packets targeted to the service provider */
  if(iph->daddr == redirect_networkip)
  {

    /* UDP encapsulation */
    if (IP_in_UDP_ENCAP) 
    {
      if(iph->protocol == IPPROTO_TCP)
      {
	tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);

	// irrelevent pacekts
	if (ntohs(tcph->dest) != 9877) {
	  return NF_ACCEPT;
	}

	// remember the information from original packets
	source_ip = iph->saddr;
	dest_ip = iph->daddr;
	original_ip_len = ntohs(iph->tot_len);
	tot_payload_len = ntohs(iph->tot_len) - iph->ihl*4 - tcph->doff*4;

	//printk(KERN_INFO "Packet length at POST_ROUTING: %u\n", ntohs(iph->tot_len));

	/*insert new header for authenticator*/
	/* 1. Insert UDP header first 
	   2. Then insert IP header 
	   */

	// Need to perform headroom check before inserting new data to avoid segmentation fault
	if (!(skb_headroom(skb) > (sizeof(struct iphdr) + sizeof(struct udphdr)))) {
	  if (pskb_expand_head(skb, (sizeof(struct iphdr) + sizeof(struct udphdr)), 0, GFP_ATOMIC) != 0) { 
	    printk(KERN_INFO "headeroom is not enough");
	    return NF_DROP;
	  } 
	} 

	if (!(skb_headroom(skb) > (sizeof(struct iphdr) + sizeof(struct udphdr)))) {
	  printk(KERN_INFO "headeroom is not enough");
	  return NF_DROP;
	}

	/*UDP header*/
	udph = (struct udphdr*) skb_push(skb, sizeof(struct udphdr));
	udph->source = htons(30000);
	udph->dest = htons(30000);
	udph->len = htons(tot_payload_len); // for payload size


	// UDP checksum: 
	// VXLAN's UDP checksum is 0. So we do not need to calculate the checksum actually.  
	udph->check = 0; 

	/*IP header*/
	iph = (struct iphdr*) skb_push(skb, sizeof(struct iphdr));
	iph->protocol = IPPROTO_UDP;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + original_ip_len + sizeof(struct udphdr));
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 60;

	// addresses
	iph->saddr = source_ip;
	iph->daddr = dest_ip;

	// compute the checksum
	skb->ip_summed = CHECKSUM_NONE;
	ip_send_check(iph);

	//printk(KERN_INFO "Packet length after POST_ROUTING: %u\n", ntohs(iph->tot_len));
	return NF_ACCEPT;
      } /*Handle TCP traffic*/

    } /*UDP encap*/

  } /* Packets for the victim */


  return NF_ACCEPT;                                                              
}



/*Called when module loaded using insmod*/
int init_module()
{
  middlebox_networkip = ip_str_to_num(middlebox_ip);
  redirect_networkip = ip_str_to_num(redirect_ip);

  // hook for incoming packets
  nf_hook_in.hook = hook_func_in;                   
  nf_hook_in.hooknum = NF_INET_PRE_ROUTING;   
  nf_hook_in.pf = PF_INET;                           
  nf_hook_in.priority = NF_IP_PRI_FIRST;             
  nf_register_hook(&nf_hook_in);                     


  // hook for outgoing packets
  nf_hook_out.hook = hook_func_out;                   
  nf_hook_out.hooknum = NF_INET_POST_ROUTING;   
  nf_hook_out.pf = PF_INET;                           
  nf_hook_out.priority = NF_IP_PRI_FIRST;             
  nf_register_hook(&nf_hook_out);  

  printk(KERN_INFO "Start redirect (with authentication) module\n");
  return 0;                                    
}


/*Called when module unloaded using rmmod*/
void cleanup_module()
{
  nf_unregister_hook(&nf_hook_in);                   
  nf_unregister_hook(&nf_hook_out);    
  printk(KERN_INFO "Remove redirect (with authentication) module\n");
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhuotao Liu");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("MiddleAuth+");
