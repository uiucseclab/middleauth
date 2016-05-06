#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>

/* controle variable */
bool STORE_CAPABILITY = true;
bool RETURN_CAPABILITY = true;

/* Netfilter HOOKs */
static struct nf_hook_ops nf_hook_in;
static struct nf_hook_ops nf_hook_out;
static struct nf_hook_ops nf_hook_local_in;
static char *param_dev = NULL;
MODULE_PARM_DESC(param_dev, "The operated network interface.");
module_param(param_dev, charp, 0);


/*Addresses*/
char middlebox_ip[15] = "192.168.200.61";
char redirect_ip[15] = "192.168.30.109";
unsigned int middlebox_networkip;
unsigned int redirect_networkip;


/* convert string to number IP  */
unsigned int ip_str_to_num(const char *buf)
{
  unsigned int tmpip[4] = {0};
  unsigned int tmpip32 = 0;

  sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);

  tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];

  return tmpip32;
}


/*hook for the local-in packet*/
// A function for debugging
unsigned int hook_func_local_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *iph = NULL;
  struct tcphdr *tcph=NULL;
  redirect_networkip = ip_str_to_num(redirect_ip);

  // ignore irrelevent packets
  if (!in) return NF_ACCEPT;
  if (strcmp(in->name, param_dev) != 0) return NF_ACCEPT;

  // strip ip header
  iph = (struct iphdr*) skb_network_header(skb);
  if (unlikely(iph == NULL)) return NF_ACCEPT; 


  if (iph->daddr == redirect_networkip) {
    if (iph->protocol == IPPROTO_TCP) {
      tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);		

      //printk(KERN_INFO "LOCAL_IN: TCP packet with length %u received. \n", skb->len);
    }

    if (iph->protocol == IPPROTO_UDP) {
      printk(KERN_INFO "LOCAL_IN: UDP packet with length %u received, error! \n", skb->len);
    }
  }

  return NF_ACCEPT;
}


/*hook for the inbound packet*/
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *iph = NULL;
  struct tcphdr *tcph=NULL;
  int tcplen;
  unsigned int tcp_payload_len;


  // ignore irrelevent packets
  if (!in) return NF_ACCEPT;
  if (strcmp(in->name, param_dev) != 0) return NF_ACCEPT;

  // strip ip header
  iph = (struct iphdr*)skb_network_header(skb);

  middlebox_networkip = ip_str_to_num(middlebox_ip);
  redirect_networkip = ip_str_to_num(redirect_ip);

  // handling all packets targetting the service provider
  if(iph->daddr == redirect_networkip) {
    // All traffic is encapsulated into UDP packets
    //printk(KERN_INFO "PRE_ROUTING: Packet length before stripping: %u\n", skb->len);

    // the outer IP/UDP header can be stripped by either the software here
    // In some case, the linux kernel will strip packets for us :) 
    if(iph->protocol == IPPROTO_UDP)
    {
      /* remove the outer IP and UDP header */
      if (skb->len < (sizeof(struct iphdr) + sizeof(struct udphdr) + 40)) {
	printk(KERN_INFO "Packets without encapsulation !!!!");
	return NF_DROP;
      } 

      //strip the ip and udp header to deliver original data payload
      iph = (struct iphdr*) skb_pull(skb, (sizeof(struct iphdr) + sizeof(struct udphdr)));
      // offset the skb_buff
      skb->network_header += (sizeof(struct iphdr) + sizeof(struct udphdr));
      skb->transport_header += (sizeof(struct iphdr) + sizeof(struct udphdr));
      
      //printk(KERN_INFO "PRE_ROUTING: Packets have been decapsulated.\n");
      //printk(KERN_INFO "PRE_ROUTING: Packet length after stripping: %u\n", skb->len);
    } 

    /*
     * 1. If network capabilities are appended in the data payload, we need to further strip the network capabitilies
     */

  }
  return NF_ACCEPT;                                                              
}


/*Called when module loaded using insmod*/
int init_module()
{
  if (param_dev == NULL) {
    param_dev = "eth6\0"; // default interface
  }

  // inbound traffic
  nf_hook_in.hook = hook_func_in;  
  nf_hook_in.hooknum = NF_INET_PRE_ROUTING;   
  nf_hook_in.pf = PF_INET;                           
  nf_hook_in.priority = NF_IP_PRI_FIRST;             
  nf_register_hook(&nf_hook_in);    

  // local_in traffic
  nf_hook_local_in.hook = hook_func_local_in;  
  nf_hook_local_in.hooknum = NF_INET_LOCAL_IN;   
  nf_hook_local_in.pf = PF_INET;                           
  nf_hook_local_in.priority = NF_IP_PRI_FIRST;             
  nf_register_hook(&nf_hook_local_in);

  printk(KERN_INFO "Start Authentication Module\n");
  return 0;                                    
}


/*Called when module unloaded using rmmod*/
void cleanup_module()
{
  nf_unregister_hook(&nf_hook_in);  
  nf_unregister_hook(&nf_hook_local_in);
  printk(KERN_INFO "Remove Authentication Module\n");
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhuotao Liu");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("MiddleAuth+");
