#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/kmod.h>
#include <linux/if_arp.h>
#include <net/ip.h>

#define VNETIF_LIST_PROC_NAME  "vnetif"
#define VNETIF_ADD_PROC_NAME   "vnetif_add"
#define VNETIF_DEL_PROC_NAME   "vnetif_del"
#define VNETIF_IPV4_PROC_NAME  "vnetif_ipv4"

#define VNETIF_CMD_BUF_SZ   64
#define VNETIF_READ_BUF_SZ  1024
#define VNETIF_CIDR_SUFFIX  "/24"

struct vnetif_priv {
    int if_id;
    __be32 ipv4_addr;
};

struct vnetif_dev {
    struct net_device *netdev;
    struct list_head list;
};

struct vnetif_arp_eth_ipv4 {
    unsigned char sha[ETH_ALEN];
    __be32 sip;
    unsigned char tha[ETH_ALEN];
    __be32 tip;
} __packed;

static LIST_HEAD(vnetif_list);
static DEFINE_MUTEX(vnetif_lock);

static struct proc_dir_entry *proc_list_entry;
static struct proc_dir_entry *proc_add_entry;
static struct proc_dir_entry *proc_del_entry;
static struct proc_dir_entry *proc_ipv4_entry;

static int next_if_id;

static int vnet_open(struct net_device *dev);
static int vnet_stop(struct net_device *dev);
static netdev_tx_t vnet_xmit(struct sk_buff *skb, struct net_device *dev);
static void vnet_setup(struct net_device *dev);

static struct vnetif_dev *vnetif_find_locked(const char *name);
static int vnetif_create_locked(void);
static int vnetif_destroy_one_locked(const char *name);
static int vnetif_validate_ipv4_locked(const char *name, const char *ip_str,
                                       char *ifname_out,
                                       size_t ifname_out_len);
static int vnetif_set_ipv4_locked(const char *name, const char *ip_str);
static void vnetif_destroy_all_locked(void);
static int vnetif_set_link_up(struct net_device *dev);

static bool vnetif_should_reply_icmp_echo(struct sk_buff *skb,
                                          struct net_device *dev);
static bool vnetif_should_reply_arp(struct sk_buff *skb,
                                    struct net_device *dev);

static void vnetif_update_icmp_checksum(struct icmphdr *icmph, size_t len);
static void vnetif_update_ip_checksum(struct iphdr *iph);

static int vnetif_build_icmp_echo_reply(struct sk_buff *skb,
                                        struct net_device *dev);
static int vnetif_build_arp_reply(struct sk_buff *skb,
                                  struct net_device *dev);

static netdev_tx_t vnetif_rx_reply_local(struct sk_buff *skb,
                                         struct net_device *dev);

static int vnetif_run_cmd(char **argv);
static int vnetif_apply_ipv4_userspace(const char *ifname, const char *ip_str);

static ssize_t vnetif_list_read(struct file *file, char __user *buffer,
                                size_t count, loff_t *ppos);
static ssize_t vnetif_add_write(struct file *file, const char __user *buffer,
                                size_t count, loff_t *ppos);
static ssize_t vnetif_del_write(struct file *file, const char __user *buffer,
                                size_t count, loff_t *ppos);
static ssize_t vnetif_ipv4_write(struct file *file, const char __user *buffer,
                                 size_t count, loff_t *ppos);

static const struct proc_ops vnetif_list_proc_ops = {
    .proc_read = vnetif_list_read,
};

static const struct proc_ops vnetif_add_proc_ops = {
    .proc_write = vnetif_add_write,
};

static const struct proc_ops vnetif_del_proc_ops = {
    .proc_write = vnetif_del_write,
};

static const struct proc_ops vnetif_ipv4_proc_ops = {
    .proc_write = vnetif_ipv4_write,
};

static int vnet_open(struct net_device *dev)
{
    netif_start_queue(dev);
    pr_info("vnetif: %s up\n", dev->name);
    return 0;
}

static int vnet_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    pr_info("vnetif: %s down\n", dev->name);
    return 0;
}

static bool vnetif_should_reply_arp(struct sk_buff *skb,
                                    struct net_device *dev)
{
    struct vnetif_priv *priv;
    struct ethhdr *eth;
    struct arphdr *arp;
    struct vnetif_arp_eth_ipv4 *arp_data;

    if (!skb)
        return false;

    if (skb->len < sizeof(struct ethhdr) +
                   sizeof(struct arphdr) +
                   sizeof(struct vnetif_arp_eth_ipv4))
        return false;

    if (!pskb_may_pull(skb, sizeof(struct ethhdr) +
                            sizeof(struct arphdr) +
                            sizeof(struct vnetif_arp_eth_ipv4)))
        return false;

    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ethhdr));

    eth = eth_hdr(skb);
    if (!eth)
        return false;

    if (eth->h_proto != htons(ETH_P_ARP))
        return false;

    arp = (struct arphdr *)skb_network_header(skb);
    if (!arp)
        return false;

    if (arp->ar_hrd != htons(ARPHRD_ETHER))
        return false;

    if (arp->ar_pro != htons(ETH_P_IP))
        return false;

    if (arp->ar_hln != ETH_ALEN)
        return false;

    if (arp->ar_pln != 4)
        return false;

    if (arp->ar_op != htons(ARPOP_REQUEST))
        return false;

    arp_data = (struct vnetif_arp_eth_ipv4 *)(arp + 1);

    priv = netdev_priv(dev);
    if (!priv->ipv4_addr)
        return false;

    return arp_data->tip == priv->ipv4_addr;
}

static bool vnetif_should_reply_icmp_echo(struct sk_buff *skb,
                                          struct net_device *dev)
{
    struct vnetif_priv *priv;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct icmphdr *icmph;

    if (!skb)
        return false;

    if (!pskb_may_pull(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)))
        return false;

    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ethhdr));

    eth = eth_hdr(skb);
    if (!eth)
        return false;

    if (eth->h_proto != htons(ETH_P_IP))
        return false;

    iph = (struct iphdr *)skb_network_header(skb);
    if (!iph)
        return false;

    if (iph->version != 4 || iph->ihl < 5)
        return false;

    if (iph->protocol != IPPROTO_ICMP)
        return false;

    if (!pskb_may_pull(skb, sizeof(struct ethhdr) +
                            iph->ihl * 4 +
                            sizeof(struct icmphdr)))
        return false;

    iph = (struct iphdr *)skb_network_header(skb);
    icmph = (struct icmphdr *)((u8 *)iph + iph->ihl * 4);
    if (!icmph)
        return false;

    if (icmph->type != ICMP_ECHO)
        return false;

    priv = netdev_priv(dev);
    if (!priv->ipv4_addr)
        return false;

    return iph->daddr == priv->ipv4_addr;
}

static void vnetif_update_icmp_checksum(struct icmphdr *icmph, size_t len)
{
    icmph->checksum = 0;
    icmph->checksum = ip_compute_csum((void *)icmph, len);
}

static void vnetif_update_ip_checksum(struct iphdr *iph)
{
    iph->check = 0;
    ip_send_check(iph);
}

static int vnetif_build_icmp_echo_reply(struct sk_buff *skb,
                                        struct net_device *dev)
{
    struct ethhdr *eth;
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct vnetif_priv *priv;
    __be32 tmp_ip;
    size_t ip_hdr_len;
    size_t icmp_len;

    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ethhdr));

    eth = eth_hdr(skb);
    if (!eth)
        return -EINVAL;

    iph = (struct iphdr *)skb_network_header(skb);
    if (!iph)
        return -EINVAL;

    ip_hdr_len = iph->ihl * 4;
    if (skb->len < sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct icmphdr))
        return -EINVAL;

    icmph = (struct icmphdr *)((u8 *)iph + ip_hdr_len);
    if (!icmph)
        return -EINVAL;

    priv = netdev_priv(dev);

    /* Reply goes back to whoever sent the request. */
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);

    tmp_ip = iph->saddr;
    iph->saddr = priv->ipv4_addr;
    iph->daddr = tmp_ip;
    iph->ttl = 64;

    icmph->type = ICMP_ECHOREPLY;
    icmph->code = 0;

    icmp_len = ntohs(iph->tot_len) - ip_hdr_len;

    vnetif_update_icmp_checksum(icmph, icmp_len);
    vnetif_update_ip_checksum(iph);

    return 0;
}

static int vnetif_build_arp_reply(struct sk_buff *skb,
                                  struct net_device *dev)
{
    struct ethhdr *eth;
    struct arphdr *arp;
    struct vnetif_arp_eth_ipv4 *arp_data;
    struct vnetif_priv *priv;
    unsigned char requester_mac[ETH_ALEN];
    __be32 requester_ip;

    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ethhdr));

    if (skb->len < sizeof(struct ethhdr) +
                   sizeof(struct arphdr) +
                   sizeof(struct vnetif_arp_eth_ipv4))
        return -EINVAL;

    eth = eth_hdr(skb);
    if (!eth)
        return -EINVAL;

    arp = (struct arphdr *)skb_network_header(skb);
    if (!arp)
        return -EINVAL;

    arp_data = (struct vnetif_arp_eth_ipv4 *)(arp + 1);
    if (!arp_data)
        return -EINVAL;

    priv = netdev_priv(dev);

    memcpy(requester_mac, arp_data->sha, ETH_ALEN);
    requester_ip = arp_data->sip;

    memcpy(eth->h_dest, requester_mac, ETH_ALEN);
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    arp->ar_op = htons(ARPOP_REPLY);

    memcpy(arp_data->tha, requester_mac, ETH_ALEN);
    arp_data->tip = requester_ip;

    memcpy(arp_data->sha, dev->dev_addr, ETH_ALEN);
    arp_data->sip = priv->ipv4_addr;

    return 0;
}

static netdev_tx_t vnetif_rx_reply_local(struct sk_buff *skb,
                                         struct net_device *dev)
{
    struct ethhdr *eth = eth_hdr(skb);

    /*
     * If the reply is destined for our own MAC it is a local self-ping.
     * Deliver it directly via netif_rx so the host's IP stack receives it,
     * regardless of whether vnet0 happens to be a bridge slave.  Routing
     * through the bridge for a self-addressed frame would cause it to be
     * dropped (bridge does not loop frames back to itself on the xmit path).
     */
    if (ether_addr_equal(eth->h_dest, dev->dev_addr)) {
        /* Self-ping: deliver directly to the local IP stack. */
        skb->dev = dev;
        skb->ip_summed = CHECKSUM_NONE;
        skb->protocol = eth_type_trans(skb, dev);
        skb->pkt_type = PACKET_HOST;
        netif_rx(skb);
        return NETDEV_TX_OK;
    }

    /*
     * Remote reply: inject via netif_rx(vnet0) so the bridge RX path
     * learns vnet0's MAC on port vnet0 in its FDB.  Requires the bridge's
     * LOCAL FDB entry for vnet0's MAC to have been removed first
     * (the test script does this with "bridge fdb del <mac> dev vnet0 master").
     */
    skb->dev = dev;
    skb->ip_summed = CHECKSUM_NONE;
    skb->protocol = eth_type_trans(skb, dev);
    netif_rx(skb);

    return NETDEV_TX_OK;
}

static netdev_tx_t vnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct ethhdr *eth;
    struct net_device *master;
    int xmit_ret;
    int ret;

    if (!skb) {
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

    skb_reset_mac_header(skb);
    skb_set_network_header(skb, sizeof(struct ethhdr));
    eth = eth_hdr(skb);

    /*
     * When we are a bridge slave, any non-self unicast frame queued for
     * transmission should be handed to the bridge for normal forwarding.
     * Relying on the source MAC being exactly dev->dev_addr is too strict:
     * the host stack may emit replies after bridge/local delivery with a
     * different L2 source context, and dropping those breaks remote ping.
     * Self-addressed frames (standalone self-ping) still fall through to the
     * custom handlers below.
     */
    if (!ether_addr_equal(eth->h_dest, dev->dev_addr) &&
        !is_multicast_ether_addr(eth->h_dest)) {
        rcu_read_lock();
        master = netdev_master_upper_dev_get_rcu(dev);
        if (master)
            dev_hold(master);
        rcu_read_unlock();

        if (master) {
            dev->stats.tx_packets++;
            dev->stats.tx_bytes += skb->len;
            skb->dev = master;
            skb->ip_summed = CHECKSUM_NONE;
            skb->protocol = eth->h_proto;
            xmit_ret = dev_queue_xmit(skb);
            if (xmit_ret)
                pr_err("vnetif: bridge xmit failed on %s: %d\n",
                       dev->name, xmit_ret);
            dev_put(master);
            return NETDEV_TX_OK;
        }
    }

    if (vnetif_should_reply_arp(skb, dev)) {
        ret = vnetif_build_arp_reply(skb, dev);
        if (ret) {
            pr_info("vnetif: failed to build ARP reply on %s, ret=%d\n",
                    dev->name, ret);
            dev_kfree_skb(skb);
            dev->stats.tx_dropped++;
            return NETDEV_TX_OK;
        }

        dev->stats.tx_packets++;
        dev->stats.tx_bytes += skb->len;
        dev->stats.rx_packets++;
        dev->stats.rx_bytes += skb->len;

        return vnetif_rx_reply_local(skb, dev);
    }

    if (vnetif_should_reply_icmp_echo(skb, dev)) {
        ret = vnetif_build_icmp_echo_reply(skb, dev);
        if (ret) {
            pr_info("vnetif: failed to build ICMP echo reply on %s, ret=%d\n",
                    dev->name, ret);
            dev_kfree_skb(skb);
            dev->stats.tx_dropped++;
            return NETDEV_TX_OK;
        }

        dev->stats.tx_packets++;
        dev->stats.tx_bytes += skb->len;
        dev->stats.rx_packets++;
        dev->stats.rx_bytes += skb->len;

        return vnetif_rx_reply_local(skb, dev);
    }

    dev_kfree_skb(skb);
    dev->stats.tx_dropped++;
    return NETDEV_TX_OK;
}

static const struct net_device_ops vnet_netdev_ops = {
    .ndo_open       = vnet_open,
    .ndo_stop       = vnet_stop,
    .ndo_start_xmit = vnet_xmit,
};

static void vnet_setup(struct net_device *dev)
{
    ether_setup(dev);
    dev->netdev_ops = &vnet_netdev_ops;
    eth_hw_addr_random(dev);
    netif_carrier_on(dev);
}

static struct vnetif_dev *vnetif_find_locked(const char *name)
{
    struct vnetif_dev *entry;

    list_for_each_entry(entry, &vnetif_list, list) {
        if (strcmp(entry->netdev->name, name) == 0)
            return entry;
    }

    return NULL;
}

static int vnetif_set_link_up(struct net_device *dev)
{
    int ret;

    rtnl_lock();
    ret = dev_open(dev, NULL);
    rtnl_unlock();

    if (ret)
        pr_err("vnetif: failed to bring %s up: %d\n", dev->name, ret);
    else
        pr_info("vnetif: %s brought up automatically\n", dev->name);

    return ret;
}

static int vnetif_run_cmd(char **argv)
{
    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        NULL
    };
    int ret;

    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if (ret == 0)
        return 0;

    if (ret < 0)
        return ret;

    pr_err("vnetif: command %s exited with wait status %d\n", argv[0], ret);
    return -EINVAL;
}

static int vnetif_apply_ipv4_userspace(const char *ifname, const char *ip_str)
{
    char addr_cidr[48];
    char *argv_addr[] = {
        "/usr/sbin/ip",
        "addr",
        "replace",
        addr_cidr,
        "dev",
        (char *)ifname,
        NULL
    };
    char *argv_addr_fallback[] = {
        "/sbin/ip",
        "addr",
        "replace",
        addr_cidr,
        "dev",
        (char *)ifname,
        NULL
    };
    char *argv_link[] = {
        "/usr/sbin/ip",
        "link",
        "set",
        "dev",
        (char *)ifname,
        "up",
        NULL
    };
    char *argv_link_fallback[] = {
        "/sbin/ip",
        "link",
        "set",
        "dev",
        (char *)ifname,
        "up",
        NULL
    };
    int ret;

    snprintf(addr_cidr, sizeof(addr_cidr), "%s%s", ip_str, VNETIF_CIDR_SUFFIX);

    ret = vnetif_run_cmd(argv_addr);
    if (ret)
        ret = vnetif_run_cmd(argv_addr_fallback);
    if (ret) {
        pr_err("vnetif: failed to configure IPv4 on %s, ret=%d\n",
               ifname, ret);
        return ret;
    }

    ret = vnetif_run_cmd(argv_link);
    if (ret)
        ret = vnetif_run_cmd(argv_link_fallback);
    if (ret) {
        pr_err("vnetif: failed to set %s up via ip tool, ret=%d\n",
               ifname, ret);
        return ret;
    }

    pr_info("vnetif: configured %s with IPv4 %s\n", ifname, addr_cidr);
    return 0;
}

static int vnetif_create_locked(void)
{
    struct net_device *dev;
    struct vnetif_dev *entry;
    struct vnetif_priv *priv;
    int ret;

    dev = alloc_netdev(sizeof(struct vnetif_priv),
                       "vnet%d",
                       NET_NAME_UNKNOWN,
                       vnet_setup);
    if (!dev)
        return -ENOMEM;

    priv = netdev_priv(dev);
    priv->if_id = next_if_id++;
    priv->ipv4_addr = 0;

    ret = register_netdev(dev);
    if (ret) {
        free_netdev(dev);
        return ret;
    }

    ret = vnetif_set_link_up(dev);
    if (ret) {
        unregister_netdev(dev);
        free_netdev(dev);
        return ret;
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        unregister_netdev(dev);
        free_netdev(dev);
        return -ENOMEM;
    }

    entry->netdev = dev;
    list_add_tail(&entry->list, &vnetif_list);

    pr_info("vnetif: created interface %s\n", dev->name);
    return 0;
}

static int vnetif_destroy_one_locked(const char *name)
{
    struct vnetif_dev *entry;

    entry = vnetif_find_locked(name);
    if (!entry)
        return -ENOENT;

    list_del(&entry->list);
    unregister_netdev(entry->netdev);
    free_netdev(entry->netdev);
    kfree(entry);

    pr_info("vnetif: removed interface %s\n", name);
    return 0;
}

static int vnetif_validate_ipv4_locked(const char *name, const char *ip_str,
                                       char *ifname_out,
                                       size_t ifname_out_len)
{
    struct vnetif_dev *entry;
    __be32 addr;

    entry = vnetif_find_locked(name);
    if (!entry)
        return -ENOENT;

    if (!in4_pton(ip_str, -1, (u8 *)&addr, -1, NULL))
        return -EINVAL;

    strscpy(ifname_out, entry->netdev->name, ifname_out_len);
    return 0;
}

static int vnetif_set_ipv4_locked(const char *name, const char *ip_str)
{
    struct vnetif_dev *entry;
    struct vnetif_priv *priv;
    __be32 addr;

    entry = vnetif_find_locked(name);
    if (!entry)
        return -ENOENT;

    if (!in4_pton(ip_str, -1, (u8 *)&addr, -1, NULL))
        return -EINVAL;

    priv = netdev_priv(entry->netdev);
    priv->ipv4_addr = addr;

    pr_info("vnetif: %s ipv4 set to %pI4\n", name, &priv->ipv4_addr);
    return 0;
}

static void vnetif_destroy_all_locked(void)
{
    struct vnetif_dev *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &vnetif_list, list) {
        list_del(&entry->list);
        unregister_netdev(entry->netdev);
        free_netdev(entry->netdev);
        kfree(entry);
    }
}

static ssize_t vnetif_list_read(struct file *file, char __user *buffer,
                                size_t count, loff_t *ppos)
{
    char *kbuf;
    size_t len = 0;
    struct vnetif_dev *entry;
    struct vnetif_priv *priv;
    ssize_t ret;

    if (*ppos != 0)
        return 0;

    kbuf = kzalloc(VNETIF_READ_BUF_SZ, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mutex_lock(&vnetif_lock);

    list_for_each_entry(entry, &vnetif_list, list) {
        priv = netdev_priv(entry->netdev);

        if (priv->ipv4_addr) {
            len += scnprintf(kbuf + len, VNETIF_READ_BUF_SZ - len,
                             "%s %pI4\n",
                             entry->netdev->name,
                             &priv->ipv4_addr);
        } else {
            len += scnprintf(kbuf + len, VNETIF_READ_BUF_SZ - len,
                             "%s -\n",
                             entry->netdev->name);
        }

        if (len >= VNETIF_READ_BUF_SZ - 1)
            break;
    }

    mutex_unlock(&vnetif_lock);

    ret = simple_read_from_buffer(buffer, count, ppos, kbuf, len);
    kfree(kbuf);

    return ret;
}

static ssize_t vnetif_add_write(struct file *file, const char __user *buffer,
                                size_t count, loff_t *ppos)
{
    int ret;

    mutex_lock(&vnetif_lock);
    ret = vnetif_create_locked();
    mutex_unlock(&vnetif_lock);

    if (ret)
        return ret;

    return count;
}

static ssize_t vnetif_del_write(struct file *file, const char __user *buffer,
                                size_t count, loff_t *ppos)
{
    char kbuf[VNETIF_CMD_BUF_SZ];
    int ret;

    if (count == 0)
        return 0;

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buffer, count))
        return -EFAULT;

    kbuf[count] = '\0';
    strim(kbuf);

    if (kbuf[0] == '\0')
        return -EINVAL;

    mutex_lock(&vnetif_lock);
    ret = vnetif_destroy_one_locked(kbuf);
    mutex_unlock(&vnetif_lock);

    if (ret)
        return ret;

    return count;
}

static ssize_t vnetif_ipv4_write(struct file *file, const char __user *buffer,
                                 size_t count, loff_t *ppos)
{
    char kbuf[VNETIF_CMD_BUF_SZ];
    char ifname[IFNAMSIZ] = {0};
    char ip_str[32] = {0};
    int parsed;
    int ret;

    if (count == 0)
        return 0;

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, buffer, count))
        return -EFAULT;

    kbuf[count] = '\0';
    strim(kbuf);

    parsed = sscanf(kbuf, "%15s %31s", ifname, ip_str);
    if (parsed != 2)
        return -EINVAL;

    mutex_lock(&vnetif_lock);
    ret = vnetif_validate_ipv4_locked(ifname, ip_str, ifname, sizeof(ifname));
    mutex_unlock(&vnetif_lock);
    if (ret)
        return ret;

    ret = vnetif_apply_ipv4_userspace(ifname, ip_str);
    if (ret)
        return ret;

    mutex_lock(&vnetif_lock);
    ret = vnetif_set_ipv4_locked(ifname, ip_str);
    mutex_unlock(&vnetif_lock);
    if (ret)
        return ret;

    return count;
}

static int __init vnetif_init(void)
{
    int ret;

    next_if_id = 0;

    proc_list_entry = proc_create(VNETIF_LIST_PROC_NAME, 0444, NULL,
                                  &vnetif_list_proc_ops);
    if (!proc_list_entry)
        return -ENOMEM;

    proc_add_entry = proc_create(VNETIF_ADD_PROC_NAME, 0222, NULL,
                                 &vnetif_add_proc_ops);
    if (!proc_add_entry)
        goto err_remove_list;

    proc_del_entry = proc_create(VNETIF_DEL_PROC_NAME, 0222, NULL,
                                 &vnetif_del_proc_ops);
    if (!proc_del_entry)
        goto err_remove_add;

    proc_ipv4_entry = proc_create(VNETIF_IPV4_PROC_NAME, 0222, NULL,
                                  &vnetif_ipv4_proc_ops);
    if (!proc_ipv4_entry)
        goto err_remove_del;

    mutex_lock(&vnetif_lock);
    ret = vnetif_create_locked();
    mutex_unlock(&vnetif_lock);
    if (ret)
        goto err_remove_ipv4;

    pr_info("vnetif: module loaded\n");
    return 0;

err_remove_ipv4:
    proc_remove(proc_ipv4_entry);
    proc_ipv4_entry = NULL;
err_remove_del:
    proc_remove(proc_del_entry);
    proc_del_entry = NULL;
err_remove_add:
    proc_remove(proc_add_entry);
    proc_add_entry = NULL;
err_remove_list:
    proc_remove(proc_list_entry);
    proc_list_entry = NULL;
    return ret;
}

static void __exit vnetif_exit(void)
{
    mutex_lock(&vnetif_lock);
    vnetif_destroy_all_locked();
    mutex_unlock(&vnetif_lock);

    if (proc_ipv4_entry) {
        proc_remove(proc_ipv4_entry);
        proc_ipv4_entry = NULL;
    }

    if (proc_del_entry) {
        proc_remove(proc_del_entry);
        proc_del_entry = NULL;
    }

    if (proc_add_entry) {
        proc_remove(proc_add_entry);
        proc_add_entry = NULL;
    }

    if (proc_list_entry) {
        proc_remove(proc_list_entry);
        proc_list_entry = NULL;
    }

    pr_info("vnetif: module unloaded\n");
}

module_init(vnetif_init);
module_exit(vnetif_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arayik Gharibyan");
MODULE_DESCRIPTION("Virtual network interface kernel module with procfs control, local ICMP echo handling and basic ARP reply");
MODULE_VERSION("1.0");
