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

#define VNETIF_LIST_PROC_NAME  "vnetif"
#define VNETIF_ADD_PROC_NAME   "vnetif_add"
#define VNETIF_DEL_PROC_NAME   "vnetif_del"
#define VNETIF_IPV4_PROC_NAME  "vnetif_ipv4"

#define VNETIF_CMD_BUF_SZ   64
#define VNETIF_READ_BUF_SZ  1024

struct vnetif_priv {
    int if_id;
    __be32 ipv4_addr;
};

struct vnetif_dev {
    struct net_device *netdev;
    struct list_head list;
};

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
static int vnetif_set_ipv4_locked(const char *name, const char *ip_str);
static void vnetif_destroy_all_locked(void);

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
    pr_info("%s: interface opened\n", dev->name);
    return 0;
}

static int vnet_stop(struct net_device *dev)
{
    netif_stop_queue(dev);
    pr_info("%s: interface stopped\n", dev->name);
    return 0;
}

static netdev_tx_t vnet_xmit(struct sk_buff *skb, struct net_device *dev)
{
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
    dev->flags |= IFF_NOARP;
    eth_hw_addr_random(dev);
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
    return -ENOMEM;
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
MODULE_DESCRIPTION("Virtual network interface kernel module with procfs control");
MODULE_VERSION("1.0");