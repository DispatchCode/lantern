#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>

#define DEVICE_NAME "packet_sniffer"
#define CLASS_NAME "packet_sniffer_class"
#define BUFFER_SIZE 4096
#define IP_BUFF_SIZE 16

static wait_queue_head_t wait_queue;
static struct nf_hook_ops nf_ops;
static dev_t dev_num;
static struct cdev char_dev;

static char buffer[BUFFER_SIZE];
static int buffer_index = 0;
static DEFINE_MUTEX(buffer_mutex);
static int data_ready = 0;

static struct class *packet_class = NULL;
static struct device *packet_device = NULL;

static ssize_t device_read(struct file *file, char __user *user_buffer, size_t len, loff_t *offset);
static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);

static struct file_operations f_ops = {
    .owner = THIS_MODULE,
    .read = device_read,
    .open = device_open,
    .release = device_release,
};

static int device_open(struct inode *inode, struct file *file) {
    pr_info("packet_sniffer: Device opened\n");
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    pr_info("packet_sniffer: Device closed\n");
    return 0;
}

static ssize_t device_read(struct file *file, char __user *user_buffer, size_t len, loff_t *offset) {
    int size_to_copy;

    if (wait_event_interruptible(wait_queue, data_ready)) {
        return -ERESTARTSYS;
    }

    if (mutex_lock_interruptible(&buffer_mutex)) {
        return -ERESTARTSYS;
    }

    size_to_copy = min(buffer_index, (int)len);
    if (copy_to_user(user_buffer, buffer, size_to_copy)) {
        mutex_unlock(&buffer_mutex);
        return -EFAULT;
    }

    buffer_index = 0;
    data_ready = 0;
    mutex_unlock(&buffer_mutex);

    return size_to_copy;
}

static unsigned int capture(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    char src_ip[IP_BUFF_SIZE], dest_ip[IP_BUFF_SIZE];
    int bytes_written, remaining_space;

    if (skb->protocol != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }

    rcu_read_lock(); // Start RCU read-side critical section
    ip_header = ip_hdr(skb);

    scnprintf(src_ip, IP_BUFF_SIZE, "%pI4", &ip_header->saddr);
    scnprintf(dest_ip, IP_BUFF_SIZE, "%pI4", &ip_header->daddr);

    if (mutex_trylock(&buffer_mutex)) { // Use non-blocking lock to avoid sleeping
        remaining_space = BUFFER_SIZE - buffer_index;

        if (remaining_space <= 0) {
            buffer_index = 0;
            memset(buffer, 0, BUFFER_SIZE);
            pr_info("packet_sniffer: Cleaning buffer...\n");
            remaining_space = BUFFER_SIZE;
        }

        bytes_written = scnprintf(buffer + buffer_index, remaining_space, "Packet: %s -> %s\n", src_ip, dest_ip);
        buffer_index += bytes_written;
        remaining_space -= bytes_written;

        if (remaining_space > 0) {
            switch (ip_header->protocol) {
                case IPPROTO_TCP:
                    tcp_header = tcp_hdr(skb);
                    bytes_written = scnprintf(buffer + buffer_index, remaining_space, "TCP: %s:%d -> %s:%d\n",
                        src_ip, ntohs(tcp_header->source), dest_ip, ntohs(tcp_header->dest));
                    buffer_index += bytes_written;
                    remaining_space -= bytes_written;
                    break;
                case IPPROTO_UDP:
                    udp_header = udp_hdr(skb);
                    bytes_written = scnprintf(buffer + buffer_index, remaining_space, "UDP: %s:%d -> %s:%d\n",
                        src_ip, ntohs(udp_header->source), dest_ip, ntohs(udp_header->dest));
                    buffer_index += bytes_written;
                    remaining_space -= bytes_written;
                    break;
                default:
                    break;
            }
        }

        data_ready = 1;
        mutex_unlock(&buffer_mutex);
        wake_up_interruptible(&wait_queue);
    }

    rcu_read_unlock(); // End RCU read-side critical section

    return NF_ACCEPT;
}

static int __init packet_sniffer_init(void) {
    int ret;

    init_waitqueue_head(&wait_queue);

    nf_ops.hook = capture;
    nf_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_ops.pf = PF_INET;
    nf_ops.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nf_ops);
    if (ret) {
        pr_err("packet_sniffer: Netfilter registration failed\n");
        return ret;
    }

    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret) {
        pr_err("packet_sniffer: Character device region allocation failed\n");
        goto err_nf_unregister_net_hook;
    }

    cdev_init(&char_dev, &f_ops);
    char_dev.owner = THIS_MODULE;

    ret = cdev_add(&char_dev, dev_num, 1);
    if (ret) {
        pr_err("packet_sniffer: Failed to add character device\n");
        goto err_unregister_chrdev_region;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    packet_class = class_create(CLASS_NAME);
#else
    packet_class = class_create(THIS_MODULE, CLASS_NAME);
#endif

    if (IS_ERR(packet_class)) {
        pr_err("packet_sniffer: Failed to create device class\n");
        ret = PTR_ERR(packet_class);
        goto err_cdev_del;
    }

    packet_device = device_create(packet_class, NULL, dev_num, NULL, DEVICE_NAME);

    if (IS_ERR(packet_device)) {
        pr_err("packet_sniffer: Failed to create device\n");
        ret = PTR_ERR(packet_device);
        goto err_class_destroy;
    }

    pr_info("packet_sniffer: Module loaded\n");

    return 0;

err_class_destroy:
    class_destroy(packet_class);
err_cdev_del:
    cdev_del(&char_dev);
err_unregister_chrdev_region:
    unregister_chrdev_region(dev_num, 1);
err_nf_unregister_net_hook:
    nf_unregister_net_hook(&init_net, &nf_ops);

    return ret;
}

static void __exit packet_sniffer_exit(void) {
    device_destroy(packet_class, dev_num);
    class_unregister(packet_class);
    class_destroy(packet_class);
    cdev_del(&char_dev);
    unregister_chrdev_region(dev_num, 1);
    nf_unregister_net_hook(&init_net, &nf_ops);

    pr_info("packet_sniffer: Module unloaded\n");
}

module_init(packet_sniffer_init);
module_exit(packet_sniffer_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("random_debil");
MODULE_DESCRIPTION("Packet sniffer and analyzer");
