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
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>

#include "packet_sniffer.h"

/* 
 * used to read incoming data along with wait_event_interruptible()
 * it will make the process sleep if there are no data
 * 
 */
static wait_queue_head_t wait_queue;

// netfilter hook operations
static struct nf_hook_ops nf_ops;

// packet filled in by the kernel
static struct net_packet buffer[BUFFER_SIZE];

// spinlock used in the capture() funciton
// mutex used in the device_read() function
static DEFINE_SPINLOCK(buffer_spinlock);
static DEFINE_MUTEX(buffer_mutex);

// there are new data?
static int data_ready = 0;
// index in buffer
static int packet_index = 0;

// Character device management
static struct class *packet_class = NULL;
static struct device *packet_device = NULL;
static struct cdev char_dev;
static dev_t dev_num;

//
// Character Device callbacks
//
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

/*
 * read new data and copy them to the user buffer
 * The task is awaken by the wait_event_interruptible() function
 *
 * IMPORTANT: we can sleep in this context!
 * 
 */

static ssize_t device_read(struct file *file, char __user *user_buffer, size_t len, loff_t *offset) {
	int size_to_copy, packet_size;

	if (wait_event_interruptible(wait_queue, data_ready)) {
		return -ERESTARTSYS;
	}

	if(mutex_lock_interruptible(&buffer_mutex)) {
		return -ERESTARTSYS;
	}

	packet_size = sizeof(struct net_packet);
	size_to_copy = min(packet_index * packet_size, (int)len);
	if (likely(copy_to_user(user_buffer, buffer, size_to_copy))) {
		mutex_unlock(&buffer_mutex);
		return -EFAULT;
	}

	packet_index = 0;
	data_ready = 0;
	mutex_unlock(&buffer_mutex);

	return size_to_copy;
}

static void fill_http_info(struct sk_buff *skb, struct tcphdr *tcp,  struct net_packet *pkt) {
	char *data = (char*)((unsigned char*) tcp + (tcp->doff << 2));
	int data_len = skb->len - ((unsigned char*)data - (unsigned char*) ip_hdr(skb));

	if(data_len <= 0) {
		return;
	}

	pr_info("fill_http_info\n");
	if(strncmp(data, "GET", 3) == 0 || strncmp(data, "POST", 4) == 0) {
		sscanf(data, "%7s", pkt->http_method);
		pr_info("REQUEST METHOD: %s", pkt->http_method);	
		char *host_ptr = strnstr(data, "Host:", data_len);
		if(host_ptr) {
			sscanf(host_ptr, "Host: %255s", pkt->hostname);
		}

		char *length_ptr = strnstr(data, "Content-Length:", data_len);
		if(length_ptr) {
			sscanf(length_ptr, "Content-Length: %d", &pkt->length);
		}

		char *body_ptr = strnstr(data, "\r\n\r\n", data_len);
		if(body_ptr) {
			body_ptr += 4;
			strncpy(pkt->http_body, body_ptr, min(HTTP_BODY_SIZE, data_len - (body_ptr - data)));
		}
	}
}

// read TCP / UDP header and collect IP informations
static struct net_packet fill_packet_info(struct sk_buff *skb, struct iphdr *ip_header) {
	struct net_packet pkt;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct timespec64 ts;

	ts = ktime_to_timespec64(skb->tstamp);

	pkt.skb_len = skb->len;
	pkt.protocol = ip_header->protocol;
	pkt.timestamp_sec = ts.tv_sec;
	pkt.timestamp_nsec = ts.tv_nsec;

	memcpy(&pkt.network, ip_header, sizeof(struct iphdr));	

	switch(pkt.protocol) {
		case IPPROTO_TCP:
			tcp_header = tcp_hdr(skb);
			memcpy(&pkt.transport, tcp_header, sizeof(struct tcphdr));
			fill_http_info(skb, tcp_header, &pkt);
			break;
		case IPPROTO_UDP:
			udp_header = udp_hdr(skb);
			memcpy(&pkt.transport, udp_header, sizeof(struct udphdr));
			break;
	}

	return pkt;
}

/*
 * Netfilter hook entry point
 *
 * spinlock to protect the buffer 
 * when data are available, the task waiting on the queue is woken up
 *
 * Better don't sleep here...
 *
 */
static unsigned int capture(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *ip_header;
	struct net_packet pkt;
	unsigned long flags;

	if (skb->protocol != htons(ETH_P_IP)) {
		return NF_ACCEPT;
	}

	ip_header = ip_hdr(skb);
	
	pkt = fill_packet_info(skb, ip_header);

	spin_lock_irqsave(&buffer_spinlock, flags);

	if(likely(packet_index < BUFFER_SIZE)) {
		memcpy(&buffer[packet_index++], &pkt, sizeof(struct net_packet));
		data_ready = 1;
		spin_unlock_irqrestore(&buffer_spinlock, flags);
		wake_up_interruptible(&wait_queue);
	}
	else {
		pr_info("packet_sniffer: Buffer is full, reset buffer...");
		memset(buffer, 0, BUFFER_SIZE);
		packet_index = 0;
		spin_unlock_irqrestore(&buffer_spinlock, flags);
	}

	return NF_ACCEPT;
}

#define CLASS_NAME "packet_sniffer_class"

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
MODULE_AUTHOR("Marco Crivellari");
MODULE_DESCRIPTION("Packet sniffer and analyzer");
