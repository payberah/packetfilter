#define MODULE
#define __KERNEL__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <asm/types.h>
#include <asm/uaccess.h>

#define DEVICE_NAME "char_dev"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("payberah@yahoo.com");
//------------------------------------------------

int major;
int device_open(struct inode *, struct file *);
int device_release(struct inode *, struct file *);
ssize_t device_write(struct file *, const char *, size_t length, loff_t *);
extern int (*packet_drop)(struct sk_buff *);

struct file_operations fops = {
    owner   : THIS_MODULE,
    write   : device_write,
    open    : device_open,
    release : device_release
};

struct Rule {
    __u32 srcIp;
    __u32 dstIp;
    __u16 srcPort;
    __u16 dstPort;
    __u8 proto;
};

struct Filter {
    struct Rule rule;
    int deny;
};

struct Tuple {
    int srcIpLen;
    int dstIpLen;
    int srcPortLen;
    int dstPortLen;
    int protoLen;
};

struct TupleSpace {
    struct Tuple tuple;
    struct Filter filter[20];
    int count;
    struct TupleSpace *next;
};

struct Filter filter;
struct Tuple tuple;
struct TupleSpace *ptr, *first;
int flag = 0;
int count = 0;

//------------------------------------------------
void show_str(__u8 *str, int len) {
    int i;
    printk("<1>command: ");
    for (i = 0; i < len; i++)
	printk("%x ", str[i]);
    printk("\n");
    return;
}

//------------------------------------------------
int device_open(struct inode *inode, struct file *file) {
    printk("\ndevice_open ...\n");
    return 0;
}

//------------------------------------------------
int device_release(struct inode *inode, struct file *file) {
    return 0;
}

//------------------------------------------------
ssize_t device_write(struct file *file, const char *buffer, size_t length, loff_t *offset) {
    if (first == NULL) {
	if ((ptr = kmalloc(sizeof(struct TupleSpace), GFP_KERNEL)) == NULL) {
	    packet_drop = 0;
	    printk("<1>\nnot enough memory ...\n");
	    return 1;
	}

	ptr->next = NULL;
	first = ptr;
    }

    if (flag == 0) {
	copy_from_user(&(ptr->tuple), buffer, sizeof(tuple));
	flag = 1;
    } else {
	copy_from_user(&(ptr->filter[count]), buffer, sizeof(filter));
	if (ptr->filter[count].rule.srcIp == 0 && 
	    ptr->filter[count].rule.dstIp == 0 && 
	    ptr->filter[count].rule.srcPort == 0 &&
	    ptr->filter[count].rule.dstPort == 0 && 
	    ptr->filter[count].rule.proto == 0) {
	    if ((ptr->next = kmalloc(sizeof(struct TupleSpace), GFP_KERNEL)) == NULL) {
	        packet_drop = 0;
	        printk("<1>\nnot enough memory ...\n");
	        return 1;
	    }
	    ptr->count = count;
	    ptr = ptr->next;
	    ptr->next = NULL;
	    count = 0;
	    flag = 0;
	} else
	    count++;
    }

    return -EINVAL;
}

//------------------------------------------------
int drop(struct sk_buff *skb) {
    int i, j;
    int mask1, mask2;
    struct Rule packet, tempPacket;

    packet.srcIp = skb->nh.iph->saddr;
    packet.dstIp = skb->nh.iph->daddr;
    packet.srcPort = skb->h.th->source;
    packet.dstPort = skb->h.th->dest;
    packet.proto = 0;

    if (ptr != NULL) {
        for (ptr = first; ptr->next != NULL; ptr = ptr->next) {
	    tempPacket = packet;

	    mask1 = ptr->tuple.srcIpLen;
	    mask2 = ptr->tuple.dstIpLen;

	    if (mask1 == 24)
		tempPacket.srcIp &= 0x00ffffff;
	    else if (mask1 == 16)
		tempPacket.srcIp &= 0x0000ffff;
	    else if (mask1 == 8)
		tempPacket.srcIp &= 0x000000ff;
	    else if (mask1 == 0)
		tempPacket.srcIp &= 0x00000000;

	    if (mask2 == 24)
		tempPacket.dstIp &= 0x00ffffff;
	    else if (mask2 == 16)
		tempPacket.dstIp &= 0x0000ffff;
	    else if (mask2 == 8)
		tempPacket.dstIp &= 0x000000ff;
	    else if (mask2 == 0)
		tempPacket.dstIp &= 0x00000000;
	
	for (j = 0; j < ptr->count; j++) {
	    if (ptr->filter[j].deny) {
		if ((tempPacket.srcIp == ptr->filter[j].rule.srcIp || ptr->filter[j].rule.srcIp == 0) &&
		    (tempPacket.dstIp == ptr->filter[j].rule.dstIp || ptr->filter[j].rule.dstIp == 0) &&
		    (tempPacket.srcPort == ptr->filter[j].rule.srcPort || ptr->filter[j].rule.srcPort == 0) &&
		    (tempPacket.dstPort == ptr->filter[j].rule.dstPort || ptr->filter[j].rule.dstPort == 0) &&
		    (tempPacket.proto == ptr->filter[j].rule.proto || ptr->filter[j].rule.proto == 0))
	    	    return 1;
	    } else {
		if ((tempPacket.srcIp == ptr->filter[j].rule.srcIp || ptr->filter[j].rule.srcIp == 0) &&
		    (tempPacket.dstIp == ptr->filter[j].rule.dstIp || ptr->filter[j].rule.dstIp == 0) &&
		    (tempPacket.srcPort == ptr->filter[j].rule.srcPort || ptr->filter[j].rule.srcPort == 0) &&
		    (tempPacket.dstPort == ptr->filter[j].rule.dstPort || ptr->filter[j].rule.dstPort == 0) &&
		    (tempPacket.proto == ptr->filter[j].rule.proto || ptr->filter[j].rule.proto == 0))
	    	    return 0;
	    }
	}
    }

    return 0; // default accept
}

//------------------------------------------------
int init_module() {
    ptr = first = NULL;
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
	printk("<1>\ndevice failed with %d\n", major);
	return major;
    }

    packet_drop = drop;

    printk("<1>\npacket filetr is installed ...\n");
    printk("<1>mknod /dev/test c %d 0\n", major);
    return 0;
}

//------------------------------------------------
void cleanup_module() {
    int ret;
    packet_drop = 0;

    ptr = first;
    while (1) {
	if (ptr == NULL)
	    break;
	else
	    ptr = ptr->next;
	kfree(first);
	first = ptr;
    }
    
    ret = unregister_chrdev(major, DEVICE_NAME);

    if (ret < 0)
	printk("<1>\nError in unregister_chrdev: %d\n", ret);
    else
	printk("<1>\npacket filetr is Uninstalled ...\n");
}
