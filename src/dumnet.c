#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h> 		// printk()
#include <linux/slab.h>			// kmalloc()
#include <linux/errno.h>		// error codes
#include <linux/types.h>		// size_t
#include <linux/in.h>
#include <linux/netdevice.h>	// struct deivce and other headers
#include <linux/etherdevice.h>	// eth_type_trans
#include <linux/ip.h>			// struct iphdr
#include <linux/tcp.h>			// struct tcphdr
#include <linux/skbuff.h>
#include <linux/version.h>

#include "common.h"
#include "dumnet.h"

// https://github.com/duxing2007/ldd3-examples-3.x/blob/origin/linux-4.9.y/snull/snull.c

MODULE_LICENSE("GPL");
MODULE_AUTHOR("amscw");

//-------------------------------------------------------------------------------------------------
// MACRO
//-------------------------------------------------------------------------------------------------
#define POOL_SIZE	8

//-------------------------------------------------------------------------------------------------
// Types
//-------------------------------------------------------------------------------------------------
struct dumPacket_
{
	struct dumPacket_ *pNext;
	struct net_device *pDev;
	int datalen;
	u8 data[ETH_DATA_LEN];
};

struct dumPriv_ {
	struct net_device *pDev;
	struct net_device_stats stats;
	int status;
	struct dumPacket_ *pPool;			// pointer to last item in list
	struct dumPacket_ *pRxQueue;		// List of incoming packets 
	int bIsRxIntEnabled;
	int txPacketLen;
	u8 *pTxPacketData;
	struct sk_buff *pSkB;
	spinlock_t lock;
	struct net_device *pdev;
};

//-------------------------------------------------------------------------------------------------
// Prototypes
//-------------------------------------------------------------------------------------------------
static int dumOpen(struct net_device *pDev); 
static int dumClose(struct net_device *pDev);
static int dumConfig(struct net_device *pDev, struct ifmap *pMap);
static int dumTxPkt(struct sk_buff *pSkB, struct net_device *pDev);
static int dumIoctl(struct net_device *pDev, struct ifreq *pReq, int cmd);
static int dumChangeMTU(struct net_device *pDev, int newMTU);
static void dumTxTimeout (struct net_device *pDev);
static struct net_device_stats *dumStats(struct net_device *pDev);
static int dumHeader(struct sk_buff *pSkB, struct net_device *pDev, unsigned short type, 
	const void *pDAddr, const void *pSAddr, unsigned len);

//-------------------------------------------------------------------------------------------------
// Varibles
//-------------------------------------------------------------------------------------------------
struct net_device *dummyDevs[2];
static void (*dummyNetdevInterrupt)(int, void *, struct pt_regs *);
static const struct net_device_ops dummyNetdevOps = {
	.ndo_open            = dumOpen,
	.ndo_stop            = dumClose,
	.ndo_start_xmit      = dumTxPkt,
	.ndo_do_ioctl        = dumIoctl,
	.ndo_set_config      = dumConfig,
	.ndo_get_stats       = dumStats,
	.ndo_change_mtu      = dumChangeMTU,
	.ndo_tx_timeout      = dumTxTimeout
};
static const struct header_ops dummyHeaderOps = {
    .create  = dumHeader,
    .cache = NULL,
};
static int timeout = DUMMY_NETDEV_TIMEOUT;
static unsigned long transStart;

//-------------------------------------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------------------------------------
/*
 * Packet management functions
 */
static void createPool(struct net_device *pDev)
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	int i;
	struct dumPacket_ *pPkt;

	pPriv->pPool = NULL;
	for (i = 0; i < POOL_SIZE; i++)
	{
		pPkt = kmalloc(sizeof (struct dumPacket_), GFP_KERNEL);
		if (pPkt == NULL)
		{
			PRINT_STATUS_MSG("cannot allocate packet #%i (%ld bytes)", -ENOMEM, i, sizeof (struct dumPacket_));
			return;
		}
		pPkt->pDev = pDev;
		pPkt->pNext = pPriv->pPool;
		pPriv->pPool = pPkt;
	}
}

static void destroyPool(struct net_device *pDev) 
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	struct dumPacket_ *pPkt;

	while((pPkt = pPriv->pPool)) {
		pPriv->pPool = pPkt->pNext;
		kfree(pPkt);
		// FIXME: in-flight packets (currently used)?
	}
}

static struct dumPacket_ * getPkt(struct net_device *pDev)
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	unsigned long flags = 0;
	struct dumPacket_ *pPkt;

	spin_lock_irqsave(&pPriv->lock, flags);
	pPkt = pPriv->pPool;
	if (pPkt == NULL)
	{
		PRINT_STATUS_MSG("pool is empty", -1);
		netif_stop_queue(pDev);
	} else {
		pPriv->pPool = pPkt->pNext;
		pPkt->pNext = NULL;
	}
	spin_unlock_irqrestore(&pPriv->lock, flags);
	return pPkt;
}

static void freePkt(struct dumPacket_ *pPkt)
{
	unsigned long flags = 0;
	struct dumPriv_ *pPriv;

	if (pPkt != NULL)
	{
		pPriv = netdev_priv(pPkt->pDev);
		spin_lock_irqsave(&pPriv->lock, flags);
		pPkt->pNext = pPriv->pPool;
		pPriv->pPool = pPkt;
		spin_unlock_irqrestore(&pPriv->lock, flags);
		if (netif_queue_stopped(pPkt->pDev) && pPkt->pNext == NULL)
			netif_wake_queue(pPkt->pDev);
	}
}

static void enqueuePkt(struct net_device *pDev, struct dumPacket_ *pPkt)
{
	unsigned long flags = 0;
	struct dumPriv_ *pPriv = netdev_priv(pDev);

	spin_lock_irqsave(&pPriv->lock, flags);
	pPkt->pNext=pPriv->pRxQueue;
	pPriv->pRxQueue=pPkt;
	spin_unlock_irqrestore(&pPriv->lock, flags);
}

static struct dumPacket_ *dequeuePkt(struct net_device *pDev)
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	struct dumPacket_ *pPkt;
	unsigned long flags = 0;
	spin_lock_irqsave(&pPriv->lock, flags);
	pPkt = pPriv->pRxQueue;
	if (pPkt != NULL)
	{
		pPriv->pRxQueue = pPkt->pNext;
		pPkt->pNext = NULL;
	}
	spin_unlock_irqrestore(&pPriv->lock, flags);
	return pPkt;
}

/*
 * Net device functionality
 */
static void rxIntEn(struct net_device *pDev, int bIsEnable)
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	pPriv->bIsRxIntEnabled = bIsEnable;
}

static void rxPkt(struct net_device *pDev, struct dumPacket_ *pPkt)
{
	struct sk_buff *pSkB;
	struct dumPriv_ *pPriv = netdev_priv(pDev);

	// The packet has been retrived from transmission medium.
	// Build an skb around it, so upper layers can handle it
	pSkB = dev_alloc_skb(pPkt->datalen + 2);
	if (pSkB == NULL)
	{
		if (printk_ratelimit())
			PRINT_STATUS_MSG("cannot allocate socket buffer, packet dropped", -ENOMEM);
		pPriv->stats.rx_dropped++;
		return;			
	}
	skb_reserve(pSkB, 2); // align IP on 16-bit boundary
	memcpy(skb_put(pSkB, pPkt->datalen), pPkt->data, pPkt->datalen);

	// Write metadata, and then pass to the receive level
	pSkB->dev = pDev;
	pSkB->protocol = eth_type_trans(pSkB, pDev);
	pSkB->ip_summed = CHECKSUM_UNNECESSARY;
	pPriv->stats.rx_packets++;
	pPriv->stats.rx_bytes += pPkt->datalen;
	netif_rx(pSkB);
}

static void txPktByHW(char *pBuf, int len, struct net_device *pDev)
{
	// This function deals with hw details. This interface loops back the packet to the other dummy interface (if any).
	// In other words, this function implements the dummy-device behaviour, while all other procedures are rather device-independent
	struct iphdr *pIP;
	struct net_device *pDest;
	struct dumPriv_ *pPriv;
	u32 *pSAddr, *pDAddr;
	struct dumPacket_ *pTxBuffer;
    
	// I am paranoid. Ain't I?
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
	{
		PRINT_STATUS_MSG("packet too short (%i octets)", -1, len);
		return;
	}

	if (1) { /* enable this conditional to look at the data */
		int i;
		PDEBUG("len is %i\n" KERN_DEBUG "data:", len);
		for (i=14; i<len; i++)
			printk(" %02x", pBuf[i]&0xff);
		printk("\n");
	}

	// Ethhdr is 14 bytes, but the kernel arranges for iphdr
	pIP = (struct iphdr *)(pBuf + sizeof(struct ethhdr));
	pSAddr = &pIP->saddr;
	pDAddr = &pIP->daddr;

	((u8 *)pSAddr)[2] ^= 1; // change the third octet (class C)
	((u8 *)pDAddr)[2] ^= 1;

	pIP->check = 0;         // and rebuild the checksum (ip needs it)
	pIP->check = ip_fast_csum((unsigned char *)pIP, pIP->ihl);

	if (pDev == dummyDevs[0])
		PDEBUG("%08x:%05i --> %08x:%05i\n",
				ntohl(pIP->saddr), ntohs(((struct tcphdr *)(pIP+1))->source),
				ntohl(pIP->daddr), ntohs(((struct tcphdr *)(pIP+1))->dest));
	else
		PDEBUG("%08x:%05i <-- %08x:%05i\n",
				ntohl(pIP->daddr), ntohs(((struct tcphdr *)(pIP+1))->dest),
				ntohl(pIP->saddr), ntohs(((struct tcphdr *)(pIP+1))->source));

	
	// Ok, now the packet is ready for transmission: first simulate a receive interrupt 
	// on the twin device, then a transmission-done on the transmitting device
	pDest = dummyDevs[pDev == dummyDevs[0] ? 1 : 0];
	pPriv = netdev_priv(pDest);
	pTxBuffer = getPkt(pDev);
	pTxBuffer->datalen = len;
	
	// fake transmit packet
	memcpy(pTxBuffer->data, pBuf, len);

	// fake receive packet
	enqueuePkt(pDest, pTxBuffer);	
	if (pPriv->bIsRxIntEnabled) {
		pPriv->status |= DUMMY_NETDEV_TX_INTR;
		dummyNetdevInterrupt(0, pDest, NULL);
	}

	// terminate transmission
	pPriv = netdev_priv(pDev);
	pPriv->txPacketLen = len;
	pPriv->pTxPacketData = pBuf;
	pPriv->status |= DUMMY_NETDEV_TX_INTR;
	dummyNetdevInterrupt(0, pDev, NULL);
}


static void regularIntHandler(int irq, void *pDevId, struct pt_regs *pRegs)
{
	int statusWord;
	struct dumPriv_ *pPriv;
	struct dumPacket_ *pPkt = NULL;
	
	// As usual, check the "device" pointer to be sure it is really interrupting.
	// Then assign "struct device *dev"
	struct net_device *pDev = (struct net_device *)pDevId;
	// and check with hw if it's really ours 

	// paranoid
	if (pDev == NULL)
		return;

	// Lock the device
	pPriv = netdev_priv(pDev);
	spin_lock(&pPriv->lock);

	// retrieve statusword: real netdevices use I/O instructions
	statusWord = pPriv->status;
	pPriv->status = 0;
	if (statusWord & DUMMY_NETDEV_RX_INTR) {
		// send it to rxPkt for handling 
		pPkt = pPriv->pRxQueue;
		if (pPkt) {
			pPriv->pRxQueue = pPkt->pNext;
			rxPkt(pDev, pPkt);
		}
	}
	if (statusWord & DUMMY_NETDEV_TX_INTR) {
		// a transmission is over: free the skb
		pPriv->stats.tx_packets++;
		pPriv->stats.tx_bytes += pPriv->txPacketLen;
		dev_kfree_skb(pPriv->pSkB);
	}

	// Unlock the device and we are done
	spin_unlock(&pPriv->lock);
	if (pPkt) 
		freePkt(pPkt); // Do this outside the lock!
	return;
}

 
void dumSetup(struct net_device *pDev)
{
	// The init function (sometimes called probe).
	// It is invoked by register_netdev()
	struct dumPriv_ *pPriv;

	// Then, initialize the priv field. This encloses the statistics and a few private fields.
	pPriv = netdev_priv(pDev);
	memset(pPriv, 0, sizeof(struct dumPriv_));
	spin_lock_init(&pPriv->lock);
	pPriv->pDev = pDev;


#if 0
    // Make the usual checks: check_region(), probe irq, ...  -ENODEV
	// should be returned if no device found.  No resource should be
	// grabbed: this is done on open(). 
#endif 

	// Then, assign other fields in dev, using ether_setup() and some hand assignments
	ether_setup(pDev);	// assign some of the fields
	pDev->watchdog_timeo = timeout;
	
	// keep the default flags, just add NOARP
	pDev->flags |= IFF_NOARP;
	pDev->features |= NETIF_F_HW_CSUM;
	
	pDev->netdev_ops = &dummyNetdevOps;
	pDev->header_ops = &dummyHeaderOps;
	
	rxIntEn(pDev, 1);	// enable receive interrupts
	createPool(pDev);
}

void dumCleanup(void)
{
	int i;
    
	for (i = 0; i < 2;  i++) {
		if (dummyDevs[i]) {
			unregister_netdev(dummyDevs[i]);
			destroyPool(dummyDevs[i]);
			free_netdev(dummyDevs[i]);
		}
	}
}
	
/*
 * Net device operations
 */

static int dumOpen(struct net_device *pDev) 
{
	// request_region(), request_irq(), ...

	// Assign the hardware address
	memcpy(pDev->dev_addr, "\0DUMM0", ETH_ALEN);
	if (pDev == dummyDevs[1])
		pDev->dev_addr[ETH_ALEN-1]++; // \0DUMM1
	netif_start_queue(pDev);
	return 0;
}

static int dumClose(struct net_device *pDev)
{
	// release ports, irq and such...

	netif_stop_queue(pDev);
	return 0;	
}

static int dumConfig(struct net_device *pDev, struct ifmap *pMap)
{
	int err;

	if (pDev->flags & IFF_UP)
	{
		// can't act on a running interface
		PRINT_STATUS(err = -EBUSY);
		return err;
	} 

	if (pMap->base_addr != pDev->base_addr) {
		// can't change I/O address
		PRINT_STATUS(err = -EOPNOTSUPP);
		return err;
	} 

	if (pMap->irq != pDev->irq) {
		// Allow changing the IRQ
		pDev->irq = pMap->irq;
	}

	// ignore other fields
	return 0;
}

static int dumTxPkt(struct sk_buff *pSkB, struct net_device *pDev)
{
	int len;
	char *pData, shortpkt[ETH_ZLEN];
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	
	pData = pSkB->data;
	len = pSkB->len;
	if (len < ETH_ZLEN) {
		memset(shortpkt, 0, ETH_ZLEN);
		memcpy(shortpkt, pSkB->data, pSkB->len);
		len = ETH_ZLEN;
		pData = shortpkt;
	}
	transStart = jiffies; 	// save the timestamp
	pPriv->pSkB = pSkB;				// Remember the skb, so we can free it at interrupt time

	// actual deliver of data is device-specific, and not shown here
	txPktByHW(pData, len, pDev);

	return NETDEV_TX_OK;
}

static int dumIoctl(struct net_device *pDev, struct ifreq *pReq, int cmd)
{
	PDEBUG("ioctl not implemeted\n");
	return 0;
}

static int dumChangeMTU(struct net_device *pDev, int newMTU)
{
	// The "change_mtu" method is usually not needed.
	// If you need it, it must be like this.

	unsigned long flags = 0;
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	spinlock_t *pLock = &pPriv->lock;
    int err = 0;

	// check ranges
	if ((newMTU < 68) || (newMTU > 1500))
	{
		PRINT_STATUS_MSG("MTU is out if range (68, 1500): %i", (err=-EINVAL), newMTU);
		return err;
	}

	// Do anything you need, and the accept the value
	spin_lock_irqsave(pLock, flags);
	pDev->mtu = newMTU;
	spin_unlock_irqrestore(pLock, flags);
	return 0;
}

static void dumTxTimeout (struct net_device *pDev)
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);

	PDEBUG("Transmit timeout at %ld, latency %ld\n", jiffies, jiffies - transStart);
    
    // Simulate a transmission interrupt to get things moving
	pPriv->status = DUMMY_NETDEV_TX_INTR;
	dummyNetdevInterrupt(0, pDev, NULL);
	pPriv->stats.tx_errors++;
	netif_wake_queue(pDev);
	return;
}

static struct net_device_stats *dumStats(struct net_device *pDev)
{
	struct dumPriv_ *pPriv = netdev_priv(pDev);
	return &pPriv->stats;
}

/*
 * Header operations
 */

static int dumHeader(struct sk_buff *pSkB, struct net_device *pDev, unsigned short type, 
	const void *pDAddr, const void *pSAddr, unsigned len)
{
	struct ethhdr *pEth = (struct ethhdr *)skb_push(pSkB,ETH_HLEN);

	pEth->h_proto = htons(type);
	memcpy(pEth->h_source, pSAddr ? pSAddr : pDev->dev_addr, pDev->addr_len);
	memcpy(pEth->h_dest, pDAddr ? pDAddr : pDev->dev_addr, pDev->addr_len);
	pEth->h_dest[ETH_ALEN-1]   ^= 0x01;   /* dest is us xor 1 */
	return (pDev->hard_header_len);
}


/*
 * Entry/exit point functions
 */

static int dummyNetdevModuleInit(void)
{
	int err = 0, i;

	// Define interrupt
	dummyNetdevInterrupt = regularIntHandler;

	// Allocate devices
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0))
	dummyDevs[0] = alloc_netdev(sizeof (struct dumPriv_), "dummy%d", dumSetup);
	dummyDevs[1] = alloc_netdev(sizeof (struct dumPriv_), "dummy%d", dumSetup);
#else
	dummyDevs[0] = alloc_netdev(sizeof (struct dumPriv_), "dummy%d", NET_NAME_UNKNOWN, dumSetup);
	dummyDevs[1] = alloc_netdev(sizeof (struct dumPriv_), "dummy%d", NET_NAME_UNKNOWN, dumSetup);
#endif
	if (dummyDevs[0] == NULL || dummyDevs[1] == NULL)
	{
		err = -ENOMEM;
		PRINT_STATUS_MSG("cannot allocate struct dummyNet_priv_ (err=%d)", err, err);
		dumCleanup();
		return err;
	}

	// Register devices
	for (i = 0; i<2; i++)
		if ((err = register_netdev(dummyDevs[i])) != 0)
		{
			PRINT_STATUS_MSG("cannot register net device (err=%d)", err, err);
			dumCleanup();
			return err;
		}

	PRINT_STATUS(err);
	return 0;
}

static void dummyNetdevModuleExit(void)
{	
	dumCleanup();
	PRINT_STATUS(0);
}

module_init(dummyNetdevModuleInit);
module_exit(dummyNetdevModuleExit);
