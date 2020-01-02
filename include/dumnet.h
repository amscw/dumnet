#ifndef _DUMMY_NET_H
#define _DUMMY_NET_H

// These are the flags in the statusword
#define DUMMY_NETDEV_RX_INTR 	0x0001
#define DUMMY_NETDEV_TX_INTR 	0x0002

// Default timeout period
#define DUMMY_NETDEV_TIMEOUT 	5 // In jiffies

extern struct net_device *dummyDevs[];


#endif // _DUMMY_NET_H