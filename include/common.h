#ifndef _COMMON_H
#define _COMMON_H

//-------------------------------------------------------------------------------------------------
// MACRO
//-------------------------------------------------------------------------------------------------
#define DRIVER_NAME "dummy-net"
#define PDEBUG(fmt,args...) printk(KERN_DEBUG"%s(%s):"fmt, DRIVER_NAME, __FUNCTION__, ##args)
#define PERR(fmt,args...) printk(KERN_ERR"%s(%s):"fmt, DRIVER_NAME, __FUNCTION__, ##args)
#define PINFO(fmt,args...) printk(KERN_INFO"%s:"fmt,DRIVER_NAME, ##args)
#define PRINT_STATUS_MSG(fmt, err, args...) printk(KERN_DEBUG"%s(%s)-[%s] "fmt"\n", DRIVER_NAME, __FUNCTION__, err ? messages[MSG_FAIL] : messages[MSG_OK], ##args)
#define PRINT_STATUS(err) PRINT_STATUS_MSG("", (err)) 

//-------------------------------------------------------------------------------------------------
// Types
//-------------------------------------------------------------------------------------------------
enum message_index_ { MSG_OK, MSG_FAIL };

//-------------------------------------------------------------------------------------------------
// Varibles
//-------------------------------------------------------------------------------------------------
extern const char* messages[];

#endif // _COMMON_H
