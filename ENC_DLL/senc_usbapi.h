#ifndef LIBSENC_SENC_USBAPI_H_
#define LIBSENC_SENC_USBAPI_H_

#include "libsenc.h"
#include "senc_assist.h"


#define			SENC_ERROR_USB_IO												0x00000101
#define			SENC_ERROR_USB_INVALID_PARAM									0x00000102
#define			SENC_ERROR_USB_ACCESS_DENY										0x00000103
#define			SENC_ERROR_USB_NO_DEVICE										0x00000104
#define			SENC_ERROR_USB_NOT_FOUND										0x00000105
#define			SENC_ERROR_USB_BUSY												0x00000106
#define			SENC_ERROR_USB_TIMEOUT											0x00000107
#define			SENC_ERROR_USB_OVERFLOW											0x00000108
#define			SENC_ERROR_USB_PIPE												0x00000109
#define			SENC_ERROR_USB_INTERRUPTED										0x0000010A
#define			SENC_ERROR_USB_NO_MEMORY										0x0000010B
#define			SENC_ERROR_USB_NOT_SUPPORTED									0x0000010C
#define			SENC_ERROR_USB_UNKNOWN											0x000001FF

//USB超时时间(ms)，0则无超时
#define			SENC_BULK_TIME_OUT												500000
#define			LIBUSB_TRANSFER_SUCCESS											0

#define			SENC_SS_PID														0x0452
#define			SENC_SS_VID														0x1BC0

//********************************************************************************************************//
//*函数：USB_GetDevList()
//*功能：获取加密卡设备列表||Get encrypt cards list;
//*参数：SENCryptCardList*		senclist						//加密卡设备列表
//*日期：2016/09/29 by Wangjf
unsigned int USB_GetDevList(SENCryptCardList*	OUT	senclist);
//********************************************************************************************************//
//*函数：SENC_Open()
//*功能：开启设备||Open device
//*参数：SENCryptCard*	SencDev					//加密卡设备handle
//*日期：2016/09/29 by Wangjf
unsigned int USB_Open(SENCryptCard*	IN	SencDev);
//********************************************************************************************************//
//*函数：SENC_Close()
//*功能：关闭设备||Close device
//*参数：SENCryptCard*		sencDev,						//加密卡设备handle
//*日期：2016/09/29 by Wangjf
unsigned int USB_Close(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_Init()
//*功能：初始化设备空间||Initial device
//*参数：SENCryptCard*		sencDev,						//加密卡设备handle
//*日期：2016/09/29 by Wangjf
unsigned int USB_Init(SENCryptCard*	IN	sencDev);
//********************************************************************************************************//
//*函数：SENC_Bulk_Write()
//*功能：USB BULK_ONLY模式写操作||Data write-in in USB BulkOnly mode
//*参数：SENCryptCard*	sencDev,					//加密卡设备handle
//		unsigned int	EndPoint					//EndPoint 写
//		unsigned char*	pucSendData					//待发送数据
// 		unsigned int	uiSendLength				//待发送数据长度
//*日期：2016/09/29 by Wangjf
unsigned int SENC_Bulk_Write(SENCryptCard*	IN	 sencDev,			//加密卡设备handle
							 unsigned char	IN	 EndPoint,			//EndPoint 写
							 unsigned char*	IN	 pucSendData,		//待发送数据
							 unsigned int	IN	 uiSendLength);		//待发送数据长度
//********************************************************************************************************//
//*函数：SENC_Bulk_Read()
//*功能：USB BULK_ONLY模式读操作||Data read-in in USB BulkOnly mode
///*参数：SENCryptCard*	sencDev,					//加密卡设备handle
//		unsigned int	EndPoint					//EndPoint 读
// 		unsigned char*	pucReadData					//接收数据
//		unsigned int	uiReadLength				//接收数据长度
//*日期：2016/09/29 by Wangjf
unsigned int SENC_Bulk_Read(SENCryptCard*	IN	sencDev,			//加密卡设备handle
							unsigned char	IN	EndPoint,			//EndPoint 读
							unsigned char*	OUT	pucReadData,		//接收数据
							unsigned int	IN	uiReadLength);		//接收数据长度
//********************************************************************************************************//
//*函数：sencdev_New()
//*功能：申请设备指针空间||malloc memory for device pointer
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：	2016/10/18
//by Wangjf
unsigned int sencdev_New(SENCryptCard** IN	sencDev);
//********************************************************************************************************//
//*函数：sencdev_Free()
//*功能：释放设备指针空间||free device pointer
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：	2016/10/18
//by Wangjf
unsigned int sencdev_Free(SENCryptCard*	IN sencDev);
//********************************************************************************************************//

//*函数：sencdev_Init()
//*功能：初始化设备指针空间||initialize device pointer memory
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：	2016/10/18
//by Wangjf
unsigned int sencdev_Init(SENCryptCard*	IN sencDev);


//*函数：USB_NewCtx()
//*功能：初始化设备列表libusb容器||Initialize libusb context of devices list;
//*参数：SENCryptCardList*		senclist						//加密卡设备列表
//*日期：2017/03/22
//by Wangjf
unsigned int USB_NewCtx(SENCryptCardList* senclist);

//*函数：USB_FreeCtx()
//*功能：释放设备列表libusb容器||Free libusb context of devices list;
//*参数：SENCryptCardList*		senclist						//加密卡设备列表
//*日期：2017/03/22
//by Wangjf
unsigned int USB_FreeCtx(SENCryptCardList* senclist);



#endif //LIBSENC_SENC_USBAPI_H_
