#include "libsenc.h"
#include "senc_usbapi.h"
#include <stdlib.h>
#include "senc_assist.h"
#include "senc_error.h"


#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#pragma once
// #include "libusb\libusb\libusb.h"
// #include "libusb\libusb\libusbi.h"
#include "libusb.h"
#elif defined(linux) || defined(__linux__)
#include <string.h>
#include <stdio.h>
#include "libusb.h"
#endif

#define		SENC_RECONNECT_TIMES		3
#define		SENC_RECONNECT_DELAY		1000


//*函数：USB_NewCtx()
//*功能：初始化设备列表libusb容器||Initialize libusb context of devices list;
//*参数：SENCryptCardList*		senclist						//加密卡设备列表
//*日期：2017/03/22
//by Wangjf
unsigned int USB_NewCtx(SENCryptCardList* senclist)
{
	int r;

	//libusb initial
	r = libusb_init((libusb_context **)(&senclist->ctx));//初始化libusb容器
	if(r<SENC_SUCCESS){
		return ERROR_LOG(usbErrorCheck(r),"Libusb Error: Init Context");
	}
	return SENC_SUCCESS;
}

//*函数：USB_FreeCtx()
//*功能：释放设备列表libusb容器||Free libusb context of devices list;
//*参数：SENCryptCardList*		senclist						//加密卡设备列表
//*日期：2017/03/22
//by Wangjf
unsigned int USB_FreeCtx(SENCryptCardList* senclist)
{
	//libusb context release
	libusb_exit((libusb_context *)senclist->ctx);

	return SENC_SUCCESS;
}


//*函数：USB_GetDevList()
//*功能：获取加密卡设备列表||Get encrypt cards list;
//*参数：SENCryptCardList*		senclist						//加密卡设备列表
//*日期：2016/09/29
//by Wangjf
unsigned int USB_GetDevList(SENCryptCardList* senclist)
{
	struct libusb_device **devs;
	struct libusb_device *dev;
	unsigned int i = 0;
	int r,DevCount=0;
	unsigned char Path[8]={0};

	//enum usb devices
	r =libusb_get_device_list((libusb_context *)senclist->ctx, &devs);
	if(r<SENC_SUCCESS){
		return ERROR_LOG(usbErrorCheck(r),"Libusb Error: Get Device List");
	}

	//find senc cards
	while (((dev = devs[i++]) != NULL)&&DevCount<64) {
		struct libusb_device_descriptor desc;
		r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0)
		{
			libusb_free_device_list(devs, 1);
			return ERROR_LOG(usbErrorCheck(r),"Get List: Get Device Descriptor");
		}
		if (desc.idVendor == SENC_SS_VID && desc.idProduct == SENC_SS_PID) {		
			//record dev_path			
			r = libusb_get_port_numbers(dev,Path,sizeof(Path));
			memset(senclist->devs[DevCount]->Dev_Path_str,'#',16);
			for(int i=0;i<r;i++){
				senclist->devs[DevCount]->Dev_Path[i]=Path[i];
				if(Path[i]<26){
					senclist->devs[DevCount]->Dev_Path_str[i]=Path[i]+'A';
				}else{
					senclist->devs[DevCount]->Dev_Path_str[i]=(Path[i]%26)+'a';
				}
			}

			if(senclist->devs[DevCount]->Dev_Path[1]>0){
				int tflag=2;
				while(senclist->devs[DevCount]->Dev_Path[tflag]!=-1) tflag++;
				senclist->devs[DevCount]->Port_Num=senclist->devs[DevCount]->Dev_Path[tflag-1]+(senclist->devs[DevCount]->Dev_Path[tflag-2]-1)*4;
				senclist->devs[DevCount]->Case_Num=senclist->devs[DevCount]->Dev_Path[tflag-3];
			}else{
				senclist->devs[DevCount]->Port_Num=senclist->devs[DevCount]->Dev_Path[0];
				senclist->devs[DevCount]->Case_Num=senclist->devs[DevCount]->Dev_Path[0];
			}
			DevCount++;
		}
	}
	senclist->DevNums=DevCount;

	libusb_free_device_list(devs, 1);
	return SENC_SUCCESS;
}

//*函数：USB_Open()
//*功能：开启设备并占用接口||Open device and claim for interface
//*参数：SENCryptCardList*	senclist					//加密卡设备列表
//*日期：2016/11/09
//by Wangjf
unsigned int USB_Open(SENCryptCard* SencDev)
{
	struct libusb_device **devs;
	struct libusb_device *found = NULL;
	struct libusb_device *dev;
	unsigned int i = 0;
	unsigned char Path[8];
	int r;

	//libusb initial
	r = libusb_init((libusb_context **)(&SencDev->ctx));//初始化内容结构体
	if(r<SENC_SUCCESS){
		return ERROR_LOG(usbErrorCheck(r),"Device Open: Init Device Context");
	}

	//enum usb devices
	if (libusb_get_device_list((libusb_context *)SencDev->ctx, &devs) < 0)
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
		return NULL;
#elif defined(linux) || defined(__linux__)
		return 0;
#endif

	//find target device in list
	while (((dev = devs[i++]) != NULL)) {
		struct libusb_device_descriptor desc;
		r = libusb_get_device_descriptor(dev, &desc);
		if (r < 0){
			libusb_free_device_list(devs, 1);
			libusb_exit((libusb_context *)SencDev->ctx);
			return ERROR_LOG(usbErrorCheck(r),"Device Open: Get Device Descriptor");
		}
		if (desc.idVendor == SENC_SS_VID && desc.idProduct == SENC_SS_PID) {
			int flag=1;			

			r=libusb_get_port_numbers(dev,Path,sizeof(Path));
			for(int t=0;t<r;t++){
				if(Path[t]!=SencDev->Dev_Path[t]){
					flag=0;
					break;
				}				
			}
			if(flag==1){
				found = dev;
				break;
			}			
		}
	}

	if(!found){
		libusb_free_device_list(devs, 1);
		libusb_exit((libusb_context *)SencDev->ctx);
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Device Open: Device Not Found");
	}

	//open target device
	r = libusb_open(found, (libusb_device_handle**)(&SencDev->dev_handle));
	if (r < 0){
		libusb_free_device_list(devs, 1);
		libusb_exit((libusb_context *)SencDev->ctx);
		return ERROR_LOG(usbErrorCheck(r),"Device Open: Open Failed");
	}
	if(libusb_kernel_driver_active((libusb_device_handle*)SencDev->dev_handle,0) == 1){//驱动检测
		libusb_detach_kernel_driver((libusb_device_handle*)SencDev->dev_handle,0);
	}
	r = libusb_claim_interface((libusb_device_handle*)SencDev->dev_handle,0);//申请并独占接口
	if(r<SENC_SUCCESS){ 
		libusb_attach_kernel_driver((libusb_device_handle*)SencDev->dev_handle,0);
		libusb_close((libusb_device_handle*)SencDev->dev_handle);
		libusb_exit((libusb_context *)SencDev->ctx);
		return ERROR_LOG(usbErrorCheck(r),"Device Open: Claim Interface Failed");
	}

	//set mthread lock
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	CLock* tLock=new CLock;
	SencDev->DevLock=(CLock*)tLock;
#elif defined(linux) || defined(__linux__)
	MUTEX_TYPE* tLock=new MUTEX_TYPE;
	SencDev->DevLock=(MUTEX_TYPE*)tLock;
#endif
	SencDev->OpenSign=TRUE;
	libusb_free_device_list(devs, 1);
	return SENC_SUCCESS;
}



//*函数：USB_Close()
//*功能：关闭设备||Close device
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：2016/09/29
//by Wangjf
unsigned int USB_Close(SENCryptCard* sencDev)
{
	unsigned int ucRet = 0;

	//param check
	if(!sencDev) return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Device Close: Device Not Found");

	if(sencDev->OpenSign == FALSE)//设备开启表示未置位
		return SENC_SUCCESS;

	//release interface and close device
	ucRet = libusb_release_interface((libusb_device_handle*)sencDev->dev_handle,0);//释放接口
	if(ucRet!=SENC_SUCCESS){
		return ERROR_LOG(usbErrorCheck(ucRet),"Device Close: Release Interface Failed");
	}
	libusb_attach_kernel_driver((libusb_device_handle*)sencDev->dev_handle,0);
	libusb_close((libusb_device_handle*)sencDev->dev_handle);
	libusb_exit((libusb_context *)sencDev->ctx);

	sencdev_Init(sencDev);

	return SENC_SUCCESS;
}



//*函数：sencdev_New()
//*功能：申请设备指针空间||malloc memory for device pointer
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：	2016/10/18
//by Wangjf
unsigned int sencdev_New(SENCryptCard** sencDev)
{
	// 	unsigned int uiRet;
	*sencDev =(SENCryptCard*)malloc(sizeof(SENCryptCard));//为设备结构体申请空间
	if(!sencDev){
		return ERROR_LOG(SENC_ERROR_OUT_OF_MEMORY,"Device New: Malloc Failed"); 
	}
	memset((*sencDev),0,sizeof(SENCryptCard));
	(*sencDev)->OpenSign = FALSE;
	(*sencDev)->dev_handle = NULL;
	(*sencDev)->ctx = NULL;
	(*sencDev)->DevCtx=(unsigned char*)malloc(sizeof(KeyData));
	memset((*sencDev)->Dev_Path,-1,sizeof((*sencDev)->Dev_Path));
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	(*sencDev)->DevLock=NULL;
#elif defined(linux) || defined(__linux__)
	//(*sencDev)->DevMutex=(MUTEX_TYPE*)malloc(sizeof(MUTEX_TYPE));
#endif	

	return SENC_SUCCESS;
}

//*函数：sencdev_Init()
//*功能：初始化设备指针空间||initialize memory for device pointer
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：	2016/10/18
//by Wangjf
unsigned int sencdev_Init(SENCryptCard* sencDev)
{
	// 	memset(*sencDev,0,sizeof(SENCryptCard));
	sencDev->OpenSign = FALSE;
	sencDev->dev_handle = NULL;
	sencDev->ctx = NULL;
	memset(sencDev->DevCtx,0,sizeof(KeyData));
	memset(sencDev->Dev_Path,-1,sizeof(sencDev->Dev_Path));
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	sencDev->DevLock=NULL;
#elif defined(linux) || defined(__linux__)
	//sencDev->DevMutex=(MUTEX_TYPE*)malloc(sizeof(MUTEX_TYPE));
#endif	

	return SENC_SUCCESS;
}


//*函数：sencdev_Free()
//*功能：释放设备指针空间||release memory for device pointer
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//*日期：	2016/10/18
//by Wangjf
unsigned int sencdev_Free(SENCryptCard* sencDev)
{
	//释放结构体
	if(!sencDev){
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Memory Release: Parameter Error"); 
	}
	free(sencDev->DevCtx);
	if(sencDev->ctx) libusb_exit((libusb_context *)sencDev->ctx);
#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	delete((CLock*)sencDev->DevLock);
#elif defined(linux) || defined(__linux__)
	delete((MUTEX_TYPE*)sencDev->DevLock);
#endif
	free(sencDev);
	//sencDev->OpenSign=FALSE;
	// 	sencDev = NULL;

	return SENC_SUCCESS;
}



//*函数：SENC_Bulk_Write()
//*功能：USB BULK_ONLY模式写操作||Data write-in in USB BulkOnly mode
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//		unsigned int		EndPoint						//EndPoint 写
//		unsigned char*		pucSendData						//待发送数据
// 		unsigned int		uiSendLength					//待发送数据长度
//*日期：2016/09/29
//by Wangjf

unsigned int SENC_Bulk_Write(SENCryptCard*	 sencDev,			//加密卡设备handle
							 unsigned char	 EndPoint,			//EndPoint 写
							 unsigned char*	 pucSendData,		//待发送数据
							 unsigned int	 uiSendLength)		//待发送数据长度
{
	int iActualSendLength=0;
	unsigned int ucRet = 0;
	//	int reconnected=0;

	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Usb Write: Device Not Found");
	if(!pucSendData||(EndPoint!=SENC_BULK_ENDPOINT_WRITE_1K&&EndPoint!=SENC_BULK_ENDPOINT_WRITE_2K))
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Usb Write: Parameter Error");

	ucRet = libusb_bulk_transfer((libusb_device_handle*)sencDev->dev_handle,EndPoint,pucSendData,uiSendLength,&iActualSendLength,SENC_BULK_TIME_OUT);
	if((int)ucRet<LIBUSB_TRANSFER_SUCCESS)
	{		
		// 		while(reconnected<SENC_RECONNECT_TIMES){
		// reconnect_W:
		// #if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
		// 			Sleep(SENC_RECONNECT_DELAY);
		// #elif defined(linux) || defined(__linux__)
		// 			usleep(SENC_RECONNECT_DELAY*1000);
		// #endif
		// // 			ucRet = USB_Open(sencDev);
		// // 			if(ucRet!=LIBUSB_TRANSFER_SUCCESS){
		// // 				reconnected++;
		// // 				goto reconnect_W;
		// // 			}
		// // 			ucRet=SENC_DH_KeyExchange(sencDev);		//秘钥交换
		// // 			if(ucRet!=LIBUSB_TRANSFER_SUCCESS){
		// // 				reconnected++;
		// // 				goto reconnect_W;
		// // 			}
		// 			ucRet = libusb_bulk_transfer(sencDev->dev_handle,EndPoint,pucSendData,uiSendLength,&iActualSendLength,SENC_BULK_TIME_OUT);
		// 			if(ucRet!=LIBUSB_TRANSFER_SUCCESS){
		// 				reconnected++;
		// 				goto reconnect_W;
		// 			}
		// 			break;
		// 		}
		if(ucRet!=LIBUSB_TRANSFER_SUCCESS)
			return ERROR_LOG(usbErrorCheck(ucRet),"Usb Write Transfer: Libusb Error");//libusb错误码转换
	}
	else if(iActualSendLength!=(int)uiSendLength)//待发送长度与实际发送长度比较
		return ERROR_LOG(SENC_ERROR_TRANSFER_LENGTH_NOT_MATCH,"Usb Write Transfer: Transfered Data Length Error");

	return SENC_SUCCESS;
}

//*函数：SENC_Bulk_Read()
//*功能：USB BULK_ONLY模式读操作||Data read-in in USB BulkOnly mode
//*参数：SENCryptCard		sencDev,						//加密卡设备handle
//		unsigned int	EndPoint					//EndPoint 读
// 		unsigned char*	pucReadData					//接收数据
//		unsigned int	uiReadLength				//接收数据长度
//*日期：2016/09/29
//by Wangjf
unsigned int SENC_Bulk_Read(SENCryptCard*		sencDev,				//加密卡设备handle
							unsigned char		EndPoint,			//EndPoint 读
							unsigned char*	pucReadData,		//接收数据
							unsigned int		uiReadLength)		//接收数据长度
{
	int iActualReadLength=0;
	unsigned int ucRet = 0;
	//	int reconnected=0;

	if(!sencDev)
		return ERROR_LOG(SENC_ERROR_DEVICE_NOT_FOUND,"Usb Read: Device Not Found");
	if(!pucReadData||(EndPoint!=SENC_BULK_ENDPOINT_READ_1K&&EndPoint!=SENC_BULK_ENDPOINT_READ_2K))
		return ERROR_LOG(SENC_ERROR_PARAMETER_ERROR,"Usb Read: Parameter Error");

	ucRet = libusb_bulk_transfer((libusb_device_handle*)sencDev->dev_handle,EndPoint,pucReadData,uiReadLength,&iActualReadLength, SENC_BULK_TIME_OUT);
	if((int)ucRet<LIBUSB_TRANSFER_SUCCESS)
	{
		// 		while(reconnected<SENC_RECONNECT_TIMES){
		// reconnect_R:
		// #if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
		// 			Sleep(SENC_RECONNECT_DELAY);
		// #elif defined(linux) || defined(__linux__)
		// 			usleep(SENC_RECONNECT_DELAY*1000);
		// #endif
		// // 			ucRet = USB_Open(sencDev);
		// // 			if(ucRet!=LIBUSB_TRANSFER_SUCCESS){
		// // 				reconnected++;
		// // 				goto reconnect_R;
		// // 			}
		// // 			ucRet=SENC_DH_KeyExchange(sencDev);		//秘钥交换
		// // 			if(ucRet!=LIBUSB_TRANSFER_SUCCESS){
		// // 				reconnected++;
		// // 				goto reconnect_R;
		// // 			}
		// 			ucRet = libusb_bulk_transfer(sencDev->dev_handle,EndPoint,pucReadData,uiReadLength,&iActualReadLength, SENC_BULK_TIME_OUT);
		// 			if(ucRet!=LIBUSB_TRANSFER_SUCCESS){
		// 				reconnected++;
		// 				goto reconnect_R;
		// 			}
		// 			break;
		// 		}
		if(ucRet!=LIBUSB_TRANSFER_SUCCESS)
			return ERROR_LOG(usbErrorCheck(ucRet),"Usb Read Transfer: Libusb Error");//libusb错误码转换
	}
	else if(iActualReadLength!=(int)uiReadLength)//待接受长度与实际接受长度比较
		return ERROR_LOG(SENC_ERROR_TRANSFER_LENGTH_NOT_MATCH,"Usb Read Transfer: Transfered Data Length Error");

	return SENC_SUCCESS;
}
