#include "libsenc.h"
#include "senc_assist.h"
#include "senc_serialport.h"
#include "senc_error.h"

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <windows.h>
#include <SetupAPI.h>
// #include <iostream>
#pragma comment (lib,"setupapi.lib")

// using namespace std;

#elif defined(linux) || defined(__linux__)
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <dirent.h>
#endif

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#include <tchar.h>
CLock gSerialLock;
#elif defined(linux) || defined(__linux__)
MUTEX_TYPE gSerialLock;


int UART0_Recv(int fd, char* rcvbuf, int rcvlen){
	int len,fs_sel;
	fd_set fs_read;

	struct timeval time;

	FD_ZERO(&fs_read);
	FD_SET(fd,&fs_read);

	time.tv_sec=10;
	time.tv_usec=0;

	fs_sel=select(fd+1,&fs_read,NULL,NULL,&time);

	if(fs_sel){
		len=read(fd,rcvbuf,rcvlen);
		return len;
	}else
		return 0;
}



#endif


int SENC_COM_RESET(int TargetSerialPort, int CaseIndex)		//Ä¿±ê¶Ë¿ÚºÅ
{
	//frame reset command
	char cmd[10]={"AT+RST"};
	cmd[6]=('0'+TargetSerialPort/10)&0xff;
	cmd[7]=('0'+TargetSerialPort%10)&0xff;
	char readbuf[32];
	int iRet=0;
	int ResetSignal=0;

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	HANDLE hCom;
	DWORD sendLen,readLen;
	BOOL flag=0;
	DCB SerialAttributes;
	COMMTIMEOUTS TimeOutAttribute={0};


#elif defined(linux) || defined(__linux__)
	struct termios options;
// 	char Dev_Path[128]={SERIAL_HUB_LINUX_PATH};
	char Dev_Path[128]={"/dev/serial/by-path/"};
	int sendLen;	
	int fd;
	DIR *dir;
	struct dirent *ptr;
	char Path[1000];
	int findflag=0,addresslen=0;
	if(!(dir=opendir("/dev/serial/by-path/"))){
		return ERROR_LOG(SENC_ERROR_SERIAL_PORT_NO_SERIAL_FOUND,"Cannot Open Path /dev/serial/by-path/");
	}
	while((ptr=readdir(dir))){
		if(strcmp(ptr->d_name,".")==0||strcmp(ptr->d_name,"..")==0) continue;
		else if(ptr->d_type==10){
			int cc=0;
			while(cc<ptr->d_reclen-5){
				if (ptr->d_name[cc+1]=='.'&&ptr->d_name[cc+2]=='4'&&ptr->d_name[cc+3]=='.'&&ptr->d_name[cc+4]=='4'&&ptr->d_name[cc+5]==':') break;
				else cc++;
			}
	
			if((CaseIndex<10&&(ptr->d_name[cc]==(CaseIndex+'0')))||((CaseIndex>=10)&&(ptr->d_name[cc]==(CaseIndex%10+'0'))&&(ptr->d_name[cc-1]==((CaseIndex/10)%10+'0')))){
				memcpy(Path,ptr->d_name,ptr->d_reclen);
				addresslen=ptr->d_reclen;
				findflag=1;
				break;
			}else continue;
		}else continue;
	}
	if(findflag!=1) return ERROR_LOG(SENC_ERROR_SERIAL_PORT_NO_SERIAL_FOUND,"Target Serial Not Found");
	memcpy(Dev_Path+20,Path,addresslen);
	closedir(dir);
#endif


	do{
#if defined(_WIN32)
		CGuard guard(gSerialLock);
#elif defined(linux) || defined(__linux__)
		AUTO_GUARD(ThreadLock,MUTEX_TYPE,gSerialLock)
#endif

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
		//WIN32 environment
		HKEY hKey;
		LONG regret;
		LPCTSTR RegPath="HARDWARE\\DEVICEMAP\\SERIALCOMM";
		LPCTSTR serialport="\\\\.\\COM19";
		regret=::RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegPath,NULL,KEY_READ,&hKey);

		if(regret == ERROR_SUCCESS){
			int i=0;
			TCHAR portName[256],commName[256];
			DWORD dwLen, dwSize;
			while(1){
				dwLen=dwSize=sizeof(portName);
				if(::RegEnumValue(hKey,i,portName,&dwLen,NULL,NULL,(PUCHAR)commName,&dwSize)==ERROR_NO_MORE_ITEMS)
					break;
				//comm is the name;
				i++;
			}
			RegCloseKey(hKey);
		}

		//open COMX
		hCom=CreateFile(serialport,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
		if((HANDLE)-1==hCom)
		{
			iRet=ERROR_LOG(SENC_ERROR_SERIAL_PORT_CANNOT_OPEN,"CreateFile Failed");
			break;
		}

		//Initialize attributes and set
		memset(&SerialAttributes,0,sizeof(DCB));
		SerialAttributes.DCBlength=sizeof(DCB);
		flag=GetCommState(hCom,&SerialAttributes);
		if(FALSE==flag){
			flag=GetLastError();
			iRet=ERROR_LOG(flag|SERIAL_HUB_WIN32_ERROR,"GetCommState Failed");
			break;
		}
		SerialAttributes.BaudRate=CBR_115200;
		SerialAttributes.ByteSize=8;
		SerialAttributes.Parity=EVENPARITY;
		SerialAttributes.StopBits=ONESTOPBIT;

		flag=SetCommState(hCom,&SerialAttributes);
		if(FALSE==flag){
			flag=GetLastError();
			iRet=ERROR_LOG(flag|SERIAL_HUB_WIN32_ERROR,"GetCommState Failed");
			break;
		}

		//set time-out configuration
		TimeOutAttribute.ReadTotalTimeoutMultiplier=SERIAL_HUB_TIME_OUT_PERIOD;
		TimeOutAttribute.WriteTotalTimeoutMultiplier=SERIAL_HUB_TIME_OUT_PERIOD;
		// 	TimeOutAttribute.ReadIntervalTimeout=MAXDWORD;
		flag=SetCommTimeouts(hCom,&TimeOutAttribute);
		if(FALSE==flag){
			flag=GetLastError();
			iRet=ERROR_LOG(flag|SERIAL_HUB_WIN32_ERROR,"GetCommState Failed");
			break;
		}

		while(ResetSignal<3){
			//send reset command
			flag=WriteFile(hCom,cmd,8,&sendLen,NULL);
			if(FALSE==flag||sendLen!=8){
				iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_WRITE_ERROR,"Serial WriteFile Failed");
				break;
			}

			//receive reset response
			flag=ReadFile(hCom,readbuf,8,&readLen,NULL);
			if(FALSE==flag)
			{
				iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_READ_ERROR,"Serial ReadFile Failed");
				break;
			}
			if(memcmp(readbuf,"SUCCESS",7)!=0){
				if(memcmp(readbuf,"FAIL",4)!=0){
					iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_READ_ERROR,"Received 'FAIL'");
					break;					
				}else {
					if(++ResetSignal>=3) iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_RESET_FAILED,"Reset Failed");					
				}
			}else{
				iRet=SENC_SUCCESS;
				break;
			}
		}

#elif defined(linux) || defined(__linux__)


		// 		fd=open(Dev_Path,O_RDWR);
		fd=open(Dev_Path,O_RDWR|O_NOCTTY|O_NDELAY);
		if(-1==fd){
			iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_CANNOT_OPEN,"Open Serial Failed");
			break;
		}else
			fcntl(fd,F_SETFL,0);


		tcgetattr(fd,&options);
		memset(&options,0,sizeof(options));
		cfsetispeed(&options,B115200);
		cfsetospeed(&options,B115200);
		// 		options.c_cflag |=B115200; //baud rate
		options.c_cflag |=CS8; //8 data bits
		options.c_cflag &=~CSTOPB; //1 stop bit
		options.c_cflag |=PARENB; //enable parity bit
		options.c_cflag &=~PARODD; //even parity

		// 		options.c_cflag &= ~CRTSCTS;//disable hardware flow control;


		options.c_cflag |=CLOCAL|CREAD;
		options.c_lflag &=~(ICANON | ECHO | ECHOE | ISIG);
		options.c_oflag &= ~OPOST;

		tcflush(fd,TCIOFLUSH);
		options.c_cc[VTIME]=SERIAL_HUB_TIME_OUT_PERIOD; //time-out cost, sec
		options.c_cc[VMIN]=0;

		if(tcsetattr(fd,TCSANOW,&options)!=0){
			iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_CANNOT_SET_ATTRIBUTE,"Set Serial Attributes Failed");
			break;
		}

		while(ResetSignal<3){
			sendLen=write(fd,cmd,8);
			if(sendLen!=8){
				iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_WRITE_ERROR,"Serial Write Failed");
				break;
			}

			sleep(1);
			//usleep(1000);//usec

			int /*n,max_fd,*/len=7,count=0;
			/*
			fd_set input;
			struct timeval timeout;
			char * ptr=readbuf;


			FD_ZERO(&input);
			FD_SET(fd,&input);
			max_fd=fd+1;

			
			while(1){
				timeout.tv_sec=0;
				timeout.tv_usec=500;

				n=select(max_fd,&input,NULL,NULL,&timeout);
				if(n<1){
					iRet= SENC_ERROR_SERIAL_PORT_READ_ERROR+0x10;
					break;
				}else{
					ioctl(fd,FIONREAD,&len);
					if(!len){
						iRet= SENC_ERROR_SERIAL_PORT_READ_ERROR+0x20;
						break;
					}
					len=read(fd,ptr,len);
					ptr+=len;
					count+=len;
				}
			}
			*/

			count=UART0_Recv(fd,readbuf,len);
			if(count==0){
				iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_READ_ERROR,"Serial Write Failed");
			}
			readbuf[count]=0;

			if(iRet!=SENC_SUCCESS){
				break;
			}

			// 		readLen=read(fd,readbuf,8);
			if(memcmp(readbuf,"SUCCESS",7)!=0){
				if(memcmp(readbuf,"FAIL",4)!=0){
					iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_READ_ERROR,"Received 'FAIL'");
					break;
				}else{
					if(++ResetSignal>=3) iRet= ERROR_LOG(SENC_ERROR_SERIAL_PORT_RESET_FAILED,"Received 'FAIL'");	
				}
			}else{
				iRet=SENC_SUCCESS;
				break;
			}
		}

#endif
	}while(0);

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
	CloseHandle(hCom);
#elif defined(linux) || defined(__linux__)
	close(fd);
#endif

	return iRet;

}