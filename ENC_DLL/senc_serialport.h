#ifndef LIBSENC_SENC_SERIALPORT_H_
#define LIBSENC_SENC_SERIALPORT_H_



#define SERIAL_HUB_LINUX_PATH	"/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_A505SBIG-if00-port0"
#define SERIAL_HUB_WIN32_PATH	"\\\\?\\ftdibus#vid_0403+pid_6001"
#define SERIAL_HUB_ERROR		0x30000000
#define SERIAL_HUB_WIN32_ERROR	0x30010000

#if defined(_WIN32) || defined(WIN32) || defined(_WIN64)
#define SERIAL_HUB_TIME_OUT_PERIOD		10
#elif defined(linux) || defined(__linux__)
#define SERIAL_HUB_TIME_OUT_PERIOD		30
#endif

int SENC_COM_RESET(int TargetSerialPort, int CaseIndex);		//Ä¿±ê¶Ë¿ÚºÅ


#endif //LIBSENC_SENC_SERIALPORT_H_