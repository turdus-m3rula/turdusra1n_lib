#ifndef __LIBIRECOVERY_WRAPPER_H
#define __LIBIRECOVERY_WRAPPER_H

#pragma mark - IOKit
#if defined(USE_IOKIT_BACKEND)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>
extern uint32_t dfu_send_buffer(IOUSBDeviceInterface245 **handle, const uint8_t* data, size_t length);
#pragma mark - libusb
#elif defined (USE_LIBUSB_BACKEND)
extern uint32_t dfu_send_buffer(void **handle, const uint8_t* data, size_t length);
#pragma mark - dummy
#else
extern uint32_t dfu_send_buffer(void **handle, const uint8_t* data, size_t length);
#endif


#endif
