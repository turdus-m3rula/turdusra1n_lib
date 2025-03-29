/*
 * libirecovery.c
 * Communication to iBoot/iBSS on Apple iOS devices via USB
 *
 * Copyright (c) 2011-2023 Nikias Bassen <nikias@gmx.li>
 * Copyright (c) 2012-2020 Martin Szulecki <martin.szulecki@libimobiledevice.org>
 * Copyright (c) 2010 Chronic-Dev Team
 * Copyright (c) 2010 Joshua Hill
 * Copyright (c) 2008-2011 Nicolas Haunold
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>

#pragma mark - IOKit
#if defined(USE_IOKIT_BACKEND)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>
#pragma mark - libusb
#elif defined (USE_LIBUSB_BACKEND)
// TODO
#pragma mark - dummy
#else
// TODO
#endif

struct irecv_client_private {
#if defined(USE_IOKIT_BACKEND)
    IOUSBDeviceInterface320 **handle;
#elif defined (USE_LIBUSB_BACKEND)
    // TODO
#pragma mark - dummy
#else
    // TODO
#endif
};

typedef struct irecv_client_private irecv_client_private;
typedef irecv_client_private* irecv_client_t;

typedef enum {
    IRECV_E_SUCCESS           =  0,
    IRECV_E_NO_DEVICE         = -1,
    IRECV_E_OUT_OF_MEMORY     = -2,
    IRECV_E_UNABLE_TO_CONNECT = -3,
    IRECV_E_INVALID_INPUT     = -4,
    IRECV_E_FILE_NOT_FOUND    = -5,
    IRECV_E_USB_UPLOAD        = -6,
    IRECV_E_USB_STATUS        = -7,
    IRECV_E_USB_INTERFACE     = -8,
    IRECV_E_USB_CONFIGURATION = -9,
    IRECV_E_PIPE              = -10,
    IRECV_E_TIMEOUT           = -11,
    IRECV_E_UNSUPPORTED       = -254,
    IRECV_E_UNKNOWN_ERROR     = -255
} irecv_error_t;

enum {
    IRECV_SEND_OPT_NONE              = 0,
    IRECV_SEND_OPT_DFU_NOTIFY_FINISH = (1 << 0),
    IRECV_SEND_OPT_DFU_FORCE_ZLP     = (1 << 1),
    IRECV_SEND_OPT_DFU_SMALL_PKT     = (1 << 2)
};

static unsigned int crc32_lookup_t1[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

#define crc32_step(a,b) \
a = (crc32_lookup_t1[(a & 0xFF) ^ ((unsigned char)b)] ^ (a >> 8))

#define USB_TIMEOUT 10000

#if defined(USE_IOKIT_BACKEND)
static int iokit_usb_control_transfer(irecv_client_t client, uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, unsigned char *data, uint16_t w_length, unsigned int timeout)
{
    IOReturn result;
    IOUSBDevRequestTO req;
    
    bzero(&req, sizeof(req));
    req.bmRequestType     = bm_request_type;
    req.bRequest          = b_request;
    req.wValue            = OSSwapLittleToHostInt16(w_value);
    req.wIndex            = OSSwapLittleToHostInt16(w_index);
    req.wLength           = OSSwapLittleToHostInt16(w_length);
    req.pData             = data;
    req.noDataTimeout     = timeout;
    req.completionTimeout = timeout;
    
    result = (*client->handle)->DeviceRequestTO(client->handle, &req);
    switch (result) {
        case kIOReturnSuccess:         return req.wLenDone;
        case kIOReturnTimeout:         return IRECV_E_TIMEOUT;
#ifdef kIOUSBTransactionTimeout
        case kIOUSBTransactionTimeout: return IRECV_E_TIMEOUT;
#endif
        case kIOReturnNotResponding:   return IRECV_E_NO_DEVICE;
        case kIOReturnNoDevice:        return IRECV_E_NO_DEVICE;
        default:                       break;
    }
    return IRECV_E_UNKNOWN_ERROR;
}
#endif

static irecv_error_t irecv_usb_control_transfer(irecv_client_t client, uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, unsigned char *data, uint16_t w_length, unsigned int timeout)
{
#pragma mark - IOKit
#if defined(USE_IOKIT_BACKEND)
    return iokit_usb_control_transfer(client, bm_request_type, b_request, w_value, w_index, data, w_length, timeout);
#pragma mark - libusb
#elif defined (USE_LIBUSB_BACKEND)
    return IRECV_E_UNSUPPORTED; // TODO
#pragma mark - dummy
#else
    return IRECV_E_UNSUPPORTED; // TODO
#endif
}

static irecv_error_t irecv_reset(irecv_client_t client)
{
#pragma mark - IOKit
#if defined(USE_IOKIT_BACKEND)
    IOReturn result;
    
    result = (*client->handle)->ResetDevice(client->handle);
    if (result != kIOReturnSuccess && result != kIOReturnNotResponding) {
        //debug("error sending device reset: %#x\n", result);
        return IRECV_E_UNKNOWN_ERROR;
    }
    
    result = (*client->handle)->USBDeviceReEnumerate(client->handle, 0);
    if (result != kIOReturnSuccess && result != kIOReturnNotResponding) {
        //debug("error re-enumerating device: %#x (ignored)\n", result);
    }
    return IRECV_E_SUCCESS;
#pragma mark - libusb
#elif defined (USE_LIBUSB_BACKEND)
    return IRECV_E_UNSUPPORTED; // TODO
#pragma mark - dummy
#else
    return IRECV_E_UNSUPPORTED; // TODO
#endif
}


static irecv_error_t irecv_get_status(irecv_client_t client, unsigned int* status)
{
    unsigned char buffer[6];
    memset(buffer, '\0', 6);
    if (irecv_usb_control_transfer(client, 0xA1, 3, 0, 0, buffer, 6, USB_TIMEOUT) != 6) {
        *status = 0;
        return IRECV_E_USB_STATUS;
    }
    *status = (unsigned int) buffer[4];
    return IRECV_E_SUCCESS;
}

static irecv_error_t irecv_send_buffer(irecv_client_t client, unsigned char* buffer, unsigned long length, unsigned int options)
{
#pragma mark - IOKit
#if defined(USE_IOKIT_BACKEND)
    irecv_error_t error = 0;
    
    unsigned int h1 = 0xFFFFFFFF;
    unsigned char dfu_xbuf[12] = {0xff, 0xff, 0xff, 0xff, 0xac, 0x05, 0x00, 0x01, 0x55, 0x46, 0x44, 0x10};
    
    int dfu_crc = 1;
    
    int packet_size = 0x800; // DFU mode
    
    int last = length % packet_size;
    int packets = length / packet_size;
    
    if (last != 0) {
        packets++;
    }
    else {
        last = packet_size;
    }
    
    /* initiate transfer */
    uint8_t state = 0;
    if (irecv_usb_control_transfer(client, 0xa1, 5, 0, 0, (unsigned char*)&state, 1, USB_TIMEOUT) == 1) {
        error = IRECV_E_SUCCESS;
    } else {
        return IRECV_E_USB_UPLOAD;
    }
    switch (state) {
        case 2:
            /* DFU IDLE */
            break;
        case 10:
            // debug("DFU ERROR, issuing CLRSTATUS\n");
            irecv_usb_control_transfer(client, 0x21, 4, 0, 0, NULL, 0, USB_TIMEOUT);
            error = IRECV_E_USB_UPLOAD;
            break;
        default:
            // debug("Unexpected state %d, issuing ABORT\n", state);
            irecv_usb_control_transfer(client, 0x21, 6, 0, 0, NULL, 0, USB_TIMEOUT);
            error = IRECV_E_USB_UPLOAD;
            break;
    }
    
    if (error != IRECV_E_SUCCESS) {
        return error;
    }
    
    int i = 0;
    // unsigned long count = 0;
    unsigned int status = 0;
    int bytes = 0;
    
    for (i = 0; i < packets; i++) {
        int size = (i + 1) < packets ? packet_size : last;
        
        /* Use bulk transfer for recovery mode and control transfer for DFU and WTF mode */
        if (dfu_crc) {
            int j;
            for (j = 0; j < size; j++) {
                crc32_step(h1, buffer[i*packet_size + j]);
            }
        }
        if (dfu_crc && i + 1 == packets) {
            int j;
            if (size + 16 > packet_size) {
                bytes = irecv_usb_control_transfer(client, 0x21, 1, i, 0, &buffer[i * packet_size], size, USB_TIMEOUT);
                if (bytes != size) {
                    return IRECV_E_USB_UPLOAD;
                }
                // count += size;
                size = 0;
            }
            for (j = 0; j < 2; j++) {
                crc32_step(h1, dfu_xbuf[j * 6 + 0]);
                crc32_step(h1, dfu_xbuf[j * 6 + 1]);
                crc32_step(h1, dfu_xbuf[j * 6 + 2]);
                crc32_step(h1, dfu_xbuf[j * 6 + 3]);
                crc32_step(h1, dfu_xbuf[j * 6 + 4]);
                crc32_step(h1, dfu_xbuf[j * 6 + 5]);
            }
            
            char* newbuf = (char*)malloc(size + 16);
            if (size > 0) {
                memcpy(newbuf, &buffer[i * packet_size], size);
            }
            memcpy(newbuf + size, dfu_xbuf, 12);
            newbuf[size + 12] = h1 & 0xFF;
            newbuf[size + 13] = (h1 >>  8) & 0xFF;
            newbuf[size + 14] = (h1 >> 16) & 0xFF;
            newbuf[size + 15] = (h1 >> 24) & 0xFF;
            size += 16;
            bytes = irecv_usb_control_transfer(client, 0x21, 1, i, 0, (unsigned char*)newbuf, size, USB_TIMEOUT);
            free(newbuf);
        }
        else {
            bytes = irecv_usb_control_transfer(client, 0x21, 1, i, 0, &buffer[i * packet_size], size, USB_TIMEOUT);
        }
        
        if (bytes != size) {
            return IRECV_E_USB_UPLOAD;
        }
        
        error = irecv_get_status(client, &status);
        
        if (error != IRECV_E_SUCCESS) {
            return error;
        }
        
        if (status != 5) {
            int retry = 0;
            
            while (retry++ < 20) {
                irecv_get_status(client, &status);
                if (status == 5) {
                    break;
                }
                sleep(1);
            }
            
            if (status != 5) {
                return IRECV_E_USB_UPLOAD;
            }
        }
        
        // count += size;
        // debug("Sent: %d bytes - %lu of %lu\n", bytes, count, length);
    }
    
    if (options & IRECV_SEND_OPT_DFU_NOTIFY_FINISH) {
        irecv_usb_control_transfer(client, 0x21, 1, packets, 0, (unsigned char*) buffer, 0, USB_TIMEOUT);
        
        for (i = 0; i < 2; i++) {
            error = irecv_get_status(client, &status);
            if (error != IRECV_E_SUCCESS) {
                return error;
            }
        }
        
        if (options & IRECV_SEND_OPT_DFU_FORCE_ZLP) {
            /* we send a pseudo ZLP here just in case */
            irecv_usb_control_transfer(client, 0x21, 1, 0, 0, 0, 0, USB_TIMEOUT);
        }
        
        irecv_reset(client);
    }
    
    return IRECV_E_SUCCESS;
#pragma mark - libusb
#elif defined (USE_LIBUSB_BACKEND)
    return IRECV_E_UNSUPPORTED; // TODO
#pragma mark - dummy
#else
    return IRECV_E_UNSUPPORTED; // TODO
#endif
}

#pragma mark - IOKit
#if defined(USE_IOKIT_BACKEND)
uint32_t dfu_send_buffer(IOUSBDeviceInterface245 **handle, const uint8_t* data, size_t length)
{
    uint32_t rv = 0xAAAAAAAA;
    
    irecv_client_t client = NULL;
    
    client = (irecv_client_t)malloc(sizeof(struct irecv_client_private));
    if (client == NULL) {
        rv = 0xAAAAFFFF;
        return rv;
    }
    client->handle = (IOUSBDeviceInterface320 **)handle;
    
    irecv_error_t irecv_rv = irecv_send_buffer(client, (unsigned char*)data, (unsigned long)length, IRECV_SEND_OPT_DFU_NOTIFY_FINISH);
    
    switch (irecv_rv) {
        case IRECV_E_SUCCESS:
            rv = 0;
            break;
        case IRECV_E_NO_DEVICE:
            rv = 0xAAAA0000 | 0x1;
            break;
        case IRECV_E_OUT_OF_MEMORY:
            rv = 0xAAAA0000 | 0x2;
            break;
        case IRECV_E_UNABLE_TO_CONNECT:
            rv = 0xAAAA0000 | 0x3;
            break;
        case IRECV_E_INVALID_INPUT:
            rv = 0xAAAA0000 | 0x4;
            break;
        case IRECV_E_FILE_NOT_FOUND:
            rv = 0xAAAA0000 | 0x5;
            break;
        case IRECV_E_USB_UPLOAD:
            rv = 0xAAAA0000 | 0x6;
            break;
        case IRECV_E_USB_STATUS:
            rv = 0xAAAA0000 | 0x7;
            break;
        case IRECV_E_USB_INTERFACE:
            rv = 0xAAAA0000 | 0x8;
            break;
        case IRECV_E_USB_CONFIGURATION:
            rv = 0xAAAA0000 | 0x9;
            break;
        case IRECV_E_PIPE:
            rv = 0xAAAA0000 | 0xA;
            break;
        case IRECV_E_TIMEOUT:
            rv = 0xAAAA0000 | 0xB;
            break;
        case IRECV_E_UNSUPPORTED:
            rv = 0xAAAA0000 | 0xC;
            break;
        case IRECV_E_UNKNOWN_ERROR:
            rv = 0xAAAA0000 | 0xE;
            break;
        default:
            rv = 0xAAAA0000 | 0xF;
            break;
    }
    if (client) {
        free(client);
        client = NULL;
    }
    return rv;
}
#pragma mark - libusb
#elif defined (USE_LIBUSB_BACKEND)
uint32_t dfu_send_buffer(void **handle, const uint8_t* data, size_t length) { return 0xFFFFFFFA; };
#pragma mark - dummy
#else
extern uint32_t dfu_send_buffer(void **handle, const uint8_t* data, size_t length) { return 0xFFFFFFFB; };
#endif
