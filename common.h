//
// PV Display Helper
//
// Copyright (C) 2016 - 2017 Assured Information Security, Inc. All rights reserved.
//
#ifndef COMMON__H
#define COMMON__H

#if defined __linux__ && defined __KERNEL__
#include <linux/mutex.h>
#include <xen/interface/xen.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/init.h>
#elif defined __linux__
#include <pthread.h>
#include "data-structs/list.h"
#define PAGE_SIZE 0x1000
#define PAGE_MASK ~((uintptr_t)(PAGE_SIZE - 1))
#endif

//For now, let libivc know that we're running in a kernel. Really, this should
//be fixed so libivc detects the standard predefines for the linux kernel.
#if defined __linux__ && defined __KERNEL__
#define KERNEL
#elif defined _WIN32 && defined KERNEL
#include <wdm.h>
#include <windef.h>
#include <wintypes.h>
#include <ntifs.h>
#include <wdf.h>
#define BUG() do { \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
} while(0)
#elif defined _WIN32
#include <windows.h>
#include <wintypes.h>
#include <stdio.h>
#include <stdlib.h>
#define BUG() do { \
    fprintf(stderr,"BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
} while(0)
#elif defined __linux__
#include <stdio.h>
#include <stdlib.h>
#endif

#if defined _WIN32
#define MEM_TAG 'cviP'
#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12L
#endif
#ifndef PAGE_MASK
#define PAGE_MASK ~((uintptr_t)(PAGE_SIZE - 1))
#endif
#define SUCCESS 0
#define __func__ __FUNCTION__
#define inline _inline
#endif
#define CONNECTIONID_ANY 0xFFFFFFFFFFFFFFFF //big
//Include the IVC InterVM communciations "library".
#include <libivc.h>
#ifdef __linux
#include <xen/xen.h>
#endif
#include "pv_driver_interface.h"

#ifdef _WIN32
#define SIZE_FORMAT "%Id"
#else
#define SIZE_FORMAT "%zd"
#endif

//If uncommented, the following line prints out verbose debug input relating
//to all use of locking functions.
//#define DEBUG_LOCKS
//#define DISPLAY_HELPER_DEBUG

/******************************************************************************/
/* Useful Quick Functions                                                     */
/******************************************************************************/

/*
 * We use ARGB buffers for the guests. This is the format going from left to
 * right, or in other words, A is the upper most bits, and B is the lower
 * most bits.
 */
static const size_t bits_per_pixel = 32;

/**
 * Quick function to return the amount of bytes necessary to store a number of pixels.
 */
static inline size_t pixels_to_bytes(size_t pixels)
{
    return pixels * (bits_per_pixel / 8);
}

/**
 * Quick function return the amount of bytes necessary to store a framebuffer.
 */
static inline size_t bytes_to_store_framebuffer(size_t stride, size_t height)
{
    return pixels_to_bytes(stride) * height;
}


/**
 * By its spec, a hardware cursor image is guaranteed to be 64x64 with a stride
 * of 64 pixels. At 32bpp, this should take 16,384 bytes.
 */
#define CURSOR_IMAGE_SIZE (64 * 64 * (bits_per_pixel / 8))


/******************************************************************************/
/* Forward Declarations                                                       */
/******************************************************************************/

struct pv_display;
struct pv_display_provider;

/**
 * PV Cursor Information
 * Stores all information regarding to a paravirtualized cursor.
 */
struct pv_cursor
{
    //A pointer to a 64x64 ARGB8888 cursor bitmap,
    //which is shared directly with the display handler host,
    //or NULL if PV cursors are not supported.
    void *image;

    //The cursor's hot spot-- that is, the location on the
    //cursor that represents the click target.
    uint32_t hotspot_x;
    uint32_t hotspot_y;

    //Stores whether the cursor is initially visible.
    bool visible;
};

/******************************************************************************/
/* Debug Macros                                                               */
/******************************************************************************/

#if defined WIN32 && defined KERNEL
#define pv_display_checkp(a,...) if (!(a)) {DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "pv_display_helper: %s failed. %s == NULL\n", __PRETTY_FUNCTION__, #a); return __VA_ARGS__; }
#define pv_display_error(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "pv_display_helper[error]: " __VA_ARGS__);
#elif defined WIN32
#define pv_display_checkp(a,...) if (!(a)) {fprintf(stderr,"pv_display_helper: %s failed. %s == NULL\n", __PRETTY_FUNCTION__, #a); return __VA_ARGS__; }
#define pv_display_error(...) fprintf(stderr, "pv_display_helper[error]: " __VA_ARGS__);
#elif defined __linux__ && defined __KERNEL__
#define pv_display_checkp(a,...) if (!(a)) {printk(KERN_ERR "pv_display_helper: %s failed. %s == NULL\n", __PRETTY_FUNCTION__, #a); return __VA_ARGS__; }
#define pv_display_error(...) pr_err("pv_display_helper[error]: " __VA_ARGS__);
#else
#define pv_display_checkp(a,...) if (!(a)) {fprintf(stderr, "pv_display_helper: %s failed. %s == NULL\n", __PRETTY_FUNCTION__, #a); return __VA_ARGS__; }
#define pv_display_error(...) fprintf(stderr, "pv_display_helper[error]: " __VA_ARGS__);
#endif


//If debug is on, automatically promote our dynamic debug statements to info statements,
//so they don't need to explicitly be turned on.
//TODO: Drop the dynamic debug on the trace statements once the display handler is stable.
#if defined(WIN32) && defined(DISPLAY_HELPER_DEBUG)
#define pv_display_debug(...) KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "pv_display_helper[debug]: " __VA_ARGS__));
#define __PV_HELPER_TRACE__ do {KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "TRACE: %s:%i\n",  __func__, __LINE__)); }while(0)
#elif defined(DISPLAY_HELPER_DEBUG) && defined(__linux__) && defined(__KERNEL__)
#define pv_display_debug(...) pr_info("pv_display_helper[debug]: " __VA_ARGS__);
#define __PV_HELPER_TRACE__ do { pr_info("TRACE: %s:%i\n",  __func__, __LINE__); } while(0);
#elif defined(__linux__) && defined(__KERNEL__)
#define pv_display_debug(...) pr_debug("pv_display_helper[debug]: " __VA_ARGS__);
#define __PV_HELPER_TRACE__ do { pr_debug("TRACE: %s:%i\n",  __func__, __LINE__); } while(0);
#elif defined(DISPLAY_HELPER_DEBUG)
#define  pv_display_debug(...) fprintf(stderr, "pv_display_helper[debug]: " __VA_ARGS__);
#define __PV_HELPER_TRACE__
#else
#define pv_display_debug(...)
#define __PV_HELPER_TRACE__
#endif


/******************************************************************************/
/* Platform Abstractions                                                      */
/******************************************************************************/


/**
 * Lock debug code.
 * These macros allow one to more easily debug locking problems in the PV display helper.
 */
#ifdef DEBUG_LOCKS
#define pv_helper_lock(name) do { pv_display_debug("LOCK: %s -- %s:%d\n", #name, __FUNCTION__, __LINE__); __pv_helper_lock(name); } while(0)
#define pv_helper_unlock(name) do { pv_display_debug("UNLOCK: %s -- %s:%d\n", #name, __FUNCTION__, __LINE__); __pv_helper_unlock(name); } while(0)
#else
#define pv_helper_lock(name) __pv_helper_lock(name)
#define pv_helper_unlock(name) __pv_helper_unlock(name)
#endif

/**
 * These platform-agnostic "shims" abstract away per-platform functionality,
 * allowing the same code to be used from various kernels and userspaces.
 */

#if defined __linux__ && defined __KERNEL__
/**
 * Platform agnostic macro for delcaring a mutex.
 */
#define PV_HELPER_DEFINE_MUTEX(name) DEFINE_MUTEX(name)

/**
 * Platform agnostic type for mutexes.
 */
typedef struct mutex pv_helper_mutex;


/**
 * Platform-agnostic function for memory allocation.
 *
 * This current iteration assumes it will never be called from an interrupt context,
 * and thus may block. If you need to call this from an interrupt context, remove the
 * might_sleep() and replace GFP_KERNEL with GFP_ATOMIC.
 */
static inline void *pv_helper_malloc(size_t size)
{
    might_sleep();
    return kzalloc(size, GFP_KERNEL);
}


/**
 * Platform-agnostic function for freeing memory.
 */
static inline void pv_helper_free(void *buffer)
{
    kfree(buffer);
}


/**
 * Platform-agnostic function for initializing a mutex.
 */
static inline void pv_helper_mutex_init(pv_helper_mutex *lock)
{
    mutex_init(lock);
}


/**
 * Platform-agnostic function for locking a mutex.
 */
static inline void __pv_helper_lock(pv_helper_mutex *lock)
{
    mutex_lock(lock);
}


/**
 * Platform-agnostic function for unlocking a mutex.
 */
static inline void __pv_helper_unlock(pv_helper_mutex *lock)
{
    mutex_unlock(lock);
}
#elif defined __linux__
// Linux userspace/QEmu specifics
#define PV_HELPER_DEFINE_MUTEX(name) pv_helper_mutex name = PTHREAD_MUTEX_INITIALIZER
#define unlikely(x) (x)
// This is bad... in userland we can use getpagesize(), but
// without dragging math.h in here for log2, or looping and
// shifting we can't easily get the shift. Hardcode for now,
// ARM guys will have to sort this out in a sane fashion :D.
#define PAGE_SHIFT 12
#define PAGE_ALIGN(x) (x&(~((1<<PAGE_SHIFT)-1)))
#define BUG() exit(-1)
/**
 * Platform agnostic type for mutexes.
 */

typedef pthread_mutex_t pv_helper_mutex;

/**
 * Platform-agnostic function for memory allocation.
 *
 * This current iteration assumes it will never be called from an interrupt context,
 * and thus may block. If you need to call this from an interrupt context, remove the
 * might_sleep() and replace GFP_KERNEL with GFP_ATOMIC.
 */
static inline void *pv_helper_malloc(size_t size)
{
    void *ptr = malloc(size);
    memset(ptr, 0x00, size);
    return ptr;
}


/**
 * Platform-agnostic function for freeing memory.
 */
static inline void pv_helper_free(void *buffer)
{
    free(buffer);
}


/**
 * Platform-agnostic function for initializing a mutex.
 */
static inline void pv_helper_mutex_init(pv_helper_mutex *lock)
{
    pthread_mutex_init(lock, NULL);
}


/**
 * Platform-agnostic function for locking a mutex.
 */
static inline void __pv_helper_lock(pv_helper_mutex *lock)
{
    pthread_mutex_lock(lock);
}


/**
 * Platform-agnostic function for unlocking a mutex.
 */
static inline void __pv_helper_unlock(pv_helper_mutex *lock)
{
    pthread_mutex_unlock(lock);
}
#elif defined KERNEL
_IRQL_requires_same_
static inline void *pv_helper_malloc(size_t size);

_IRQL_requires_same_
static inline void pv_helper_free(void *buffer);

#pragma alloc_text("PAGED_CODE", pv_helper_malloc)
#pragma alloc_text("PAGED_CODE", pv_helper_free )

typedef FAST_MUTEX pv_helper_mutex;
#define unlikely(x) (x)

/**
 * Platform-agnostic function for memory allocation.
 *
 * This current iteration assumes it will never be called from an interrupt context,
 * and thus may block.
 */
_IRQL_requires_same_
static inline void *pv_helper_malloc(size_t size)
{
    void * data = NULL;
    PAGED_CODE();
    data = ExAllocatePoolWithTag(NonPagedPool, size, MEM_TAG);
    //Zero memory on successful allocation.
    if (data)
    {
      RtlZeroMemory(data, size);
    }
    return data;
}

/**
 * Platform-agnostic function for freeing memory.
 */
_IRQL_requires_same_
static inline void pv_helper_free(void *buffer)
{
    PAGED_CODE();
    if (buffer)
    {
      ExFreePool(buffer);
    }
}

/**
 * Platform-agnostic function for initializing a mutex.
 */
static inline void pv_helper_mutex_init(pv_helper_mutex *lock)
{
    ExInitializeFastMutex(lock);
}

/**
 * Platform-agnostic function for locking a mutex.
 */
_IRQL_raises_(APC_LEVEL)
_IRQL_saves_global_(FAST_MUTEX, lock)
static inline
void __pv_helper_lock(
_Inout_ _Requires_lock_not_held_(*_Curr_) _Acquires_lock_(*_Curr_)
                      pv_helper_mutex *lock)
{
    ExAcquireFastMutex(lock);
}

/**
 * Platform-agnostic function for unlocking a mutex.
 */
_IRQL_requires_(APC_LEVEL)
_IRQL_restores_global_(FAST_MUTEX, lock)
static inline void __pv_helper_unlock(
_Inout_ _Requires_lock_held_(*_Curr_) _Releases_lock_(*_Curr_)
                                      pv_helper_mutex *lock)
{
  ExReleaseFastMutex(lock);
}
#else
typedef HANDLE pv_helper_mutex;
#define unlikely(x) (x)


static inline void *pv_helper_malloc(size_t size)
{
    void * data = NULL;
    data = malloc(size);
    //Zero memory on successful allocation.
    if (data)
    {
        RtlZeroMemory(data, size);
    }
    return data;
}

/**
* Platform-agnostic function for freeing memory.
*/
static inline void pv_helper_free(void *buffer)
{
    if (buffer)
    {
        free(buffer);
    }
}

static inline void pv_helper_mutex_init(pv_helper_mutex *lock)
{
    *lock = CreateMutex(NULL, 0, NULL);
}

static inline void __pv_helper_lock(pv_helper_mutex *lock)
{
    DWORD res;
    res = WaitForSingleObject(*lock, INFINITE);
}

static inline void __pv_helper_unlock(pv_helper_mutex *lock)
{
    ReleaseMutex(*lock);
}

#endif


/**
 * Platform agnostic function to page-align an address.
 */
static inline uintptr_t align_to_next_page(uintptr_t address)
{
    //Round the address up to the next page
    address = address + ~PAGE_MASK;

    //... and clear off everything but the PFN.
    return address & PAGE_MASK;
}

/******************************************************************************/
/* Internal Data                                                              */
/******************************************************************************/


/**
 * CRC look-up table for the CRC-16-CCITT algorithm below.
 */
static const uint16_t crc_tbl[16] =
{
    0x0000, 0x1081, 0x2102, 0x3183,
    0x4204, 0x5285, 0x6306, 0x7387,
    0x8408, 0x9489, 0xa50a, 0xb58b,
    0xc60c, 0xd68d, 0xe70e, 0xf78f
};

/**
 * Compute the CRC-16-CCITT, as used by the Display Handler.
 *
 * @param data_sections Array of "data sections" to be checksummed; each array member should be
 *    a pointer to a section of binary data to be included in the checksum.
 * @param data_lengths The lengths of the data sections in the data sections array.
 * @param sections The data sections
 *
 * @return The CRC-16-CCITT of the given data.
 */
static int16_t __pv_helper_checksum(void **data_sections, size_t *data_lengths, size_t sections)
{
    uint16_t crc = 0xffff;
    size_t i;
    
    __PV_HELPER_TRACE__;

    //For each of the provided data sections.
    for(i = 0; i < sections; ++i)
    {

        //Get a reference to the data item to be processed...
        const unsigned char *p = (const unsigned char *)data_sections[i];
        unsigned char c;
        size_t len = data_lengths[i];

        //... and compute the CRC for the given section..
        while(len--)
        {
            c = *p++;
            crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
            c >>= 4;
            crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
        }
    }

    return ~crc & 0xffff;
}


/**
 * Conveience version of the PV helper checksum function, which accepts a seperate header
 * and payload. Used for packet transmission and receipt.
 *
 * @param data The data to be checksummed.
 * @param len The lenghth of the data to be checksummed.
 *
 * @return The CRC-16-CCITT of the given data.
 */
static inline uint16_t __pv_helper_packet_checksum(struct dh_header *header, void *payload, size_t payload_length)
{
    //Place the relevant sections into arrays.
    void *data_sections[] = { header, payload };
    size_t data_lengths[]  = { sizeof(struct dh_header), payload_length };

    __PV_HELPER_TRACE__;

    //Compute the checksum.
    return __pv_helper_checksum(data_sections, data_lengths, 2);
}


/**
 * Convenience version of the PV helper checksum function which accepts a single binary
 * blob as its argument. May disappear shortly.
 *
 * @param data The data to be checksummed.
 * @param len The lenghth of the data to be checksummed.
 *
 * @return The CRC-16-CCITT of the given data.
 */
static inline uint16_t __pv_helper_blob_checksum(void *data, size_t len)
{
    __PV_HELPER_TRACE__;
    return __pv_helper_checksum(&data, &len, 1);
}


/**
 * Sends a binary payload over a provided IVC communications channel.
 * Executes "atomically", from the channel's perspective-- so no lock needs to be held while using this.
 *
 * @param channel The channel over which the data is to be transmitted.
 * @param type The packet type to be transmitted, as defined by the PV display interface.
 * @param length The length of the data to be transmitted.
 *
 * @return 0 on success, or an error code on failure.
 */
static int __send_packet(struct libivc_client *channel, uint32_t type, void *data, uint32_t length)
{
    char *transmit_buffer;
    struct dh_header *header;
    struct dh_footer *footer;
    size_t available;
    size_t packet_length;
    char *payload;
    int rc;

    if(!libivc_isOpen(channel)) {
        return -ENOENT;
    }

    available = 0;

    //Compute the size of the packet to be transmitted.
    packet_length = sizeof(struct dh_header) + length + sizeof(struct dh_footer);

    __PV_HELPER_TRACE__;

    //Allocate space for the full packet...
    transmit_buffer = (char*)pv_helper_malloc(packet_length);

    //If we weren't able to get a buffer for transmission, error out.
    if(!transmit_buffer)
        return -ENOMEM;

    //Create simple convenience pointers to the header, payload, and footer
    //within the allocated buffer.
    header  = (struct dh_header *)transmit_buffer;
    payload = transmit_buffer + sizeof(struct dh_header);
    footer  = (struct dh_footer *)(payload + length);

    //Populate the packet's header...
    header->magic1 = PV_DRIVER_MAGIC1;
    header->magic2 = PV_DRIVER_MAGIC2;
    header->type   = type;
    header->length = length;

    //... payload ...
    memcpy(payload, data, length);

    //... and footer.
    footer->crc = __pv_helper_blob_checksum(transmit_buffer, sizeof(struct dh_header) + length);

    //Output a short debug message, which can be removed once this is stable.
    pv_display_debug("SEND: Type %u, len = %u, crc= %u\n", (unsigned int)header->type,
                     (unsigned int)header->length, (unsigned int)footer->crc);

    if((rc = libivc_getAvailableSpace(channel, &available))) {
        return rc;
    }

    if(available < packet_length) {
        return -ENOMEM;
    }

    //Finally, attempt to send the packet via the provided channel.
    rc = libivc_send(channel, transmit_buffer, packet_length);

    libivc_notify_remote(channel);
    libivc_notify_remote(channel);

    //Free the allocated transmit buffer.
    pv_helper_free(transmit_buffer);

    //... and return the final status of the transmission.
    return rc;
}

#endif // COMMON__H
