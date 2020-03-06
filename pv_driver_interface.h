// 
// OpenXT Paravirtualized Display Helpers for the Display Handler
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
// Author: Kyle J. Temkin  <temkink@ainfosec.com>
//

/**
 *
 * IVC Channels
 * ------------
 *
 * There is 1 main control channel, and then there is 4 additional channels
 * that are established _per display_.
 *
 * Control Channel: Most of the communications in this interface go over the
 *     control channel. This is the only channel with a static port # as well
 *     which is 1000. Each driver must connection to port 1000, and then
 *     send / receive most of it's data through this channel.
 *
 * Event Channel: The event channel is a per display channel, who's port is
 *     provided by the display handler in the dh_add_display. This
 *     channel is used by the driver to send display specific information
 *     which includes the display's resolution and stride and cursor updates.
 *
 * Framebuffer Channel: The framebuffer channel is a per display channel, who's
 *     port is provided by the display handler in the dh_add_display.
 *     This is an IVC buffer that is used to share a framebuffer between the
 *     driver and the display handler.
 *
 * Dirty Rect Channel: The dirty rect channel is a per display channel, who's
 *     port is provided by the display handler in the dh_add_display.
 *     This channel is typically "polled" by the display handler until it
 *     exhausts the channel. This means that the display handler will enable
 *     / disable events coming from this channel to optimize world switching.
 *     The packets in this channel are also just rectangle. These packets do
 *     not contain a head or foot, as the display handler has a special
 *     receiver for this channel to always and only read in 16 bytes at a time.
 *     There is no need to optimize the dirty regions in the driver. Simply
 *     send each dirty rectangle through this channel when it becomes available.
 *
 * Cursor Image: The cursor image channel is a per display channel, who's
 *     port is provided by the display handler in the dh_add_display.
 *     This is an IVC buffer that is used to share a cursor image between the
 *     driver and the display handler.
 *
 * Also note that the control channel and the event channel support dynamic
 * length packets, but we still do length checking for security reasons. So
 * for example, it would be possible to construct a set of packets where the
 * footer is always located at the bottom of the maximum size packet, and then
 * you fill in the body as needed, but the display handler would detect that
 * a packet was sent with extra space and complain. In other words, only send
 * the number of bytes that is needed and no more as the display handler will
 * attempt to validate this information.
 *
 * Intialization Sequence
 * ----------------------
 *
 * Display Handler                      Driver
 *  1. Listens on port 1000 ------>|
 *                                 |<-- 2. Connects to port 1000
 *                                 |<-- 3. dh_driver_capabilities
 *  4. dh_display_list ----------->|
 *                                 |<-- 5. dh_display_advertised_list
 *  6. dh_add_display ------------>|
 *                                 |<-- 7. Connects to Event Port
 *                                 |<-- 8. Connects to Framebuffer Port
 *                                 |<-- 9. Connects to Dirty Rect Port
 *                                 |<-- A. Connects to Cursor Image Port
 *                                 |<-- B. dh_set_display
 *
 *
 * Note that the display handler's init sequence is entirely reactionary. This
 * means that the driver can take it's time for each step. Once the driver
 * makes it to the next step, the display handle will respond right away with
 * the next part of the sequence.
 *
 * It is also possible for the driver to start over mid-way through the
 * sequence. So long as the keying information is still valid, the display
 * handler will accept information it can make sense of.
 *
 * Host Physical Display Plug Event
 * --------------------------------
 *
 * Display Handler                      Driver
 *  1. dh_display_list ----------->|
 *                                 |<-- 2. Sends dh_display_advertised_list
 *  3. dh_add_display ------------>|
 *                                 |<-- 4. Connects to Event Port
 *                                 |<-- 5. Connects to Framebuffer Port
 *                                 |<-- 6. Connects to Dirty Rect Port
 *                                 |<-- 7. Connects to Cursor Image Port
 *                                 |<-- 8. dh_set_display
 *
 *
 * If the host physical displays ever change, the display handler will
 * provide the entire list of displays to the driver. It's up to the driver to
 * identify if anything has changed. When the display handler send's it's list,
 * the driver must always return all of the displays that it plans on using
 * with the dh_display_advertised_list. Any display missing in this list
 * will be removed by the display handler.
 *
 * Once the display handler knows what displays the driver plans on using,
 * it will send the dh_add_display for each display. In this case, the
 * driver can ignore dh_add_display packets if it already has an open
 * connection to the display. For the display handler to use a new display,
 * or update a display's resolution from the guest, the driver msut reply with
 * udpated dh_set_display packets.
 *
 * Guest Display Update
 * --------------------
 *
 * If the guest's resolution changes, it must provide this inforamtion to the
 * display handler. There are two possible ways that the guest could change
 * it's resolution:
 *
 * - The framebuffer can stay the same, and the resolution could change. If
 *   this occurs, the stride is likely to be different as well to account for
 *   the framebuffer remaining the same size.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_set_display
 *
 *
 * - The framebuffer can be replaced, and then a size change can occur. Using
 *   this model, the driver can maintain a frambuffer that is sized the same
 *   as the resolution at all times. When the driver reconnects to the
 *   framebuffer port, the display handler will ditch the old frambuffer and
 *   invalidate it. The display will not be used until the drivers sends the
 *   dh_set_display again.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. Connects to Framebuffer Port
 *                                 |<-- 2. dh_set_display
 *
 *
 * The display handler is smart enough to handle both situations, as well as
 * potential problems with these approaches.
 *
 * Host Physical Display Unplug Event
 * ----------------------------------
 *
 * If the host loses a display (which can happen from an unplug event, or
 * the user simply turning off the physical display), the host will send a
 * remove display event.
 *
 * Display Handler                      Driver
 *  1. dh_remove_display --------->|
 *
 *
 * Guest Display Unplug Event
 * --------------------------
 *
 * If the guest needs to disable a display, it can tell the display handler
 * that the display is no longer needed by sending the following
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_display_no_longer_available
 *
 * The guest can also simply disconnect itself from the various different
 * display ports (mainly the framebuffer and / or the event port). Doing
 * so will cause the display handler to disable the display simply because
 * it doesn't have the resources needed to display.
 *
 * Driver Teardown
 * ---------------
 *
 * The teardown process could be two different scenarios:
 * - Driver gracefully tears down each display, disconnects, and shuts down.
 * - Guest VM completely crashes
 *
 * The display handler must be able to support both scenarios as it is posisble
 * for a guest to crash. A graceful shutdown looks like this
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_display_no_longer_available
 *                                 |<-- 2. Disconnects from Event Port
 *                                 |<-- 3. Disconnects from Framebuffer Port
 *                                 |<-- 4. Disconnects from Dirty Rect Port
 *                                 |<-- 5. Disconnects from Cursor Image Port
 *                                 |<-- 6. Disconnects from Port 1000
 *
 * Display Handler Teardown
 * ------------------------
 *
 * It is possible for the display handler to teardown first. When this occurs
 * its likely that the display handler has crashed, and had to restart
 * itself. If possible the display handler will look like this:
 *
 * Display Handler                      Driver
 *  1. dh_remove_display -->|
 *  2. Disconnects All Ports ----->|
 *
 * It is also possible that all the driver sees is a disconnection as the
 * entire user space process in dom0 could crash (e.g. segfault), in which
 * case, the driver will need to handle this situation gracefully
 *
 * Reconnect
 * ---------
 *
 * If the guest needs to reconnect for whatever reason, it will simply redo the
 * initialization process. Note that it is possible to start somewhere in the
 * middle of the process assuming that you have the proper bookeeping. But
 * it's most likely safer to restart everything.
 *
 * If the display handler needs to reconnect (in the event of a crash), the
 * drivers will need to place themselves in a waiting state. There will be no
 * event from dom0 signaling that the display handler is ready, so it's up to
 * the driver to attempt to reconnect to port 1000. Once a successful connection
 * is possible, the driver can start it's initialization sequence again.
 *
 * Text Mode
 * ---------
 *
 * Even if the PV driver is working completely, it is possible for QEMU (which
 * also uses this interface) to request that the display handler render it's
 * framebuffer instead of the PV driver's framebuffer. This is provided to
 * support "text mode" with the likely use case being a Windows BSOD since
 * the Linux virtual console now uses basic FB support. If QEMU wishes to send
 * this message, it can do so by sending the text mode packet, with mode set
 * to the text mode enum defined in this file.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_text_mode
 *
 * Hardware Cursor
 * ---------------
 *
 * The PV driver can connect to the cursor image port to provide a hardware
 * cursor. Note that this is entirely optional, as the guest can draw the
 * cursor itself, providing dirty rects when the cursor moves. Using a hardware
 * cursor will however results in better power usage and performance, while
 * also helping to remove cursor flickering.
 *
 * Note that the display handler assumes that the width and height of the
 * cursor is 64x64, and the stride is also 64. It is perfectly ok for the
 * PV driver to allocate more space in the cursor image buffer than is needed,
 * as the extra space will be ignored, but the stride is assumed to be 64.
 * The format of the cursor is also expected to be ARGB, which means that
 * for PV drivers like the Windows PV driver, format conversion will need to
 * be done prior to writing the data to the buffer.
 *
 * The display handler is capable of displaying multiple guests all at the
 * same time. It also has to deal with displaying portions of a cursor on
 * all displays (depending on cursor location, and OS implementations). For
 * this reason, how the cursor is drawn is left to PV driver to manage. The
 * display handler simply provides the ability to display a cursor on each
 * display that is presented to the guest. The PV driver must figure out which
 * display the cursor should be located on (if not more than one due to the
 * cursor being on an edge, being shown in more than one display at the same
 * time).
 *
 * All x, y, xhot and yhot cords are with respect to the the PV driver's
 * resolution for each display. If the display handler's host displays don't
 * match the guest's displays, the display handler will scale the cords
 * as needed.
 *
 * The following attempts to describe how a cursor would be moved from one
 * monitor to another. For the purposes of this example, there are two
 * displays (d1 on the left, and d2 on the right) with event channels e1 (for
 * d1) and e2 (for d2), and the cursor is being moved from d2 to d1.
 *
 * To start, the PV driver should tell the display handler where the cursor
 * should be located. This way, when the cursor is shown, it is in the proper
 * location to start. Note that in this example, the cursor starts on d2, so
 * the PV driver would send the move cursor packet on the event channel
 * associated with d2.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_move_cursor (e2)
 *
 * Now that the display handler has placed the cursor in the proper location,
 * the PV driver should tell the display handler to show the cursor. To start
 * process, the PV driver first needs to provide the cursor image. Since the
 * PV driver has a cursor image per display, the PV driver has two options:
 * - Draw the cursor image into each cursor image channel each time the
 *   cursor image changes on the guest
 * - Cache the cursor image, and draw the cursor image in the channel that is
 *   needed.
 *
 * Not really sure which option above is better. When the cursor image is not
 * really chaning a lot, it's probably better to draw the image in each channel
 * when it changes. However, on OSes like Windows, where the cursor can change
 * a lot (the I beam is in mono, and is the inverse of it's background, which
 * means that it can change on each and every pixel move or the cursor), it
 * is probably better to cache the cursor, and only draw the image into the
 * channel that needs it.
 *
 * Note that the cursor image channel is just like the framebuffer channel, in
 * that it is in ARGB, which means that if a format change is needed, it
 * should be done by the PV driver prior to writing into the image. if the
 * cached approach is used, it might make sense to cache the converted version.
 *
 * Once the cursor image channel has the cursor image, the PV driver needs to
 * tell the display handler to display the cursor. It does so by sending the
 * update packet with the "show" variable set to PACKET_CURSOR_SHOW
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_update_cursor (e2)
 *
 * At this point, the display handler is now showing the hardware cursor. We
 * not need to move the cursor. To do this, the PV driver should send the move
 * packet each time the cursor moves.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_move_cursor (e2)
 *
 * At some point, the cursor will hit the edge of d2, which the PV driver needs
 * to detect on it's own. When this occurs, the PV driver needs to do some
 * work, based on how the OS is implemented. On most operating systems, the
 * cursor can be shown on both displays, to help the user understand it's
 * transitioning between displays. Once the cursor becomes visible on both
 * screens, the PV driver should start by moving the cursor on d2 to the
 * proper location
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_move_cursor (e2)
 *
 * The next step is to show the cursor on d1. The process of doing this is the
 * same as when the cursor is first shown (described above). To start, the
 * cursor on d1 should be moved.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_move_cursor (e1)
 *
 * And then the cursor should be shown
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_update_cursor (e1)
 *
 * Once the cursor is no longer shown on the d2 (i.e. the cursor has moved
 * to a point where it is entirely located on d1), the PV driver should tell
 * the dislay handler that the cursor is no longer visible by sending an update
 * on d2 with the "show" variable set to PACKET_CURSOR_HIDE.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_update_cursor (e2)
 *
 * Finally, the PV driver can continue to send cursor move packets on d1 until
 * the cursor stops moving (for this example)
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_move_cursor (e1)
 *
 * Display Blanking
 * ---------------
 * In order to handle modesetting without the seizure inducing flashing people
 * are accustomed to, provide a way to tell display handler that the display's
 * current framebuffer contents aren't really worth rendering. This also
 * provides a mechanism for handling DPMS requests by guest operating systems,
 * whether we just fill a dummy buffer, or actually pass the DPMS message to
 * a host monitor is implementation depended.
 *
 * To unblank, and additional message is sent, with a flag to indicate to tear
 * down whatever blanking was setup.
 *
 * Display Handler                      Driver
 *                                 |<-- 1. dh_blanking (e1)
 *
 * CRC Calculation
 * ---------------
 *
 * The following defines the CRC function that is used.
 *
 * typedef unsigned char uchar;
 *
 * static const uint16_t crc_tbl[16] = {
 *   0x0000, 0x1081, 0x2102, 0x3183,
 *   0x4204, 0x5285, 0x6306, 0x7387,
 *   0x8408, 0x9489, 0xa50a, 0xb58b,
 *   0xc60c, 0xd68d, 0xe70e, 0xf78f
 * };
 *
 * uint16_t dh_crc16(const char *data, size_t len)
 * {
 *   register uint16_t crc = 0xffff;
 *   unsigned char c;
 *   const unsigned char *p = (const unsigned char *)(data);
 *   while (len--) {
 *     c = *p++;
 *     crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
 *     c >>= 4;
 *     crc = ((crc >> 4) & 0x0fff) ^ crc_tbl[((crc ^ c) & 15)];
 *   }
 *   return ~crc & 0xffff;
 * }
 */

#ifndef __PV_DRIVER_INTERFACE__
#define __PV_DRIVER_INTERFACE__

#if defined __linux__ && defined __KERNEL__
#include <linux/types.h>
#elif defined _WIN32
#pragma warning(disable:4200)
#pragma warning(disable:4204)
#include <wintypes.h>
#else
#include <stdint.h>
#endif

#pragma pack(push, 1)



/**
 * Display Handler Packet Header
 *
 * @var magic1 should be set to PV_DRIVER_MAGIC1
 * @var magic2 should be set to PV_DRIVER_MAGIC2
 * @var type should be set to PACKET_TYPE_XXX
 * @var length of the packet's payload or
 *      sizeof(xxx) - (sizeof(dh_header) + sizeof(dh_footer))
 * @var dh_reserved_word is unused
 */
struct dh_header
{
    uint16_t magic1;
    uint16_t magic2;
    uint32_t type;
    uint32_t length;
    uint32_t dh_reserved_word;
};

/**
 * The following defines:
 * - dh_header->magic1
 * - dh_header->magic2
 */
#define PV_DRIVER_MAGIC1 (0xC0DE)
#define PV_DRIVER_MAGIC2 (0x5AFE)

/**
 * Defines the maximum packet and payload sizes based on the size of the
 * header and footer.
 */
#define PV_DRIVER_MAX_PACKET_SIZE (4096U)
#define PV_DRIVER_MAX_PAYLOAD_SIZE (PV_DRIVER_MAX_PACKET_SIZE - (sizeof(struct dh_header) + sizeof(struct dh_footer)))

/**
 * Defines the dh_header->type field for the control channel
 */
enum
{
    PACKET_TYPE_CONTROL_NONE                          = 0,
    PACKET_TYPE_CONTROL_DRIVER_CAPABILITIES           = 1,
    PACKET_TYPE_CONTROL_HOST_DISPLAY_LIST             = 2,
    PACKET_TYPE_CONTROL_ADVERTISED_DISPLAY_LIST       = 3,
    PACKET_TYPE_CONTROL_ADD_DISPLAY                   = 4,
    PACKET_TYPE_CONTROL_REMOVE_DISPLAY                = 5,
    PACKET_TYPE_CONTROL_DISPLAY_NO_LONGER_AVAILABLE   = 6,
    PACKET_TYPE_CONTROL_TEXT_MODE                     = 7,
    PACKET_TYPE_CONTROL_END                           = 8
};

/**
 * Defines the dh_header->type field for the event channels
 */
enum
{
    PACKET_TYPE_EVENT_NONE                            = 100,
    PACKET_TYPE_EVENT_SET_DISPLAY                     = 101,
    PACKET_TYPE_EVENT_UPDATE_CURSOR                   = 102,
    PACKET_TYPE_EVENT_MOVE_CURSOR                     = 103,
    PACKET_TYPE_EVENT_BLANK_DISPLAY                   = 104,
    PACKET_TYPE_EVENT_END                             = 105
};



/**
 * Display Handler Packet Footer
 *
 * @var crc should be set to dh_crc16(dh_header + payload)
 * @var dh_reserved_halfword is unused
 * @var dh_reserved_word is unused
 */
struct dh_footer
{
    uint16_t crc;
    uint16_t dh_reserved_halfword;
    uint32_t dh_reserved_word;
};



/**
 * Display Handler Display Info
 *
 * @var key defines a unique identifier for each display
 * @var x is unused
 * @var y is unused
 * @var width defines the width of the display
 * @var height defines the height of the display
 * @var dh_reserved_word is unused
 */
struct dh_display_info
{
    uint32_t key;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint32_t dh_reserved_word;
};

                                    /* These flags indicate that the driver provides
				       the following capabilities:                  */
#define DH_CAP_LFB        (1<<0)    /* Linear Framebuffer                           */
#define DH_CAP_HW_CURSOR  (1<<1)    /* Hardware Cursor                              */
#define DH_CAP_RESIZE     (1<<2)    /* Online resolution resizing                   */
#define DH_CAP_RECONNECT  (1<<3)    /* Handle disconnection from display handler    */
#define DH_CAP_HOTPLUG    (1<<4)    /* Hot plugging displays                        */
#define DH_CAP_BLANKING   (1<<5)    /* A message to indicate the display is blank   */

/**
 * Display Handler Driver Capabilities Packet:
 *
 * Sent by the driver to tell the display handler what version it is, as well
 * as the total number of displays that it supports. Also note that this
 * packet initiates the init sequence, and should be sent by the driver
 * before sending anything else.
 *
 * Sending this packet will result in the display handler sending the
 * dh_display_list.
 *
 * @var max_displays defines the maximum number of displays that the driver
 *        supports.
 * @var version should be set to PV_DRIVER_INTERFACE_VERSION
 * @var flags is unused
 * @var dh_reserved_word is unused
 *
 * DRIVER -> DISPLAY HANDLER via CONTROL CHANNEL
 */
struct dh_driver_capabilities
{
    uint32_t max_displays;
    uint32_t version;
    uint32_t flags;
    uint32_t dh_reserved_word;
};

/**
 * Defines dh_driver_capabilities->version (0xMMNNPPPP, Major.miNor.Patch)
 */
#define PV_DRIVER_INTERFACE_VERSION (0x00000001)



/**
 * Display Handler Display List Packet
 *
 * Sent by the display handler to the driver, this packet tells the driver
 * what displays the display handler has. The information from this packet
 * should be used by the driver to create the virtual displays that it
 * plans on supporting.
 *
 * Once this packet is received by the driver, it should respond with the
 * dh_display_advertised_list
 *
 * @var num_displays defines the number of displays in the packet
 * @var displays defines the array of display inforamtion
 *
 * DISPLAY HANDLER -> DRIVER via CONTROL CHANNEL
 */
struct dh_display_list
{
    uint32_t num_displays;
    struct dh_display_info displays[];
};



/**
 * Display Handler Advertised Display List Packet:
 *
 * Sent by the driver to tell the display handler what displays it has. The
 * displays[XXX]->key field should match the same field provided by the
 * display handler from the dh_display_list. If the display handler
 * receives a key that it doesn't know about, it will ignore the display
 * in this packet.
 *
 * Note that the display handler will ignore the width / height for each
 * display in this packet. The only field that it uses is the key field. To
 * tell the display handler what the width / height / stride of a display
 * is, you need to send the dh_set_display once the event channel
 * is established.
 *
 * Sending this packet will result in the display handler sending the
 * dh_add_display for each display in this list that is valid.
 *
 * @var num_displays defines the number of displays in the packet
 * @var displays defines the array of display inforamtion
 *
 * DRIVER -> DISPLAY HANDLER via CONTROL CHANNEL
 */
struct dh_display_advertised_list
{
    uint32_t num_displays;
    struct dh_display_info displays[];
};



/**
 * Display Handler Add Display Packet:
 *
 * Sent by the display handler to the driver, this packet provides the driver
 * with the ports that will be used by the display with the matching key in
 * the packet. This packet is sent in responce to the driver sending the
 * dh_display_advertised_list
 *
 * @var key defines a unique identifier for each display
 * @var event_port defines the IVC socket used by the driver to send the
 *      display handler events
 * @var framebuffer_port defines the IVC buffer that stores the display's
 *      framebuffer (XRGB format 0xXXRRGGBB)
 * @var dirty_rectangles_port defines the IVC socket use by the driver to
 *      tell the display handler which portions of the VM's framebuffer have
 *      changed.
 * @var cursor_bitmap_port defines the IVC buffer that stores the display's
 *      cursor image (ARGB format 0xAARRGGBB)
 *
 * DISPLAY HANDLER -> DRIVER via CONTROL CHANNEL
 */
struct dh_add_display
{
    uint32_t key;
    uint32_t event_port;
    uint32_t framebuffer_port;
    uint32_t dirty_rectangles_port;
    uint32_t cursor_bitmap_port;
};



/**
 * Display Handler Remove Display Packet:
 *
 * Sent by the display handler to the driver to tell the driver that the
 * display handler is no longer going to use this display. The driver should
 * attempt to tear down it's display, as this packet will likely be sent in
 * the event that the display handler loses a physical display (removed or
 * turned off)
 *
 * @var key defines a unique identifier for each display

 * DISPLAY HANDLER -> DRIVER via CONTROL CHANNEL
 */
struct dh_remove_display
{
    uint32_t key;
};



/**
 * Display Handler Display No Longer Avaialable Packet:
 *
 * Sent by the driver to the display handler, this packet provide a means for
 * the driver to tell the display handler that a display in not available. This
 * could be in response to the guest disabling a display, or it could be in
 * response to the driver coming down (maybe during a shutdown).
 *
 * @var key defines a unique identifier for each display

 * DRIVER -> DISPLAY HANDLER via CONTROL CHANNEL
 */
struct dh_display_no_longer_available
{
    uint32_t key;
};



/**
 * Display Handler Text Mode:
 *
 * Sent by the driver to the display handler, this packet provide a means for
 * the driver to tell the display handler that QEMU is not in Text Mode. There
 * is no need to send display information, and this will endable / disable
 * text mode for all displays. When text mode is enabled, the display
 * handler will use QEMU instead of the PVPlugin, even if the PVPlugin is
 * fully up and running. This event should be sent when the guest switchs
 * from the PV driver, the VGA text mode, which usually occurs when swtiching
 * to virtual consoles, or BSOD.
 *
 * @var mode defines where or not QEMU should display the guest, or the PV
 *      driver should display the guest. Set to PACKET_TEXT_MODE_DISABLED or
 *      PACKET_TEXT_MODE_ENABLED
 *
 * DRIVER -> DISPLAY HANDLER via CONTROL CHANNEL
 */
struct dh_text_mode
{
    uint32_t mode;
};

/**
 * Define the dh_text_mode->mode field
 */
enum
{
    PACKET_TEXT_MODE_DISABLED                         = 0,
    PACKET_TEXT_MODE_ENABLED                          = 1
};

/** Display Handler Blank Display:
 *
 * Set by the driver to the display handler, this packet informs the display
 * handler that a display should be blanked (e.g. dpms display sleep,
 * display modesetting).
 *
 * @var color Defines the pixel value that should be used to fill the display.
 * @var reason Provide a reason as to why the display was blanked, to allow
 *      for different types of handling (filling the above color, or passing
 *      dpms along to the display, etc).
 *
 * DRIVER -> DISPLAY_HANDLER via EVENT CHANNEL
 */
struct dh_blanking
{
    uint32_t color;
    uint32_t reason;
};

enum
{
    PACKET_BLANKING_DPMS_SLEEP                  = 0,
    PACKET_BLANKING_DPMS_WAKE                   = 1,
    PACKET_BLANKING_MODESETTING_FILL_ENABLE     = 2,
    PACKET_BLANKING_MODESETTING_FILL_DISABLE    = 3
};

/**
 * Display Handler Dirty Rectangle Packet:
 *
 * Sent by the driver to the display handler, this packet tells the display
 * handler to update a specific portion of the display that is assigned this
 * dirty rect channel.
 *
 * Note: This channel does not contain a header and footer, as the display
 * handler will always read in 16 bytes at a time.
 *
 * DRIVER -> DISPLAY HANDLER via DIRTY RECT CHANNEL
 */
struct dh_dirty_rectangle
{
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
};



/**
 * Display Handler Set Display Packet:
 *
 * Sent by the driver to the display handler, this packet tells the display
 * handler what the resolution and stride is for the display that is assigned
 * this event channel. This packet is a required to bring up a display as the
 * stride information is needed to parse the shared framebuffer. Also, the
 * width and height in this packet are the width and hieght that the display
 * handler actually pays attention to.
 *
 * Note that the following must be true: stride >= width * 4
 *
 * DRIVER -> DISPLAY HANDLER via EVENT CHANNEL
 */
struct dh_set_display
{
    uint32_t width;
    uint32_t height;
    uint32_t stride;
};



/**
 * Display Handler Update Cursor Packet:
 *
 * Tells the display handler that the cursor image channel has been updated.
 * This will instruct the display handler to update the hardware cursor's
 * image.
 *
 * @var xhot defines the cursor's hotspot
 * @var yhot defines the cursor's hotspot
 * @var show defines whether or not the cursor should be shown, or hidden.
 *      This can be set to PACKET_CURSOR_HIDE or PACKET_CURSOR_SHOW
 *
 * DRIVER -> DISPLAY HANDLER via EVENT CHANNEL
 */
struct dh_update_cursor
{
    uint32_t xhot;
    uint32_t yhot;
    uint32_t show;
};

/**
 * Defines the cursor image size that the PV will use.
 */
#define PV_DRIVER_CURSOR_WIDTH (64)
#define PV_DRIVER_CURSOR_HEIGHT (64)
#define PV_DRIVER_CURSOR_STRIDE (PV_DRIVER_CURSOR_WIDTH * 4)

/**
 * Define the dh_text_mode->mode field
 */
enum
{
    PACKET_CURSOR_HIDE                               = 0,
    PACKET_CURSOR_SHOW                               = 1,
};



/**
 * Display Handler Move Cursor Packet:
 *
 * Tells the display handler that the cursor has moved. This packet will result
 * in the display handler moving the cursor on the display that is assocaited
 * with this event channel.
 *
 * @var x new cursor location
 * @var y new cursor location
 *
 * DRIVER -> DISPLAY HANDLER via EVENT CHANNEL
 */
struct dh_move_cursor
{
    uint32_t x;
    uint32_t y;
};



#ifdef __GNUC__
#pragma GCC poison dh_reserved_word
#pragma GCC poison dh_reserved_halfword
#endif

#pragma pack(pop)
#endif
