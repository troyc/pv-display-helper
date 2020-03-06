//
// OpenXT Paravirtualized Display Helpers for the Display Handler
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
// Author: Kyle J. Temkin  <temkink@ainfosec.com>
//

//Include the definitions for our PV display helper library.
#include "common.h"
#include "pv_display_helper.h"

/******************************************************************************/
/* Module Parameters                                                          */
/******************************************************************************/

//The number of pages used per control connection. This should
//be large enough that the ring buffer is never filled by control data.
static int control_ring_pages = 1;

//If we're a linux kernel module, allow the module inserter to change this
//parameter, allowing easy tuning.
#if defined __linux__ && defined __KERNEL__
module_param(control_ring_pages, int, S_IRUGO | S_IWUSR);
#endif

//The number of pages used per event connection. This should be large
//enough that the ring buffer is never filled by event data, including
//potentially-frequent cursos movements.
static int event_ring_pages = 4;

//If we're a linux kernel module, allow the module inserter to change this
//parameter, allowing easy tuning.
#if defined __linux && defined __KERNEL__
module_param(event_ring_pages, int, S_IRUGO | S_IWUSR);
#endif


//The number of pages used for dirty rectangles data. This should be significantly
//sized, as dirty rectangles happen quite frequently; and the Display Handler may
//not be able to extract them easily enough.
static int dirty_rectangles_pages = 32;

//If we're a linux kernel module, allow the module inserter to change this
//parameter, allowing easy tuning.
#if defined __linux__ && defined __KERNEL__
module_param(dirty_rectangles_pages, int, S_IRUGO | S_IWUSR);
#endif

/******************************************************************************/
/* Event Handlers                                                             */
/******************************************************************************/

/**
 * Handles changes in the Host Display List.
 *
 * The host has sent a list of displays that it would like the PV Driver to handle. The relevant
 * driver may choose to advertise willingness to handle some or all of the plugins; but should not
 * act to create assets directly.
 *
 * @param display The display for which the event is being handled.
 * @param payload The raw event data, as received from the PV plugin.
 *
 */
static void __handle_host_display_changed_event(struct pv_display_provider *provider, void *payload)
{
    __PV_HELPER_TRACE__;

    //Get a reference to the header object, which provides information about the display list
    //that has been transmitted...
    struct dh_display_list *list = (struct dh_display_list *)payload;

    //If the user hasn't registered a handle for the Display List event, abort.
    if(!provider->host_display_change_handler)
    {
        pv_display_debug("A 'host display list changed' event was received, but no one registered a listener.\n");
        return;
    }

    //Finally, call the relevant event handler routine.
    provider->host_display_change_handler(provider, list->displays, list->num_displays);
}


/**
 * Handles a host Add Display request.
 *
 *
 * @param display The display for which the event is being handled.
 * @param payload The raw event data, as received from the display handler.
 *
 */
static void __handle_add_display_request(struct pv_display_provider *provider, struct dh_add_display *request)
{
    __PV_HELPER_TRACE__;

    //If the user hasn't registered a handle for the Display List event, abort.
    //We'll issue a full-on error message here, as lacking this listener makes us useless.
    if(!provider->add_display_handler)
    {
        pv_display_error("We've received an Add Display event, but the PV Driver hasn't set up a listener!");
        return;
    }

    //Finally, call the relevant event handler routine.
    provider->add_display_handler(provider, request);
}


/**
 * Handles a host Remove Display request.
 *
 * Sent by the display handler to the driver to tell the driver that the
 * display handler is no longer going to use this display. The driver should
 * attempt to tear down it's display, as this packet will likely be sent in
 * the event that the display handler loses a physical display (removed or
 * turned off).
 *
 * @param display The display for which the event is being handled.
 * @param payload The raw event data, as received from the display handler.
 *
 */
static void __handle_remove_display_request(struct pv_display_provider *provider, struct dh_remove_display *request)
{
    __PV_HELPER_TRACE__;

    //If the user hasn't registered a handle for the Display List event, abort.
    //We'll issue a full-on error message here, as lacking this listener makes us useless.
    if(!provider->remove_display_handler)
    {
        pv_display_error("We've received an Remove Display event, but the PV Driver hasn't set up a listener!");
        return;
    }

    //Finally, call the relevant event handler routine.
    provider->remove_display_handler(provider, request);
}

/******************************************************************************/
/* Internal Functions                                                         */
/******************************************************************************/

/**
 * Triggers the given display's fatal error handler, if one exists.
 *
 * @param display The PV display whose fatal error handler is to be triggered.
 */
static void __trigger_fatal_error_on_provider(struct pv_display_provider *provider)
{
    __PV_HELPER_TRACE__;

    if(provider->fatal_error_handler)
        provider->fatal_error_handler(provider);
}

/**
 * Handles receipt of a Display Handler control packet, delegating the packet to the appropriate handler
 * accoring to type.
 *
 * @param display The display which received the given control packet.
 * @param header The header object for the received packet.
 * @param buffer The payload for the given object.
 */
static void __handle_control_packet_receipt(struct pv_display_provider *provider, struct dh_header *header, void *buffer)
{
    __PV_HELPER_TRACE__;

    //Delegate the event to the approriate handler, according to type.
    switch(header->type)
    {

        //Host Display List events-- the Display Handler has sent a list of displays that it would like
        //the given plugin to handle.
        case PACKET_TYPE_CONTROL_HOST_DISPLAY_LIST:
            pv_display_debug("Received a Host Display Changed event!\n");
            __handle_host_display_changed_event(provider, buffer);
            return;

        //Add Display Requests-- the Display Handler would like us to provide a new display.
        case PACKET_TYPE_CONTROL_ADD_DISPLAY:
            pv_display_debug("Received an Add Display request!\n");
            __handle_add_display_request(provider, (struct dh_add_display *)buffer);
            return;

        //Remove Display Requests-- the Display Handler is finsihed with an existing display.
        case PACKET_TYPE_CONTROL_REMOVE_DISPLAY:
            pv_display_debug("Received a Remove Display request!\n")
            __handle_remove_display_request(provider, (struct dh_remove_display *)buffer);
            return;

        default:
            //For now, do nothing if we receive an unknown packet type-- this gives us some safety in the event of a version
            //mismatch. We may want to consider other behaviors, as well-- disconnecting, or sending an event to the host.
            pv_display_error("Received unknown or unexpected packet type (%u)! No action will be taken.\n", (unsigned int)header->type);
            return;
    }
}

/**
 * Attempts to read in a new packet header from the provided IVC channel,
 * and to the given buffer. This method attempts to read an entire header--
 * if no header is available, the buffer is not changed.
 *
 * @return 0 if a header was read, or an error code otherwise.
 */
static bool __try_to_read_header(struct pv_display_provider *provider)
{
    int rc;

    __PV_HELPER_TRACE__;


    //Attempt to perform a packetized read, which will pull in a header packet
    //if at all possible.
    pv_helper_lock(&provider->lock);
    rc = libivc_recv(provider->control_channel, (char *)&provider->current_packet_header, sizeof(struct dh_header));
    pv_helper_unlock(&provider->lock);

    return (rc == SUCCESS);
}


/**
 * Handle the (possible) receipt of a control packet. Note that this function
 * can be called at any time after a valid packet header has been received.
 *
 * @return True iff a packet was read.
 */
static bool __try_to_receive_control_packet(struct pv_display_provider *provider)
{
    __PV_HELPER_TRACE__;

    size_t length_with_footer;

    size_t data_available;
    struct dh_footer *footer;
    uint16_t checksum;
    char *buffer;
    int rc;

    pv_helper_lock(&provider->lock);

    //Determine the size of the remainder of the packet-- composed of the packet body ("payload") and footer.
    length_with_footer = provider->current_packet_header.length + sizeof(struct dh_footer);

    //Ask IVC for the total amount of data available.
    rc = libivc_getAvailableData(provider->control_channel, &data_available);

    //If we failed to get the /amount/ of available data, we're in trouble!
    //Fail out loudly.
    if(rc)
    {
        pv_display_error("Could not query IVC for its available data!\n");
        pv_helper_unlock(&provider->lock);
        __trigger_fatal_error_on_provider(provider);
        return false;
    }

    //If we haven't yet received enough data to parse the given packet,
    //abort quietly. We'll get the data on the next event.
    if(data_available < length_with_footer)
    {
        pv_helper_unlock(&provider->lock);
        return false;
    }


    //Otherwise, try to read the given data. First, we'll create a buffer
    //large enough to receive the rest of the packet.
    buffer = pv_helper_malloc(length_with_footer);

    //If we weren't able to allocate a receive buffer, we'll try to recover
    //on a future iteration. For now, abort!
    if(!buffer)
    {
        pv_display_error("Could not allocate enough space (" SIZE_FORMAT ") for a receive buffer. Will try to pick up again on next receipt!\n",
            length_with_footer);
        pv_helper_unlock(&provider->lock);
        return false;
    }

    //Finally, read in the remainder of the packet.
    pv_display_debug("Receiving %u bytes...\n", (unsigned int)length_with_footer);
    rc = libivc_recv(provider->control_channel, buffer, length_with_footer);

    //If we couldn't read in the remainder of the packet, something went wrong--
    //perhaps someone read before we did? (Bad locking?)
    if(rc)
    {
        pv_display_error("Could not read in a packet, though IVC claims it's there. Locking problems?\n");
        pv_helper_unlock(&provider->lock);
        pv_helper_free(buffer);
        return false;
    }

    //Finally, we'll make sure the packet is valid. To do so, we'll first get a reference to the footer,
    //which should be located right after the main packet body.
    footer = (struct dh_footer *)(buffer + provider->current_packet_header.length);

    //Compute the checksum of the received packet.
    checksum = __pv_helper_packet_checksum(&provider->current_packet_header, buffer, provider->current_packet_header.length);

    //Check the packet's CRC. If it doesn't match, we're in serious trouble. Bail out.
    if(checksum != footer->crc)
    {
        pv_display_error("Communications error: CRC did not match for a control packet. Terminating connections.\n");

        //Invalidate the received packet...
        provider->current_packet_header.length = 0;

        //... clean up, and return.
        pv_helper_free(buffer);
        pv_helper_unlock(&provider->lock);

        __trigger_fatal_error_on_provider(provider);
        return false;
    }

    //Invalidate the current packet header, as we've already handled it!
    provider->current_packet_header.length = 0;

    //Give up exclusive access to the display object, as we're done modifying it.
    pv_helper_unlock(&provider->lock);

    //Finally, pass the compelted packet to our packet receipt handler.
    __handle_control_packet_receipt(provider, &provider->current_packet_header, buffer);

    //Clean up our buffer.
    pv_helper_free(buffer);
    return true;
}


/**
 * Handle control channel events. These events usually indicate that we've
 * received a collection of control data-- but not necessarily a whole packet.
 */
static void __handle_control_channel_event(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    (void)opaque;
    (void)client;

    //Find the PV display provider associated with the given client.
    struct pv_display_provider *provider = opaque;
    bool continue_to_read = false;

    pv_display_debug("Received a control channel event.\n");

    //We've received a control channel event, which means that the remote side
    //has sent us at least a portion of a packet. We'll attempt to read all of
    //the data available, stopping we've run out of data to read.
    do
    {
        //If we haven't yet read in a valid header, try do to so.
        if(provider->current_packet_header.length == 0)
        {
            pv_display_debug("I'm not aware of an existing packet. Trying to read its header.\n");
            continue_to_read = __try_to_read_header(provider);
        }

        //If we now have a defined packet "shape" to receive, try to receive it.
        if(provider->current_packet_header.length > 0)
        {
            pv_display_debug("Receiving a Type-%u packet in progress. Trying to receive...\n",
                             (unsigned int)provider->current_packet_header.type);
            continue_to_read = __try_to_receive_control_packet(provider);
        }
    }
    while(continue_to_read);
}


/**
 * Handle control channel events. These events usually indicate that we've
 * received a collection of control data-- but not necessarily a whole packet.
 */
static void __handle_control_channel_disconnect(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    (void)opaque;
    (void)client;
    //Find the PV display provider associated with the given client...
    struct pv_display_provider *provider = opaque;

    //... and trigger its fatal error handler.
    __trigger_fatal_error_on_provider(provider);
}


/**
 * Attempts to open a control channel to the Display Handler.
 *
 * @param The display provider for which a control channel should be opened.
 *    It's assumed that the provider is already locked.
 */
static int __open_control_connection(struct pv_display_provider *provider)
{
    int rc;

    __PV_HELPER_TRACE__;

    //Try to connect to the Display Handler, which will be running in a remote domain.
    //This connection will be used to share our framebuffer.
    rc = libivc_connect_with_id(&provider->control_channel, provider->rx_domain, provider->control_port, control_ring_pages, provider->conn_id);

    //If we couldn't connect to the DH, error out!
    if(unlikely(rc != SUCCESS))
        return rc;

    //Register our event handlers-- which will handle "new data" events and disconnects, respectively.
    rc = libivc_register_event_callbacks(provider->control_channel, __handle_control_channel_event, __handle_control_channel_disconnect, provider);

    //If we couldn't register events, fail out!
    if(unlikely(rc != SUCCESS))
    {
        libivc_disconnect(provider->control_channel);
        return rc;
    }

    //Otherwise, indicate success.
    return 0;
}


/******************************************************************************/
/* PV Display Object Methods                                                  */
/******************************************************************************/

/**
 * Triggers the given display's fatal error handler, if one exists.
 *
 * @param display The PV display whose fatal error handler is to be triggered.
 */
static void __trigger_fatal_error_on_display(struct pv_display *display)
{
    __PV_HELPER_TRACE__;

    if(display->fatal_error_handler)
        display->fatal_error_handler(display);
}


/**
 * Sets the private per-driver data for the given display.
 *
 * @param display The display for which the data should be associated.
 * @param data The data to be associated with the given display.
 */
static void pv_display_set_driver_data(struct pv_display *display, void *data)
{
    __PV_HELPER_TRACE__;

    pv_helper_lock(&display->lock);
    display->driver_data = data;
    pv_helper_unlock(&display->lock);
}


/**
 * @return The display driver data associated with the given display.
 */
static void *pv_display_get_driver_data(struct pv_display *display)
{
    __PV_HELPER_TRACE__;
    void * value;

    pv_helper_lock(&display->lock);
    value = display->driver_data;
    pv_helper_unlock(&display->lock);

    return value;
}


/**
 * Changes the internal record of a PV display's resolution, and notifies the
 * Display Handler of the geometry change.
 *
 * @param display The PV display whose resolution will be changing.
 * @param width The PV display's new width.
 * @param height The PV display's new height.
 * @param stride The new stride of the shared framebuffer, in bytes.
 *
 * @return 0 on success, or an error code on failure.
 */
static int pv_display_change_resolution(struct pv_display *display, uint32_t width, uint32_t height, uint32_t stride)
{
    int rc;

    __PV_HELPER_TRACE__;

    //Create our simple "change event" structure, which describes the resolution change.
    struct dh_set_display new_geometry =
    {
        .width = width,
        .height = height,
        .stride = stride
    };

    //Ensure we have exclusive ownership of a valid PV display object.
    pv_display_checkp(display, -EINVAL);
    pv_helper_lock(&display->lock);

    //Update the display's internal fields...
    display->width = width;
    display->height = height;
    display->stride = stride;

    //... notify the Display Handler...
    rc = __send_packet(display->event_connection, PACKET_TYPE_EVENT_SET_DISPLAY,
                       &new_geometry, sizeof(new_geometry));

    //... and finally, release our lock on the display.
    pv_helper_unlock(&display->lock);

    return rc;
}


/**
 * Marks a given region of the shared framebuffer as requiring a redraw ("dirty"),
 * and requests that the host redraw a given region.
 *
 * @param display The PV display whose region is to be invalidated.
 * @param x, y, width, height -- The four bounds of the "dirty rectangle" to be invalidated.
 *
 * @param int 0 on success, or an error code otherwise.
 */
static int pv_display_invalidate_region(struct pv_display *display, uint32_t x, uint32_t y, uint32_t width, uint32_t height)
{
    size_t available_space;
    int rc;

    //Create a "dirty rectangle" data structure that describes the invalidated region...
    struct dh_dirty_rectangle region =
    {
        .x = x,
        .y = y,
        .width = width,
        .height = height
    };

    //Validate our input.
    pv_display_checkp(display, -EINVAL);
    pv_display_checkp(display->dirty_rectangles_connection, -EINVAL);

    pv_helper_lock(&display->lock);

    //First, get the amount of available space in the Dirty Rectangles buffer.
    rc = libivc_getAvailableSpace(display->dirty_rectangles_connection, &available_space);

    //If we couldn't get the amount of available space, something's gone very wrong.
    //Trigger our error handler.
    if(rc)
    {
        pv_display_error("Could not query for the amount of space left in the dirty rectangles buffer!");
        pv_helper_unlock(&display->lock);
        __trigger_fatal_error_on_display(display);
        return rc;
    }

    //If we can't fit a dirty rectangle, skip this update.
    //We should automatically recover, as a full update will be scheduled at the end of the queue.
    //See the condition below.
    if(available_space < sizeof(struct dh_dirty_rectangle))
    {
        pv_helper_unlock(&display->lock);
        return -EAGAIN;
    }

    //If we have enough space to store a dirty rectangle, but not enough space
    //to store /two/, we're about to overrun. To handle this as gracefully as we can,
    //we'll queue a full screen refresh.
    if(available_space < (sizeof(struct dh_dirty_rectangle) * 2))
    {
        region.x = 0;
        region.y = 0;
        region.width  = display->width;
        region.height = display ->height;
    }

    //Send the dirty region over the "dirty rectangles" connection.
    rc = libivc_send(display->dirty_rectangles_connection, (char *)&region, sizeof(region));

    pv_helper_unlock(&display->lock);
    return rc;
}

/**
 * @return True iff the given display currently supports a hardware cursor.
 */
static int pv_display_supports_cursor(struct pv_display *display)
{
    int display_supported;

    __PV_HELPER_TRACE__;
    pv_display_checkp(display, -EINVAL);

    //Finally, send the update notification.
    pv_helper_lock(&display->lock);
    display_supported = (display->cursor.image != NULL);
    pv_helper_unlock(&display->lock);

    return display_supported;
}


/**
 * Sends a cursor update notification to the display handler.
 * Should be called any time the cursor information (display->cursor)
 * is changed, including the cursor image contents.
 *
 * Assumes that the caller already holds the display's lock.
 *
 * @param display The display whose cursor is to be updated.
 * @param visible Nonzero iff the cursor should be displayed; or 0 if the cursor should be zero.
 *
 * @return 0 on success, or an error code on failure.
 */
#if defined _WIN32
_IRQL_requires_same_
#endif
static int __send_cursor_update_unsynchronized(struct pv_display *display)
{
    //Build the notification packet...
    struct dh_update_cursor payload = {
      .xhot = display->cursor.hotspot_x,
      .yhot = display->cursor.hotspot_y,
      .show = display->cursor.visible
    };

    //... and send it to the display handler.
    return  __send_packet(display->event_connection, PACKET_TYPE_EVENT_UPDATE_CURSOR, &payload, sizeof(payload));
}


/**
 * Sets the "hot spot" (see above) for the PV cursor associated with
 * this display.
 *
 * @param display The display whose hardware cursor should be updatd.
 * @param hotspot_x The X coordinate of the cursor's hot spot.
 * @param hotspot_y The Y coordinate of the cursor's hot spot.
 * @return Zero on success, or an error code on failure.
 */
static int pv_display_set_cursor_hotspot(struct pv_display *display,
    uint32_t hotspot_x, uint32_t hotspot_y)
{
    int rc;

    pv_display_checkp(display, -EINVAL);

    //Ensure that we have a valid cursor connection...
    pv_display_checkp(display->cursor.image, -EINVAL);
    pv_display_checkp(display->cursor_image_connection, -EINVAL);

    //... ensure that the cursor itself is valid...
    if(hotspot_x > PV_DRIVER_CURSOR_WIDTH)
      return -EINVAL;
    if(hotspot_y > PV_DRIVER_CURSOR_HEIGHT)
      return -EINVAL;

    //... update the cursor information...
    pv_helper_lock(&display->lock);
    display->cursor.hotspot_x = hotspot_x;
    display->cursor.hotspot_y = hotspot_y;

    //... and notify the display handler of the change.
    rc = __send_cursor_update_unsynchronized(display);
    pv_helper_unlock(&display->lock);

    return rc;
}

/**
 * Sets the PV cursor's visbility, showing or hiding the cursor.
 *
 * @param display The display whose hardware cursor should be updatd.
 * @param visible True iff the cursor should be visible.
 * @return Zero on success, or an error code on failure.
 */
static int pv_display_set_cursor_visibility(struct pv_display *display,
    bool visible)
{
    int rc;

    pv_display_checkp(display, -EINVAL);

    //Ensure that we have a valid cursor connection...
    pv_display_checkp(display->cursor.image, -EINVAL);
    pv_display_checkp(display->cursor_image_connection, -EINVAL);

    //... update the cursor information...
    pv_helper_lock(&display->lock);
    display->cursor.visible = (visible != 0);

    //... and notify the display handler of the change.
    rc = __send_cursor_update_unsynchronized(display);
    pv_helper_unlock(&display->lock);

    return rc;
}


/**
 * Moves the display's hardware cursor.
 * Assumes that the caller already holds the display's lock.
 *
 * @param display The display whose cursor is to be updated.
 * @param x The new X coordiante for the cursor on the display framebuffer.
 * @param y The new Y coordiante for the cursor on the display framebuffer.
 *
 * @return 0 on success, or an error code on failure.
 */
static int __send_cursor_movement_unsynchronized(struct pv_display *display, uint32_t x, uint32_t y)
{
    //Build the notification packet...
    struct dh_move_cursor payload = {
      .x = x,
      .y = y,
    };

    //... and send it to the display handler.
    return __send_packet(display->event_connection, PACKET_TYPE_EVENT_MOVE_CURSOR, &payload, sizeof(payload));
}


/**
 * Moves the display's hardware cursor.
 *
 * @param display The display whose cursor is to be updated.
 * @param x The new X coordiante for the cursor on the display framebuffer.
 * @param y The new Y coordiante for the cursor on the display framebuffer.
 *
 * @return 0 on success, or an error code on failure.
 */
static int pv_display_move_cursor(struct pv_display *display, uint32_t x, uint32_t y)
{
    int rc;

    pv_display_checkp(display, -EINVAL);

    //Ensure that we have a valid cursor connection.
    pv_display_checkp(display->cursor.image, -EINVAL);
    pv_display_checkp(display->cursor_image_connection, -EINVAL);

    //Finally, send the update notification.
    pv_helper_lock(&display->lock);
    rc = __send_cursor_movement_unsynchronized(display, x, y);
    pv_helper_unlock(&display->lock);

    return rc;
}
#if defined _WIN32
_IRQL_requires_same_
#endif
static void copy_image(struct pv_display * display, char * source, uint8_t source_height,
    size_t source_stride, size_t stride_difference,
    char * destination, size_t destination_stride)
{
    int y;
    //Iterate over each row in the given image...
    for(y = 0; y < PV_DRIVER_CURSOR_HEIGHT; ++y)
    {

        //If we've run out of source image...
        if(y >= source_height)
        {
            //... set the cursor pixels to transparent...
            memset(destination, 0, destination_stride);

            //... and continue to the next row.
            destination += destination_stride;
            continue;
        }

        //Otherwise, copy in the relevant row...
        memcpy(destination, source, source_stride);

        //... padding to the end with transparent pixels, if need be...
        if(stride_difference)
            memset(destination + source_stride, 0, stride_difference);

        //... and then move to the next row.
        source += source_stride;
        destination += destination_stride;
    }

    //Finally, notify the display handler of the new image.
    __send_cursor_update_unsynchronized(display);
}

/**
 * Loads a cursor image into the PV display's cursor buffer,
 * if possible.
 *
 * @param display The display for which the cursor image is to be populated.
 * @param image A pointer to an ARGB8888 image to be loaded.
 * @param width The width (max 64) of the image to be loaded.
 * @param height The height (max 64) of the image to be loaded.
 */
#if defined _WIN32
_IRQL_requires_same_
#endif
static int pv_display_load_cursor_image(struct pv_display *display,
    void *image, uint8_t source_width, uint8_t source_height)
{
    size_t source_stride, destination_stride, stride_difference;
    char *source, *destination;
    int rc = SUCCESS;

    if((source_width > PV_DRIVER_CURSOR_WIDTH) ||
       (source_height > PV_DRIVER_CURSOR_HEIGHT)) {

        pv_display_error("PV cursor image is larger than %dx%d! Rejecting.",
            PV_DRIVER_CURSOR_WIDTH, PV_DRIVER_CURSOR_HEIGHT);
        return -EINVAL;
    }

    //Compute the source and destination strides...
    source_stride = pixels_to_bytes(source_width);
    destination_stride = pixels_to_bytes(PV_DRIVER_CURSOR_WIDTH);

    //... and the difference between them, which will need to be filled
    //in with transparent pixels.
    stride_difference = destination_stride - source_stride;

    //Get a reference to the source image...
    source = (char *)image;
    pv_display_checkp(source, -EINVAL);

    pv_helper_lock(&display->lock);

    //... and get a reference to its destination.
    destination = (char *)display->cursor.image;

    //If we weren't able to get the PV cursor image,
    //we must not have cursor support. Abort!
    if(!destination) {
        rc = -EINVAL;
    }
    else
    {
        copy_image(display, source, source_height, source_stride, stride_difference, destination, destination_stride);
    }

    pv_helper_unlock(&display->lock);

    return rc;
}

/**
 * Re-establishes all display connections for the active display.
 *
 * This can be used to reconnect to the Display Handler in the event
 * that the display handler is killed. In this case, the normal
 * handshaking process should be followed, but instead of creating
 * a new display, the PV driver should call reconnect() on the
 * extisting display.
 *
 * @param display The display to be reconnected.
 * @param request The display handler "add_display" request
 *    that triggered the display reconnection.
 * @param rx_domain The display domain to reconnect to.
 */
static int pv_display_reconnect(struct pv_display *display,
    struct dh_add_display *request, domid_t rx_domain)
{
    int rc;

    __PV_HELPER_TRACE__;

    pv_display_checkp(display, -EINVAL);
    pv_display_checkp(request, -EINVAL);

    //First, ensure that we have a existing framebuffer and
    //event connection to reconnect to-- if we didn't, the
    //display state is invalid, and we can't reconnect.
    if(!display->framebuffer_connection || !display->event_connection)
        return -EINVAL;

    //Ensure that we've been provided a valid port for the /required/
    //connections-- we need at least a framebuffer and event connection.
    if((request->framebuffer_port == 0) || (request->event_port == 0))
        return -EINVAL;

    //Reconnect to our framebuffer...
    rc = libivc_reconnect(display->framebuffer_connection, rx_domain,
        (uint16_t)request->framebuffer_port);
    if(rc)
      return -ENXIO;

    //... and our event connection.
    rc = libivc_reconnect(display->event_connection, rx_domain,
        (uint16_t)request->event_port);
    if(rc)
      return -ENXIO;


    //If we had a dirty rectangles connection, and we have a valid
    //new connection target, reconnect our dirty rectangles connection.
    if(request->dirty_rectangles_port && display->dirty_rectangles_connection) {
        rc = libivc_reconnect(display->dirty_rectangles_connection, rx_domain,
            (uint16_t)request->dirty_rectangles_port);

        if(rc)
          pv_display_error("Warning: could not reconnect to dirty rectangles port!\n");
    }

    //And do the same for our cursor bitmap port.
    if(request->cursor_bitmap_port && display->cursor_image_connection) {
        rc = libivc_reconnect(display->cursor_image_connection, rx_domain,
            (uint16_t)request->cursor_bitmap_port);

        if(rc)
          pv_display_error("Warning: could not reconnect to PV cursor port!\n");
    }

    return 0;
}


/**
 * Tells the display handler that the display contents are no longer valid, and should be handled
 * appropriately, most likely by rendering an all black alternative buffer. It could potentially
 * be used in the future to pass the information to DRM to DPMS off that particular display.
 *
 * @param display Display that should be either blanked or restored from a blanked state.
 * @param dpms True if the display is blanked for sleep, and false if for a modesetting
 *        operation.
 * @param blank True iff the display should be blanked.
 */
static int pv_display_blank_display(struct pv_display *display, bool dpms, bool blank)
{
    int rc;
    __PV_HELPER_TRACE__;

    //Populate a "text mode" packet...
    struct dh_blanking payload;
    payload.color = 0;

    if(blank)
      payload.reason = dpms ? PACKET_BLANKING_DPMS_SLEEP : PACKET_BLANKING_MODESETTING_FILL_ENABLE;
    else
      payload.reason = dpms ? PACKET_BLANKING_DPMS_WAKE : PACKET_BLANKING_MODESETTING_FILL_DISABLE;

    pv_display_checkp(display, -EINVAL);

    //... and send it via IVC.
    pv_helper_lock(&display->lock);
    rc = __send_packet(display->event_connection, PACKET_TYPE_EVENT_BLANK_DISPLAY,
                       &payload, sizeof(payload));
    pv_helper_unlock(&display->lock);

    //If we couldn't turn on text mode, print a diagnostic.
    if(rc)
    {
        pv_display_error("Failed to send blanking display message (%d)!\n", rc);
        return rc;
    }

    //Indicate success.
    return 0;
}


/**
 * Destroys a given PV display, freeing any associated memory.
 */
static void pv_display_destroy(struct pv_display *display)
{
    __PV_HELPER_TRACE__;
    pv_display_checkp(display);

    //Tear down the event connection...
    if(display->event_connection)
        libivc_disconnect(display->event_connection);

    //... the framebuffer...
    if(display->framebuffer_connection)
        libivc_disconnect(display->framebuffer_connection);

    //... the dirty rectangles connection...
    if(display->dirty_rectangles_connection)
        libivc_disconnect(display->dirty_rectangles_connection);

    //... and the cursor image connection.
    if(display->cursor_image_connection)
        libivc_disconnect(display->cursor_image_connection);

    //Finally, tear down the display object.
    if(display)
        pv_helper_free(display);
}


/**
 * Attempts to open a outgoing channel to the display handler, which will be used to transmit
 * one-way data (such as resize events, or dirty rectangles).
 *
 * @param display The display provider for which a control channel should be opened.
 * @param client An out argument to recieve the newly created IVC client.
 * @param rx_domiain The remote domain to connect to (the "display domain").
 * @param port The port to connect to on the remote domain.
 * @param disconnect_handler The callback function to be executed if the connection disconnects.
 *
 * @return 0 on success, or an error code on failure.
 */
static int __open_outgoing_connection(struct pv_display *display, struct libivc_client **client, int pages,
                                      domid_t rx_domain, uint16_t port, libivc_client_disconnected disconnect_handler, uint64_t conn_id)
{
    (void)display;
    int rc;

    __PV_HELPER_TRACE__;

    //Try to create our per-channel connection to the display handler.
    rc = libivc_connect_with_id(client, rx_domain, port, pages, conn_id);

    //If we couldn't connect to the DH, error out!
    if(unlikely(rc))
    {
        *client = NULL;
        return rc;
    }

    //If we were provided with a disconnect callback, register it.
    if(disconnect_handler)
        libivc_register_event_callbacks(*client, NULL, disconnect_handler, display);

    //Otherwise, indicate success.
    return 0;
}



/**
 * General-case function for handling IVC disconnects.
 *
 * @param connection The connection for which a disconnect event is being handled.
 * @param locator A function which locates the PV display associated with a given
 *    IVC connection. See __find_display_with_event_connection for a good example.
 *
 */
static void __handle_disconnect_for_connection(struct libivc_client *connection, struct pv_display *display)
{
    //Simple token which prevents nested disconnect handlers.
    //This allows a user to request a disconnected as part of a response to a disconnect event
    //without creating an infinite hell-chain.
    static bool handler_in_progress = false;

    __PV_HELPER_TRACE__;

    //Validate our input.
    pv_display_checkp(connection);
    pv_display_checkp(display);

    //If we're already handling a disconnect event, abort.
    if(handler_in_progress)
        return;

    //If we were able to locate a display, trigger its fatal error handler.
    if(display)
    {
        handler_in_progress = true;
        __trigger_fatal_error_on_display(display);
        handler_in_progress = false;
    }
}



/**
 * Handle PV display event connection disconnects.
 */
static void __event_disconnect_handler(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    __handle_disconnect_for_connection(client, opaque);
}


/**
 * Handle PV display dirty rectangle connection disconnects.
 */
static void __dirty_rectangles_disconnect_handler(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    __handle_disconnect_for_connection(client, opaque);
}


/**
 * Handle PV display framebuffer connection disconnects.
 */
static void __framebuffer_disconnect_handler(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    __handle_disconnect_for_connection(client, opaque);
}


/**
 * Handle PV hardware cursor disconnects.
 */
static void __cursor_image_disconnect_handler(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    // In this initial implementation, a hardware cursor connection error will force
    // a disconnect, so the reconnect sequence can fix things. Instead, losing the
    // hardware cursor should trigger a swap to software cursor, and spawn a background
    // hardware cursor reconnect.
    pv_display_error("Hardware cursor connection broken. Forcing reconnect.");
    __handle_disconnect_for_connection(client, opaque);
}


/**
 * Attempts to open a shared memory channel to the display handler, which will be used
 * to sharea cursor image for use as a hardware cursor.
 *
 */
static int __open_cursor_image_connection(struct pv_display *display, struct libivc_client ** client,
                                          domid_t rx_domain, uint16_t port, uint64_t conn_id)
{
    int rc, pages_to_allocate;
    char * local_buffer;

    __PV_HELPER_TRACE__;

    //Allocate the space needed for the cursor image.
    //For now, we'll allocate one page more than needed for the image,
    //to ensure that we can get a page-aligned address. See framebuffer creation
    //for more information.
    pages_to_allocate = (int)((align_to_next_page(CURSOR_IMAGE_SIZE) >> PAGE_SHIFT) + 1);

    //First, attempt to create a new buffer for the hardware cursor image.
    rc = __open_outgoing_connection(display, client, pages_to_allocate, rx_domain, port, __cursor_image_disconnect_handler, conn_id);

    //If we couldn't make the connection, error out!
    if(unlikely(rc)) {
      return rc;
    }

    //Ask the IVC connection for its local buffer, which we'll use to store our framebuffer.
    //It's important to note that the shared buffer here will _not_ be page aligned, as IVC
    //stores its connection metadata at the start of its first page. The pointer returned is
    //directly after this connection metadata-- and in the middle of the page.
    rc = libivc_getLocalBuffer(*client, &local_buffer);

    //If we couldn't get a framebuffer, something's internally wrong in IVC. This isn't good!
    if(unlikely(rc != SUCCESS))
    {
        BUG();
        pv_display_error("IVC reports a valid connection, but won't give us its internal buffer!\n");

        //Disconnect from IVC...
        libivc_disconnect(*client);

        //... and tear down our work thus far.
        *client = NULL;
        return rc;
    }

    //Store the local cursor image buffer...
    display->cursor.image = local_buffer;

    //... and indicate success.
    return 0;
}



/**
 * Creates each of the IVC connections for a given PV display object, with the exception of its framebuffer.
 *
 * @param display The display for which the connections should be created.
 * @param request The "Display Add" request, which stores connection metadata.
 * @param rx_domain The domain to which an IVC connection should be created. This is almost always the
 *    domain ID of the domain that originated the request.
 *
 * @return 0 on success, or an error code on failure.
 */
static int __create_pv_display_support_connections(struct pv_display *display, struct dh_add_display *request, uint16_t rx_domain, uint64_t conn_id)
{
    int rc;

    __PV_HELPER_TRACE__;

    //Set up the display's event connection.

    rc = __open_outgoing_connection(display, &display->event_connection, event_ring_pages, rx_domain, (uint16_t)request->event_port, __event_disconnect_handler, conn_id);
    //If we weren't able to create an event connection, error out!
    if(rc)
    {
        pv_display_error("Could not create an event connection for display %u!\n", (unsigned int)request->key);
        return rc;
    }

    //If the host has offered a dirty rectangle port, create a dirty rectangle connection.
    if(request->dirty_rectangles_port) {

        //Set up the display's dirty rectangle connection.
        rc = __open_outgoing_connection(display, &display->dirty_rectangles_connection, dirty_rectangles_pages, rx_domain, (uint16_t)request->dirty_rectangles_port, __dirty_rectangles_disconnect_handler, conn_id);

        //If we weren't able to create an event connection, print an error to the log,
        //but continue-- the Display Handler will refresh the whole screen.
        if(rc) {
            pv_display_error("Could not create a dirty rectangle connection for display %u!\n", (unsigned int)request->key);
            pv_display_error("Performance will be reduced.");
        }
    }

    //If the host has offered a cursor image connection, enable hardware cursor support!
    if(request->cursor_bitmap_port) {

        //Create the hardware cursor connection-- which implicitly creates the hardware cursor buffer.
        rc = __open_cursor_image_connection(display, &display->cursor_image_connection, rx_domain, (uint16_t)request->cursor_bitmap_port, conn_id);

        //If we weren't able to create the connection, print an error, but continue
        //using a software cursor.
        if(rc) {
            pv_display_error("Could not create a hardware cursor connection for display %u!\n", (unsigned int)request->key);
            pv_display_error("Falling back to a software cursor.");
        }
    }

    //Indicate success.
    return 0;
}



/**
 * Creates a IVC-shared framebuffer for the given IVC display.
 *
 * @param rx_domain The domain with which the given display should be shared.
 * @param ivc_port  The port over which the given display should be shared.
 * @param display_size The size of the requested framebuffer, in bytes.
 * @param client An out argument to receive the IVC client that provides the framebuffer.
 *
 * @return A pointer to the allocated framebuffer, or NULL if a framebuffer could not be allocated.
 */
static void *__create_shared_framebuffer(struct pv_display *display, domid_t rx_domain, uint16_t ivc_port, uint32_t display_size, struct libivc_client **client, uint64_t conn_id)
{
    __PV_HELPER_TRACE__;

    uint16_t pages_for_framebuffer;
    uint16_t pages_to_allocate;
    char *framebuffer  = NULL;
    int rc;

    //First, compute the total number of pages necessary to store our virtual framebuffer.
    pages_for_framebuffer = (uint16_t)(align_to_next_page(display_size) >> PAGE_SHIFT);

    //Next, we'll need to compute the number of pages necessary for our IVC connection.
    //For now, IVC stores some additional communications metadata in the connection as
    //well, so we'll add on a page to store that information. (This information needs its
    //own page, as we'll be mmapp'ing out all pages touched by our framebuffer.)
    pages_to_allocate = pages_for_framebuffer + 1;

    //Try to connect to the Display Handler, which will be running in a remote domain.
    //This connection will be used to share our framebuffer.
    rc = libivc_connect_with_id(client, rx_domain, ivc_port, pages_to_allocate, conn_id);

    //If we couldn't connect to the DH, error out!
    if(unlikely(rc != SUCCESS))
    {
        pv_display_error("Failed to create a framebuffer on port %u: no IVC server.\n", (unsigned int)ivc_port);

        //... and ensure we don't leave any trailing references.
        *client = NULL;
        return NULL;
    }

    //Register a handler for framebuffer disconnect.
    rc = libivc_register_event_callbacks(*client, NULL, __framebuffer_disconnect_handler, display);

    if(rc)
        pv_display_error("Could not register a disconnect handler! Continuing with reduced fault tolerance.");

    //Ask the IVC connection for its local buffer, which we'll use to store our framebuffer.
    //It's important to note that the shared buffer here will _not_ be page aligned, as IVC
    //stores its connection metadata at the start of its first page. The pointer returned is
    //directly after this connection metadata-- and in the middle of the page.
    rc = libivc_getLocalBuffer(*client, &framebuffer);

    //If we couldn't get a framebuffer, something's internally wrong in IVC. This isn't good!
    if(unlikely(rc != SUCCESS))
    {
        BUG();
        pv_display_error("IVC reports a valid connection, but won't give us its internal buffer!\n");

        //Disconnect from IVC...
        libivc_disconnect(*client);

        //... and tear down our work thus far.
        *client = NULL;
        return NULL;
    } else {
        pv_display_debug("Got a valid connection-- buffer is located at %p.\n", framebuffer);
    }

    //Finally, return a pointer to our new framebuffer storage.
    return framebuffer;
}


/**
 * Handles registration of a fatal error handler for PV display providers.
 * Currently only allows registration of a single handler.
 *
 * @param provider The display event for which the handler should be registered.
 * @param handler The callback function which should be called to handle unrecoverable errors.
 */
static void pv_display_register_fatal_error_handler(struct pv_display *display, fatal_display_error_handler handler)
{
    __PV_HELPER_TRACE__;

    //Update the registration.
    display->fatal_error_handler = handler;
}


/**
 * Validates a given "Add Display" request.
 *
 * @return True if the request is valid, or false otherwise.
 */
static bool __validate_add_display_request(struct dh_add_display *request)
{
    __PV_HELPER_TRACE__;

    //Ensure that we have a framebuffer...
    if(request->framebuffer_port == 0)
    {
        pv_display_error("The Display Handler provided a display without a framebuffer connection-- rejecting it!\n");
        return false;
    }

    //... and ensure that we have an event connection.
    if(request->event_port == 0)
    {
        pv_display_error("The Display Handler provided a display without an event connection-- rejecting it!\n");
        return false;
    }

    //If none of our checks have failed, the request is valid!
    return true;
}


/**
 * Creates a new PV Display object, which represents an individual display -- as typically provided by a display provider.
 * Note that creating a display will not immediately make it usable-- to user a display, one must call its update_resolution
 * method.
 *
 * @param provider The display provider that should create the new domain.
 * @param new_display The out argument to recieve the new PV display object.
 * @param request The PV display creation request, which contains the information necessary to create display connections.
 * @param width The "virtual width" of the new framebuffer. This should be the largest possible width this display will be
 *    expected to take-- the user can modeset to create a smaller "view" of this framebuffer, but not a larger one.
 * @param height The "virtual height" of the new framebuffer-- see the caveat in the "width" parameter.
 * @param stride The largest possible stride of the framebuffer, in bytes.
 * @param initial_contents The initial contents of the framebuffer, as a raw binary blob -- or NULL if the framebuffer
 *    need not be initialized. This can be used to create "copies" of existing framebuffers, which is useful for handling
 *    reconnects.
 *
 */
static int provider_create_display(struct pv_display_provider *provider, struct pv_display **new_display,
                            struct dh_add_display *request, uint32_t width, uint32_t height, uint32_t stride, void *initial_contents)
{
    struct pv_display *display;
    int rc;

    __PV_HELPER_TRACE__;

    //First, validate the given display request, and ensure it represents a usable display.
    if(!__validate_add_display_request(request))
        return -EINVAL;

    //First, allocate the new display structure.
    display = pv_helper_malloc(sizeof(struct pv_display));

    //If we couldn't allocate a new display, return an error code.
    if(!display)
    {
        pv_display_error("Could not allocate enough memory for a new PV display object!\n")
        return -ENOMEM;
    }

    //Initialize our object's lock, and immediately lock it.
    //This is important, to ensure that none of our callbacks are executed before the object
    //is completely initialized.
    pv_helper_mutex_init(&display->lock);
    pv_helper_lock(&display->lock);

    //Initialize our display object's basic fields.
    display->key    = request->key;
    display->width  = width;
    display->height = height;
    display->stride = stride;

    //By default, assume we have no connections.
    display->framebuffer_connection      = NULL;
    display->event_connection            = NULL;
    display->cursor_image_connection     = NULL;
    display->dirty_rectangles_connection = NULL;

    //... and assume we have no hardware cursor.
    display->cursor.image                = NULL;

    //Next, set up the display's framebuffer.
    display->framebuffer_size = stride * height;

    display->framebuffer = __create_shared_framebuffer(display, provider->rx_domain, (uint16_t)request->framebuffer_port, display->framebuffer_size, &display->framebuffer_connection, provider->conn_id);
    //If we weren't able to create a framebuffer, tear ourselves down and abort!
    if(!display->framebuffer)
    {
        pv_display_error("Could not create a framebuffer for display %u!\n", (unsigned int)request->key);
        pv_helper_unlock(&display->lock);
        pv_display_destroy(display);
        *new_display = NULL;

        return -ENOMEM;
    }

    //Create the support connections for the given display-- including the event,
    //dirty rectangles, and cursor connections.
    rc = __create_pv_display_support_connections(display, request, provider->rx_domain, provider->conn_id);

    //If we weren't able to create the given connections, fail out!
    if(rc)
    {

        pv_helper_unlock(&display->lock);
        pv_display_destroy(display);
        *new_display = NULL;

        return rc;
    }

    //If initial contents were provided, copy them into the new framebuffer.
    if(initial_contents)
        memcpy(display->framebuffer, initial_contents, display->framebuffer_size);

    //Finally, bind the display's methods...
    display->reconnect              = pv_display_reconnect;
    display->set_driver_data        = pv_display_set_driver_data;
    display->get_driver_data        = pv_display_get_driver_data;
    display->change_resolution      = pv_display_change_resolution;
    display->invalidate_region      = pv_display_invalidate_region;
    display->supports_cursor        = pv_display_supports_cursor;
    display->load_cursor_image      = pv_display_load_cursor_image;
    display->set_cursor_hotspot     = pv_display_set_cursor_hotspot;
    display->set_cursor_visibility  = pv_display_set_cursor_visibility;
    display->move_cursor            = pv_display_move_cursor;
    display->blank_display          = pv_display_blank_display;
    display->destroy                = pv_display_destroy;

    //Bind events.
    display->register_fatal_error_handler = pv_display_register_fatal_error_handler;

    //... unlock the PV display object...
    pv_helper_unlock(&display->lock);

    //... and return, indicating success.
    *new_display = display;
    return 0;
}


/**
 * Destroys an existing PV display object, and notifies the Display Handler.
 *
 * This is now the preferred method of destroying a display object, rather than
 * destroying a display object manually by calling display->destroy(). This method's
 * functionality is almost identical, but this method notifies the Display Handler.
 *
 * @param provider The provider that should notify the Display Handler of the display's
 *    destruction. This does not need to be the same display provider as the one that
 *    generated the display, but it should represent the same connection. In other words,
 *    if a domain's provider was torn down and recreated as a part of a reconnect, it's
 *    acceptable to use that new provider to destroy a display created by the original
 *    provider.
 *
 * @param display The display to be destroyed.
 *
 */
#if defined _WIN32
//False positive AFAICT
#pragma warning ( suppress: 28167)
#endif
int provider_destroy_display(struct pv_display_provider *provider, struct pv_display *display)
{
    struct dh_display_no_longer_available request;
    int rc;

    __PV_HELPER_TRACE__;

    pv_display_checkp(provider, -EINVAL);
    pv_display_checkp(display, -EINVAL);

    // Notify the display handler that the display is being torn down.
    request.key = display->key;

    pv_helper_lock(&provider->lock);
    rc = __send_packet(provider->control_channel, PACKET_TYPE_CONTROL_DISPLAY_NO_LONGER_AVAILABLE,
                       &request, sizeof(request));
    pv_helper_unlock(&provider->lock);

    //If we couldn't send the given packet, print a diagnostic, but continue.
    //The display handler architecture is designed to survive missing information, like this.
    if(rc)
    {
        pv_display_error("Could not notify the Display Handler of display destruction.\n");
    }

    // Ask the display object to destroy itself.
    display->destroy(display);
    return rc;
}


/******************************************************************************/
/* PV Display Provider Methods                                                */
/******************************************************************************/

/**
 * Advertises the PV Driver's capabilities to the Display Handler. For now, this consists
 * only of notifying the DH of the maximum displays this plugin can create.
 *
 * @param display The Display Provider via which capabilities are to be advertised.
 * @param max_displays The maximum number of displays supported.
 */
static int provider_advertise_capabilities(struct pv_display_provider *provider, uint32_t max_displays)
{
    int rc;

    __PV_HELPER_TRACE__;

    //Populate a "driver capabilities" packet...
    struct dh_driver_capabilities capabilities =
    {
        .max_displays = max_displays,
        .version = PV_DRIVER_INTERFACE_VERSION
    };

    pv_display_checkp(provider, -EINVAL);

    //... and send it via IVC.
    pv_helper_lock(&provider->lock);
    rc = __send_packet(provider->control_channel, PACKET_TYPE_CONTROL_DRIVER_CAPABILITIES,
                       &capabilities, sizeof(struct dh_driver_capabilities));
    pv_helper_unlock(&provider->lock);

    //If we couldn't send the given packet, print a diagnostic, but continue.
    //The display handler architecture is designed to survive missing information, like this.
    if(rc)
    {
        pv_display_error("Could not advertise the driver's capabilities (%d)!\n", rc);
        return rc;
    }

    //Indicate success.
    return 0;
}


/**
 * Advertises a list of displays that the PV Driver would /like/ to handle-- typically in response
 * to a Host Display Change event.
 *
 * @param provider The Display Provider via which the advertised information will be communicated.
 * @param displays An array of dh_display_info objects, which will be advertised to the Display Handler.
 * @param display_count The number of displays to be advertised.
 *
 * @return 0 on success, or an error code on failure.
 */
#if defined _WIN32
//False positive AFAICT
#pragma warning (suppress: 28167)
#endif
static int provider_advertise_displays(struct pv_display_provider *provider, struct dh_display_info *displays, uint32_t display_count)
{
    int rc;

    __PV_HELPER_TRACE__;

    //Determine the total size of our advertisement payload.
    size_t payload_size = sizeof(struct dh_display_advertised_list) + sizeof(struct dh_display_info) * display_count;

    //Allocate space for the list of advertised displays...
    struct dh_display_advertised_list *list = pv_helper_malloc(payload_size);

    //If we weren't able to allocate a memory buffer, fail out!
    if(!list)
    {
        pv_display_error("Could not allocate enough space to advertise a list of displays!");
        return -ENOMEM;
    }

    //Copy the provided list of displays into our new structure...
    list->num_displays = display_count;
    memcpy(list->displays, displays, sizeof(struct dh_display_info) * display_count);

    //Finally, send the newly-constructed packet.
    pv_helper_lock(&provider->lock);
    rc = __send_packet(provider->control_channel, PACKET_TYPE_CONTROL_ADVERTISED_DISPLAY_LIST, list, payload_size);
    pv_helper_unlock(&provider->lock);

    //For now, provide a notification on failure.
    if(rc)
    {
        pv_display_error("Unable to send a list of advertised displays! (%d)", rc);
    }

    pv_helper_free(list);
    return rc;
}


/**
 * Forces the given display into "text mode", ensuring that only displays that support
 * emulating text mode are displayed. For now, this should only be used by the QEMU display driver.
 *
 * @param provider The display provider for the QEMU instance requesting text mode.
 * @param force_text_mode True iff the domain should be forced into "text mode".
 */
static int provider_force_text_mode(struct pv_display_provider *provider, bool force_text_mode)
{
    int rc;
    __PV_HELPER_TRACE__;

    //Populate a "text mode" packet...
    struct dh_text_mode payload;
    payload.mode = force_text_mode ? PACKET_TEXT_MODE_ENABLED : PACKET_TEXT_MODE_DISABLED;

    pv_display_checkp(provider, -EINVAL);

    //... and send it via IVC.
    pv_helper_lock(&provider->lock);
    rc = __send_packet(provider->control_channel, PACKET_TYPE_CONTROL_TEXT_MODE,
                       &payload, sizeof(payload));
    pv_helper_unlock(&provider->lock);

    //If we couldn't turn on text mode, print a diagnostic.
    if(rc)
    {
        pv_display_error("Could not switch to text mode (%d)!\n", rc);
        return rc;
    }

    //Indicate success.
    return 0;
}


/**
 * Destructor for the PV display provider object. Frees any memory associated
 * with the given object, and terminates all relevant connections.
 *
 * NOTE: You must free all subordinate PV display objects before freeing the
 * a PV Display Provider, or memory leaks will occur.
 *
 * @param display The display provider to be destroyed.
 */
static void provider_destroy(struct pv_display_provider *provider)
{
    __PV_HELPER_TRACE__;

    //If we were passed a null pointer, something's gone wrong. Report the issue.
    if(!provider)
    {
        pv_display_error("Memory leak likely: something tried to a free a null provider!\n");
        return;
    }

    //Close and clean up the control channel.
    if(provider->control_channel)
        libivc_disconnect(provider->control_channel);

    //Finally, destroy the object itself.
    pv_helper_free(provider);
}


/**
 * Handles registration of an event handler for Host Display Change events.
 * Currently only allows registration of a single handler.
 *
 * @param provider The display event for which the handler should be registered.
 * @param handler The callback function which should be called to handle the given event.
 */
static void provider_register_host_display_change_handler(struct pv_display_provider *provider, host_display_change_event_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&provider->lock);

    //Update the registration.
    provider->host_display_change_handler = handler;

    // Update the capabilities provided by the driver
    provider->capabilities |= DH_CAP_RESIZE;

    pv_helper_unlock(&provider->lock);
}


/**
 * Handles registration of an request handler for Add Display requests.
 * Currently only allows registration of a single handler.
 *
 * @param provider The display event for which the handler should be registered.
 * @param handler The callback function which should be called to handle the given event.
 */
static void provider_register_add_display_request_handler(struct pv_display_provider *provider, add_display_request_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&provider->lock);

    //Update the registration.
    provider->add_display_handler = handler;

    // Update the capabilities provided by the driver
    provider->capabilities |= DH_CAP_HOTPLUG;

    pv_helper_unlock(&provider->lock);
}

/**
 * Handles registration of an request handler for Remove Display requests.
 * Currently only allows registration of a single handler.
 *
 * @param provider The display event for which the handler should be registered.
 * @param handler The callback function which should be called to handle the given event.
 */
static void provider_register_remove_display_request_handler(struct pv_display_provider *provider, remove_display_request_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&provider->lock);

    //Update the registration.
    provider->remove_display_handler = handler;

    // Update the capabilities provided by the driver
    provider->capabilities |= DH_CAP_HOTPLUG;

    pv_helper_unlock(&provider->lock);
}


/**
 * Handles registration of a fatal error handler for PV display providers.
 * Currently only allows registration of a single handler.
 *
 * @param provider The display event for which the handler should be registered.
 * @param handler The callback function which should be called to handle unrecoverable errors.
 */
static void provider_register_fatal_error_handler(struct pv_display_provider *provider, fatal_provider_error_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&provider->lock);

    //Update the registration.
    provider->fatal_error_handler = handler;

    pv_helper_unlock(&provider->lock);
}


/**
 * Create a new PV display provider object, and start up its control channel.
 *
 * @param pv_display_provider Out argument to recieve the newly-created display provider object.
 * @param display_domain The domain ID for the domain that will recieve our display information, typically domain 0.
 * @param control_port The port number on which the display module will connect.
 */
int create_pv_display_provider_with_conn_id(struct pv_display_provider **display_provider, domid_t display_domain, uint16_t control_port, uint64_t conn_id)
{
    int rc;

    //First, allocate the new display-provider structure.
    struct pv_display_provider *provider = pv_helper_malloc(sizeof(*provider));

    __PV_HELPER_TRACE__;

    //If we couldn't allocate a new display provider, return an error code.
    if(!provider)
        return -ENOMEM;

    //Initialize our display provider's fields:
    provider->rx_domain    = display_domain;
    provider->control_port = control_port;
    provider->conn_id      = conn_id;
    provider->owner        = NULL;
    provider->current_packet_header.length = 0;

    //... and the lock that protects the display provider.
    pv_helper_mutex_init(&provider->lock);
    pv_helper_lock(&provider->lock);

    //Set up the main control channel connection.
    rc = __open_control_connection(provider);

    //If we weren't able to connect, fail out.
    if(unlikely(rc))
    {
        pv_helper_unlock(&provider->lock);
        //Tear down what we've already allocated...
        pv_helper_free(provider);
        *display_provider = NULL;

        //... and indicate there's no host "device".
        return -ENXIO;
    }

    //Finally, bind methods to the display provider.
    provider->advertise_capabilities    = provider_advertise_capabilities;
    provider->advertise_displays        = provider_advertise_displays;
    provider->create_display            = provider_create_display;
    provider->destroy_display           = provider_destroy_display;
    provider->force_text_mode           = provider_force_text_mode;
    provider->destroy                   = provider_destroy;

    //... and bind the registration methods for the events.
    provider->register_host_display_change_handler    = provider_register_host_display_change_handler;
    provider->register_add_display_request_handler    = provider_register_add_display_request_handler;
    provider->register_remove_display_request_handler = provider_register_remove_display_request_handler;
    provider->register_fatal_error_handler            = provider_register_fatal_error_handler;

    //Finally, unlock the PV display provider, making it ready for use.
    pv_helper_unlock(&provider->lock);

    //... and return our valid object.
    *display_provider = provider;
    return 0;
}

int create_pv_display_provider(struct pv_display_provider **display_provider, domid_t display_domain, uint16_t control_port)
{
    return create_pv_display_provider_with_conn_id(display_provider, display_domain, control_port, LIBIVC_ID_NONE);
}

/******************************************************************************/
/* Kernel Macros                                                              */
/******************************************************************************/

#if defined __linux__ && defined __KERNEL__
EXPORT_SYMBOL(create_pv_display_provider);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PV display communications helpers");

#elif defined WIN32 && defined KERNEL
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD PvDisplayHelperEvtDeviceAdd;

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "pv_display_helper: DriverEntry\n"));
	WDF_DRIVER_CONFIG_INIT(&config, PvDisplayHelperEvtDeviceAdd);
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
	//Initialize the global providers lock.
	return status;
}

NTSTATUS PvDisplayHelperEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
	NTSTATUS status;
	WDFDEVICE hDevice;
	(void)Driver;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "pv_display_helper: PvDisplayHelperEvtDeviceAdd\n"));
	status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
	return status;
}

#endif

void try_to_read_header(struct pv_display_provider *provider)
{
    __try_to_read_header(provider);
}

void try_to_receive_control_packet(struct pv_display_provider *provider)
{
    __try_to_receive_control_packet(provider);
}
