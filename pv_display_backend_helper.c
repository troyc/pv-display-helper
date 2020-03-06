//
// PV Display Helper
//
// Copyright (C) 2016 - 2017 Assured Information Security, Inc. All rights reserved.
//
#include "common.h"
#include "pv_display_helper.h"
#include "pv_display_backend_helper.h"

/**
 * Triggers the given consumers's fatal error handler, if one exists.
 *
 * @param display The PV display whose fatal error handler is to be triggered.
 */
static void __trigger_fatal_error_on_consumer(struct pv_display_consumer *consumer)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);
    if(consumer->fatal_error_handler)
        consumer->fatal_error_handler(consumer);
    pv_display_error(" triggering consumer error\n");
    pv_helper_unlock(&consumer->lock);
}

/**
 * Triggers the given display's fatal error handler, if one exists.
 *
 * @param display The PV display whose fatal error handler is to be triggered.
 */
static void __trigger_fatal_error_on_display_backend(struct pv_display_backend *display)
{
    __PV_HELPER_TRACE__;
    if(!display) {
        return;
    }

    pv_helper_lock(&display->fatal_lock);
    if(display->fatal_error_handler) {
        fatal_display_backend_error_handler tmp_fn = display->fatal_error_handler;
        display->fatal_error_handler = NULL;
        tmp_fn(display);
    }
    pv_helper_unlock(&display->fatal_lock);
}

/**
 * Attempts to read in a new packet header from the provided IVC channel,
 * and to the given buffer. This method attempts to read an entire header--
 * if no header is available, the buffer is not changed.
 *
 * @return 0 if a header was read, or an error code otherwise.
 */
static bool __try_to_read_header(struct pv_display_consumer *consumer)
{
    int rc;

    __PV_HELPER_TRACE__;

    //Attempt to perform a packetized read, which will pull in a header packet
    //if at all possible.
    rc = libivc_recv(consumer->control_channel, (char *)&consumer->current_packet_header, sizeof(struct dh_header));

    return (rc == SUCCESS);
}

static void __handle_guest_driver_capabilities_event(struct pv_display_consumer *consumer, struct dh_driver_capabilities *request)
{
    __PV_HELPER_TRACE__;

    if(!consumer->driver_capabilities_handler)
    {
        pv_display_error("A driver capabilities packet has been received, but no handler has been registered.");
        return;
    }

    consumer->driver_capabilities_handler(consumer, request);
}

static void __handle_advertised_display_list_request(struct pv_display_consumer *consumer, struct dh_display_advertised_list *request)
{
    __PV_HELPER_TRACE__;

    if(!consumer->advertised_list_handler)
    {
        pv_display_error("An advertised display list packet has been received, but no handler has been registered.");
        return;
    }

    consumer->advertised_list_handler(consumer, request);
}

static void __handle_display_no_longer_available_request(struct pv_display_consumer *consumer, struct dh_display_no_longer_available *request)
{
    __PV_HELPER_TRACE__;

    if(!consumer->display_no_longer_available_handler)
    {
        pv_display_error("A display no longer available request has been received, but no handler has been registered.");
        return;
    }

    consumer->display_no_longer_available_handler(consumer, request);
}

static void __handle_text_mode_request(struct pv_display_consumer *consumer, struct dh_text_mode *request)
{
    __PV_HELPER_TRACE__;

    if(!consumer->text_mode_handler)
    {
        pv_display_error("A text mode request has been received, but no handler has been registered.");
        return;
    }

    consumer->text_mode_handler(consumer, request);
}

/**
 * Handles receipt of a client control packet, delegating the packet to the appropriate handler
 * accoring to type.
 *
 * @param display The display which received the given control packet.
 * @param header The header object for the received packet.
 * @param buffer The payload for the given object.
 */
static void __handle_control_packet_receipt(struct pv_display_consumer *consumer, struct dh_header *header, void *buffer)
{
    __PV_HELPER_TRACE__;

    //Delegate the event to the approriate handler, according to type.
    switch(header->type)
    {
        // Driver Capabilities event-- the guest has sent it's capabilities
        case PACKET_TYPE_CONTROL_DRIVER_CAPABILITIES:
            pv_display_debug("Recieved a Driver Capabilities event!\n");
            __handle_guest_driver_capabilities_event(consumer, (struct dh_driver_capabilities *)buffer);
            break;

        //Advertised Display List Requests-- the guest is offering these displays
        case PACKET_TYPE_CONTROL_ADVERTISED_DISPLAY_LIST:
            pv_display_debug("Recieved an Advertised Display List request!\n");
            __handle_advertised_display_list_request(consumer, (struct dh_display_advertised_list *)buffer);
            break;

        //Display No Longer Available Requests-- the guest is revoking a display
        case PACKET_TYPE_CONTROL_DISPLAY_NO_LONGER_AVAILABLE:
            pv_display_debug("Recieved a Display No Longer Available request!\n");
            __handle_display_no_longer_available_request(consumer, (struct dh_display_no_longer_available *)buffer);
            break;
        //Text Mode Requests-- the guest is expecting the text mode buffer be displayed
        case PACKET_TYPE_CONTROL_TEXT_MODE:
            pv_display_debug("Received a Text Mode request\n");
            __handle_text_mode_request(consumer, (struct dh_text_mode *)buffer);
            break;

        default:
            //For now, do nothing if we receive an unknown packet type-- this gives us some safety in the event of a version
            //mismatch. We may want to consider other behaviors, as well-- disconnecting, or sending an event to the host.
            pv_display_error("Received unknown or unexpected packet type (%u)! No action will be taken.\n", (unsigned int)header->type);
            break;
    }
}

/**
 * Handle the (possible) receipt of a control packet. Note that this function
 * can be called at any time after a valid packet header has been received.
 *
 * @return True iff a packet was read.
 */
static bool __try_to_receive_control_packet(struct pv_display_consumer *consumer)
{
    __PV_HELPER_TRACE__;

    size_t length_with_footer;

    size_t data_available;
    struct dh_footer *footer;
    uint16_t checksum;
    char *buffer;
    int rc;

    //Determine the size of the remainder of the packet-- composed of the packet body ("payload") and footer.
    length_with_footer = consumer->current_packet_header.length + sizeof(struct dh_footer);

    //Ask IVC for the total amount of data available.
    rc = libivc_getAvailableData(consumer->control_channel, &data_available);

    //If we failed to get the /amount/ of available data, we're in trouble!
    //Fail out loudly.
    if(rc)
    {
        pv_display_error("Could not query IVC for its available data!\n");
        __trigger_fatal_error_on_consumer(consumer);
        return false;
    }

    //If we haven't yet received enough data to parse the given packet,
    //abort quietly. We'll get the data on the next event.
    if(data_available < length_with_footer)
    {
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
        return false;
    }

    //Finally, read in the remainder of the packet.
    pv_display_debug("Receiving %u bytes...\n", (unsigned int)length_with_footer);
    rc = libivc_recv(consumer->control_channel, buffer, length_with_footer);

    //If we couldn't read in the remainder of the packet, something went wrong--
    //perhaps someone read before we did? (Bad locking?)
    if(rc)
    {
        pv_display_error("Could not read in a packet, though IVC claims it's there. Locking problems?\n");
        pv_helper_free(buffer);
        return false;
    }

    //Finally, we'll make sure the packet is valid. To do so, we'll first get a reference to the footer,
    //which should be located right after the main packet body.
    footer = (struct dh_footer *)(buffer + consumer->current_packet_header.length);

    //Compute the checksum of the received packet.
    checksum = __pv_helper_packet_checksum(&consumer->current_packet_header, buffer, consumer->current_packet_header.length);

    //Check the packet's CRC. If it doesn't match, we're in serious trouble. Bail out.
    if(checksum != footer->crc)
    {
        pv_display_error("Communications error: CRC did not match for a control packet. Terminating connections.\n");

        //Invalidate the received packet...
        consumer->current_packet_header.length = 0;

        //... clean up, and return.
        pv_helper_free(buffer);
        __trigger_fatal_error_on_consumer(consumer);
        return false;
    }

    //Invalidate the current packet header, as we've already handled it!
    consumer->current_packet_header.length = 0;

    //Finally, pass the compelted packet to our packet receipt handler.
    __handle_control_packet_receipt(consumer, &consumer->current_packet_header, buffer);

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
    struct pv_display_consumer *consumer = opaque;
    pv_helper_lock(&consumer->lock);

    bool continue_to_read = false;
    pv_display_debug("Received a control channel event for remote %d on port %d\n", consumer->rx_domain, consumer->control_port);

    //We've received a control channel event, which means that the remote side
    //has sent us at least a portion of a packet. We'll attempt to read all of
    //the data available, stopping we've run out of data to read.
    do
    {
        //If we haven't yet read in a valid header, try do to so.
        if(consumer->current_packet_header.length == 0)
        {
            pv_display_debug("I'm not aware of an existing packet. Trying to read its header.\n");
            continue_to_read = __try_to_read_header(consumer);
        }

        //If we now have a defined packet "shape" to receive, try to receive it.
        if(consumer->current_packet_header.length > 0)
        {
            pv_display_debug("Receiving a Type-%u packet in progress. Trying to receive...\n",
                             (unsigned int)consumer->current_packet_header.type);
            continue_to_read = __try_to_receive_control_packet(consumer);
        }
    }
    while(continue_to_read);
    pv_helper_unlock(&consumer->lock);
}

/**
 * Sets the private per-driver data for the given display.
 *
 * @param display The display for which the data should be associated.
 * @param data The data to be associated with the given display.
 */
static void pv_display_backend_set_driver_data(struct pv_display_backend *display, void *data)
{
    __PV_HELPER_TRACE__;

    pv_helper_lock(&display->lock);
    display->driver_data = data;
    pv_helper_unlock(&display->lock);
}

/**
 * @return The display driver data associated with the given display.
 */
static void *pv_display_backend_get_driver_data(struct pv_display_backend *display)
{
    __PV_HELPER_TRACE__;
    void *value;

    value = display->driver_data;

    return value;
}

/**
 * Handle control channel events. These events usually indicate that we've
 * received a collection of control data-- but not necessarily a whole packet.
 */
static void __handle_control_channel_disconnect(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;
    (void)client;
    //Find the PV display provider associated with the given client...
    struct pv_display_consumer *consumer = opaque;

    pv_display_debug(" Disconnecting Control Channel for domid %d port %d!\n",  consumer->rx_domain, consumer->control_port);
    __trigger_fatal_error_on_consumer(consumer);

    //Make sure ivc gets cleaned up.
    libivc_disconnect(client);
}

void __handle_control_connection(void *opaque, struct libivc_client *client)
{
    __PV_HELPER_TRACE__;

    struct pv_display_consumer *consumer = (struct pv_display_consumer *)opaque;
    pv_helper_lock(&consumer->lock);
    if(consumer && consumer->new_control_connection) {
        consumer->new_control_connection(consumer->data, client);
    }
    pv_helper_unlock(&consumer->lock);

}

void finish_control_connection(struct pv_display_consumer *consumer,
                               void *cli)
{
    __PV_HELPER_TRACE__;
    struct libivc_client *client = cli;
    consumer->control_channel = client;

    libivc_register_event_callbacks(consumer->control_channel,
                                    __handle_control_channel_event,
                                    __handle_control_channel_disconnect,
                                    consumer);

    __handle_control_channel_event(consumer, consumer->control_channel);
}

int __create_control_server(struct pv_display_consumer *consumer)
{
    int rc = 0;

    __PV_HELPER_TRACE__;

    rc = libivc_start_listening_server(&consumer->control_channel_server,
                                       consumer->control_port,
                                       consumer->rx_domain,
                                       CONNECTIONID_ANY,
                                       __handle_control_connection,
                                       consumer);

    consumer->control_channel_server_listening = true;

    return rc;
}

/**
 * Event Connections
 *
 */
 /**
  * Attempts to read in a new packet header from the provided IVC channel,
  * and to the given buffer. This method attempts to read an entire header--
  * if no header is available, the buffer is not changed.
  *
  * @return 0 if a header was read, or an error code otherwise.
  */
 static bool __try_to_read_event_header(struct pv_display_backend *display)
 {
     int rc = -1;
     size_t available_data = 0;
     __PV_HELPER_TRACE__;


     //Attempt to perform a packetized read, which will pull in a header packet
     //if at all possible.
     libivc_getAvailableData(display->event_connection, &available_data);

     if(available_data >= sizeof(struct dh_header)) {
       rc = libivc_recv(display->event_connection,
			(char *)&display->current_packet_header,
			sizeof(struct dh_header));
     }

     return (rc == SUCCESS);
 }

static void __handle_set_display_request(struct pv_display_backend *display, struct dh_set_display *request)
{
    if(!display->set_display_handler) {
        pv_display_debug("A 'set display' event was received, but no one registered a listener.\n");
        return;
    }

    pv_display_debug("display_request: %p - %dx%d - %d", display, request->width, request->height, request->stride);

    display->set_display_handler(display, request->width, request->height, request->stride);
}

static void __handle_update_cursor_request(struct pv_display_backend *display, struct dh_update_cursor *request)
{
    if(!display->update_cursor_handler) {
        pv_display_debug("An 'update cursor' event was received, but no one registered a listener.\n");
        return;
    }

    display->update_cursor_handler(display, request->xhot, request->yhot, request->show);
}

static void __handle_move_cursor_request(struct pv_display_backend *display, struct dh_move_cursor *request)
{
    if(!display->move_cursor_handler) {
        pv_display_debug("A 'move cursor' event was received, but no one registered a listener.\n");
        return;
    }

    display->move_cursor_handler(display, request->x, request->y);
}

static void __handle_blank_display_request(struct pv_display_backend *display, struct dh_blanking *request)
{
  if(!display->blank_display_handler) {
    pv_display_debug("A 'blank display' event was received, but no one registered a listener.\n");
    return;
  }

  display->blank_display_handler(display, request->reason);
}

static void __handle_event_packet_receipt(struct pv_display_backend *display, struct dh_header *header, void *buffer)
{
    __PV_HELPER_TRACE__;

    //Delegate the event to the approriate handler, according to type.
    switch(header->type)
    {
        // Driver Capabilities event-- the guest has sent it's capabilities
        case PACKET_TYPE_EVENT_SET_DISPLAY:
            pv_display_debug("Received a set display event!\n");
            __handle_set_display_request(display, (struct dh_set_display *)buffer);
            break;

        // Driver Capabilities event-- the guest has sent it's capabilities
        case PACKET_TYPE_EVENT_BLANK_DISPLAY:
            pv_display_debug("Received a set display event!\n");
            __handle_blank_display_request(display, (struct dh_blanking *)buffer);
            break;

        //Advertised Display List Requests-- the guest is offering these displays
        case PACKET_TYPE_EVENT_UPDATE_CURSOR:
            pv_display_debug("Received an update cursor request!\n");
            __handle_update_cursor_request(display, (struct dh_update_cursor *)buffer);
            break;

        //Display No Longer Available Requests-- the guest is revoking a display
        case PACKET_TYPE_EVENT_MOVE_CURSOR:
            pv_display_debug("Received a move cursor request!\n");
            __handle_move_cursor_request(display, (struct dh_move_cursor *)buffer);
            break;

        default:
            //For now, do nothing if we receive an unknown packet type-- this gives us some safety in the event of a version
            //mismatch. We may want to consider other behaviors, as well-- disconnecting, or sending an event to the host.
            pv_display_error("Received unknown or unexpected packet type (%u)! No action will be taken.\n", (unsigned int)header->type);
            break;
    }
}

/**
 * Handle the (possible) receipt of a control packet. Note that this function
 * can be called at any time after a valid packet header has been received.
 *
 * @return True iff a packet was read.
 */
static bool __try_to_receive_event_packet(struct pv_display_backend *display)
{
    __PV_HELPER_TRACE__;

    size_t length_with_footer;

    size_t data_available;
    struct dh_footer *footer;
    uint16_t checksum;
    char *buffer;
    int rc;

    //Determine the size of the remainder of the packet-- composed of the packet body ("payload") and footer.
    length_with_footer = display->current_packet_header.length + sizeof(struct dh_footer);

    //Ask IVC for the total amount of data available.
    rc = libivc_getAvailableData(display->event_connection, &data_available);

    //If we failed to get the /amount/ of available data, we're in trouble!
    //Fail out loudly.
    if(rc)
    {
        pv_display_error("Could not query IVC for its available data!\n");
        return false;
    }

    //If we haven't yet received enough data to parse the given packet,
    //abort quietly. We'll get the data on the next event.
    if(data_available < length_with_footer)
    {
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
        return false;
    }

    //Finally, read in the remainder of the packet.
    pv_display_debug("Receiving %u bytes...\n", (unsigned int)length_with_footer);
    rc = libivc_recv(display->event_connection, buffer, length_with_footer);

    //If we couldn't read in the remainder of the packet, something went wrong--
    //perhaps someone read before we did? (Bad locking?)
    if(rc)
    {
        pv_display_error("Could not read in a packet, though IVC claims it's there. Locking problems?\n");
        pv_helper_free(buffer);
        return false;
    }

    //Finally, we'll make sure the packet is valid. To do so, we'll first get a reference to the footer,
    //which should be located right after the main packet body.
    footer = (struct dh_footer *)(buffer + display->current_packet_header.length);

    //Compute the checksum of the received packet.
    checksum = __pv_helper_packet_checksum(&display->current_packet_header, buffer, display->current_packet_header.length);

    //Check the packet's CRC. If it doesn't match, we're in serious trouble. Bail out.
    if(checksum != footer->crc)
    {
        pv_display_error("Communications error: CRC did not match for a control packet. Terminating connections.\n");

        //Invalidate the received packet...
        display->current_packet_header.length = 0;

        //... clean up, and return.
        pv_helper_free(buffer);
        return false;
    }

    //Invalidate the current packet header, as we've already handled it!
    display->current_packet_header.length = 0;

    //Finally, pass the compelted packet to our packet receipt handler.
    __handle_event_packet_receipt(display, &display->current_packet_header, buffer);

    //Clean up our buffer.
    pv_helper_free(buffer);

    return true;
 }


 /**
  * Handle control channel events. These events usually indicate that we've
  * received a collection of control data-- but not necessarily a whole packet.
  */
 static void __handle_event_channel_event(void *opaque, struct libivc_client *client)
 {
     __PV_HELPER_TRACE__;
     (void)client;

     //Find the PV display provider associated with the given client.
     struct pv_display_backend *display = opaque;
     bool continue_to_read = false;
     
     //Lock this so we don't disconnect while we are reading
     pv_helper_lock(&display->lock);

     if (display->disconnected) {
         pv_display_debug("Received event on closed channel \n");
         pv_helper_unlock(&display->lock);
         return;
     }
     pv_display_debug("Received a control channel event.\n");
     //We've received a control channel event, which means that the remote side
     //has sent us at least a portion of a packet. We'll attempt to read all of
     //the data available, stopping we've run out of data to read.
     do
     {
         //If we haven't yet read in a valid header, try do to so.
         if(display->current_packet_header.length == 0)
         {
           pv_display_debug("I'm not aware of an existing packet. Trying to read its header.\n");
           continue_to_read = __try_to_read_event_header(display);
         }

         //If we now have a defined packet "shape" to receive, try to receive it.
         if(display->current_packet_header.length > 0)
         {
             pv_display_debug("Receiving a Type-%u packet in progress. Trying to receive...\n",
                              (unsigned int)display->current_packet_header.type);
             continue_to_read = __try_to_receive_event_packet(display);
         }
     }
     while(continue_to_read);
     pv_helper_unlock(&display->lock);

 }

static void __handle_event_channel_disconnect(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;
    if(!display) {
        return;
    }

    __trigger_fatal_error_on_display_backend(display);
}

static void finish_event_connection(struct pv_display_backend *display,
                                    struct libivc_client *client)
{
    display->event_connection = client;

    if(!display->event_connection) {
        return;
    }

    libivc_register_event_callbacks(display->event_connection,
                                    __handle_event_channel_event,
                                    __handle_event_channel_disconnect,
                                    display);

    libivc_enable_events(display->event_connection);
}

static void __handle_event_connection(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;
    __PV_HELPER_TRACE__;
    if(display->new_event_connection_handler) {
        display->new_event_connection_handler(display->driver_data, client);
    }
}

/**
 * Framebuffer Connections
 *
 */
static void __handle_framebuffer_disconnect(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;
    if(!display) {
        return;
    }

    __trigger_fatal_error_on_display_backend(display);
}

static void finish_framebuffer_connection(struct pv_display_backend *display,
                                          struct libivc_client *client)
{

    display->framebuffer_connection = client;

    if(!display->framebuffer_connection) {
        return;
    }

    libivc_register_event_callbacks(display->framebuffer_connection, NULL, __handle_framebuffer_disconnect, display);
    libivc_getLocalBuffer(display->framebuffer_connection, (char **)&display->framebuffer);
    libivc_getLocalBufferSize(display->framebuffer_connection, &display->framebuffer_size);
}

static void __handle_framebuffer_connection(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;

    __PV_HELPER_TRACE__;

    if(display->new_framebuffer_connection_handler) {
        display->new_framebuffer_connection_handler(display->driver_data, client);
    }
}

/**
 * Dirty Rectangle Connections
 *
 */
static void __handle_dirty_rectangle_event(void *opaque, struct libivc_client *client)
{
    struct dh_dirty_rectangle rect;
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;
    size_t available_data = 0;

    libivc_getAvailableData(client, &available_data);

    while(available_data >= sizeof(struct dh_dirty_rectangle) && libivc_isOpen(client) && display->dirty_rectangles_connection) {
      memset(&rect, 0, sizeof(struct dh_dirty_rectangle));
      libivc_recv(client, (char*)&rect, sizeof(struct dh_dirty_rectangle));
      display->dirty_rectangle_handler(display, rect.x, rect.y, rect.width, rect.height);
      available_data -= sizeof(struct dh_dirty_rectangle);
    }
}

static void __handle_dirty_rectangle_disconnect(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;
    if(!display) {
        return;
    }

    __trigger_fatal_error_on_display_backend(display);
}

static void finish_dirty_rect_connection(struct pv_display_backend *display, struct libivc_client *client)
{
    display->dirty_rectangles_connection = client;

    if(!display->dirty_rectangles_connection) {
        return;
    }

    libivc_register_event_callbacks(display->dirty_rectangles_connection,
                                    __handle_dirty_rectangle_event,
                                    __handle_dirty_rectangle_disconnect,
                                    display);

    libivc_enable_events(display->dirty_rectangles_connection);

}

static void __handle_dirty_rectangle_connection(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;

    __PV_HELPER_TRACE__;
    if(display->new_dirty_rect_connection_handler) {
        display->new_dirty_rect_connection_handler(display->driver_data, client);
    }
}

/**
 * Cursor Connections
 *
 */
static void __handle_cursor_disconnect(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;
    if(!display) {
        return;
    }

    __trigger_fatal_error_on_display_backend(display);
}

static void finish_cursor_connection(struct pv_display_backend *display, struct libivc_client *client)
{
    display->cursor_image_connection = client;

    if(!display->cursor_image_connection) {
        return;
    }

    libivc_register_event_callbacks(display->cursor_image_connection,
                                    NULL,
                                    __handle_cursor_disconnect,
                                    display);
    libivc_getLocalBuffer(display->cursor_image_connection,
                          (char **)&display->cursor.image);
}

static void __handle_cursor_connection(void *opaque, struct libivc_client *client)
{
    struct pv_display_backend *display = (struct pv_display_backend *)opaque;

    __PV_HELPER_TRACE__;
    if(display->new_cursor_connection_handler) {
        display->new_cursor_connection_handler(display->driver_data, client);
    }
}

typedef void (*dirty_rectangle_request_handler)(struct pv_display_backend *display,
                                                uint32_t x,
                                                uint32_t y,
                                                uint32_t width,
                                                uint32_t height);
typedef void (*move_cursor_request_handler)(struct pv_display_backend *display,
                                            uint32_t x,
                                            uint32_t y);
typedef void (*update_cursor_request_handler)(struct pv_display_backend *display,
                                              uint32_t xhot,
                                              uint32_t yhot,
                                              uint32_t show);
typedef void (*set_display_request_handler)(struct pv_display_backend *display,
                                            uint32_t width,
                                            uint32_t height,
                                            uint32_t stride);
typedef void (*blank_display_request_handler)(struct pv_display_backend *display,
                                              uint32_t reason);
typedef void (*fatal_display_backend_error_handler)(struct pv_display_backend *display);

static void
display_register_framebuffer_connection_handler(struct pv_display_backend *display,
                                                     framebuffer_connection_handler handler)
{
    pv_helper_lock(&display->lock);

    display->new_framebuffer_connection_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_dirty_rect_connection_handler(struct pv_display_backend *display,
                                               dirty_rect_connection_handler handler)
{
    pv_helper_lock(&display->lock);

    display->new_dirty_rect_connection_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_cursor_image_connection_handler(struct pv_display_backend *display,
                                                 cursor_image_connection_handler handler)
{
    pv_helper_lock(&display->lock);

    display->new_cursor_connection_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_event_connection_handler(struct pv_display_backend *display,
                                          event_connection_handler handler)
{
    pv_helper_lock(&display->lock);

    display->new_event_connection_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_dirty_rectangle_handler(struct pv_display_backend *display, dirty_rectangle_request_handler handler)
{
    pv_helper_lock(&display->lock);

    display->dirty_rectangle_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_move_cursor_handler(struct pv_display_backend *display, move_cursor_request_handler handler)
{
    pv_helper_lock(&display->lock);

    display->move_cursor_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_update_cursor_handler(struct pv_display_backend *display, update_cursor_request_handler handler)
{
    pv_helper_lock(&display->lock);

    display->update_cursor_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_set_display_handler(struct pv_display_backend *display, set_display_request_handler handler) 
{
    pv_helper_lock(&display->lock);

    display->set_display_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
display_register_blank_display_handler(struct pv_display_backend *display, blank_display_request_handler handler)
{
    pv_helper_lock(&display->lock);

    display->blank_display_handler = handler;

    pv_helper_unlock(&display->lock);
}


static void
display_register_fatal_error_handler(struct pv_display_backend *display, fatal_display_backend_error_handler handler)
{
    pv_helper_lock(&display->lock);

    display->fatal_error_handler = handler;

    pv_helper_unlock(&display->lock);
}

static void
pv_display_backend_display_disconnect(struct pv_display_backend *display)
{
    if(!display) {
        return;
    }

    pv_helper_lock(&display->lock);
    if(display->event_connection) {
        libivc_disable_events(display->event_connection);
        display->set_display_handler = NULL;
        display->blank_display_handler = NULL;
        display->move_cursor_handler = NULL;
        display->update_cursor_handler = NULL;
        libivc_disconnect(display->event_connection);
        display->event_connection = NULL;
    }

    if(display->framebuffer_connection) {
        libivc_disconnect(display->framebuffer_connection);
        display->framebuffer_connection = NULL;
        display->framebuffer_size = 0;
    }

    if(display->dirty_rectangles_connection) {
        libivc_disable_events(display->dirty_rectangles_connection);
        libivc_disconnect(display->dirty_rectangles_connection);
        display->dirty_rectangles_connection = NULL;
        display->dirty_rectangle_handler = NULL;
    }

    if(display->cursor_image_connection) {
        libivc_disable_events(display->cursor_image_connection);
        libivc_disconnect(display->cursor_image_connection);
        display->cursor_image_connection = NULL;
    }
    display->disconnected = true;
    pv_helper_unlock(&display->lock);
}

static void
consumer_destroy_display(struct pv_display_consumer *consumer, struct pv_display_backend *display)
{

    if(!consumer || !display) {
        return;
    }

    pv_display_backend_display_disconnect(display);

    pv_helper_lock(&display->lock);

    display->fatal_error_handler = NULL;

    if(display->event_server_listening) {
      struct libivc_server *tmp = display->event_server;
      display->event_server = NULL;
      display->event_server_listening = false;
      display->set_display_handler = NULL;
      display->blank_display_handler = NULL;
      display->move_cursor_handler = NULL;
      display->update_cursor_handler = NULL;

      libivc_shutdownIvcServer(tmp);
    }

    if(display->dirty_rectangles_server_listening) {
      struct libivc_server *tmp = display->dirty_rectangles_server;
      display->dirty_rectangles_server = NULL;
      display->dirty_rectangles_server_listening = false;
      display->dirty_rectangle_handler = NULL;
      libivc_shutdownIvcServer(tmp);
    }

    if(display->cursor_image_server_listening) {
      struct libivc_server *tmp = display->cursor_image_server;
      display->cursor_image_server = NULL;
      display->cursor_image_server_listening = false;
      libivc_shutdownIvcServer(tmp);
    }

    if(display->framebuffer_server_listening) {
      struct libivc_server *tmp = display->framebuffer_server;
      display->framebuffer_server = NULL;
      display->framebuffer_server_listening = false;
      display->framebuffer = NULL;
      libivc_shutdownIvcServer(tmp);
    }
    pv_helper_unlock(&display->lock);

    pv_helper_free(display);
}

static int
pv_display_backend_start_servers(struct pv_display_backend *display)
{
    int rc;

    if(!display) {
        return -EINVAL;
    }

    pv_helper_lock(&display->lock);
    display->framebuffer_server = libivc_find_listening_server(display->domid,
                                                               display->framebuffer_port,
                                                               CONNECTIONID_ANY);
    if(!display->framebuffer_server) {
        rc = libivc_start_listening_server(&display->framebuffer_server,
                                           display->framebuffer_port,
                                           display->domid,
                                           CONNECTIONID_ANY,
                                           __handle_framebuffer_connection,
                                           display);

        if(rc) {
            pv_display_error("Failed to create framebuffer server for %d, %d\n", display->domid, rc);
            goto framebuffer_server_fail;
        }
    }

    display->event_server = libivc_find_listening_server(display->domid,
                                                         display->event_port,
                                                         CONNECTIONID_ANY);
    if(!display->event_server) {
        rc = libivc_start_listening_server(&display->event_server,
                                           display->event_port,
                                           display->domid,
                                           CONNECTIONID_ANY,
                                           __handle_event_connection,
                                           display);
        if(rc) {
            pv_display_error("Failed to create event server for %d", display->domid);
            goto event_server_fail;
        }
    }

    display->dirty_rectangles_server = libivc_find_listening_server(display->domid,
                                                                    display->dirty_rectangles_port,
                                                                    CONNECTIONID_ANY);
    if(!display->dirty_rectangles_server) {
        rc = libivc_start_listening_server(&display->dirty_rectangles_server,
                                           display->dirty_rectangles_port,
                                           display->domid,
                                           CONNECTIONID_ANY,
                                           __handle_dirty_rectangle_connection,
                                           display);

        if(rc) {
            pv_display_error("Failed to create dirty rectangle server for %d, %d\n", display->domid, rc);
            goto dirty_server_fail;
        }
    }

    display->cursor_image_server = libivc_find_listening_server(display->domid,
                                                                display->cursor_bitmap_port,
                                                                CONNECTIONID_ANY);
    if(!display->cursor_image_server) {
        rc = libivc_start_listening_server(&display->cursor_image_server,
                                           display->cursor_bitmap_port,
                                           display->domid,
                                           CONNECTIONID_ANY,
                                           __handle_cursor_connection,
                                           display);

        if(rc) {
            pv_display_error("Failed to create cursor image server for %d, %d\n", display->domid, rc);
            goto cursor_server_fail;
        }
    }

    display->cursor_image_server_listening = true;
    display->dirty_rectangles_server_listening = true;
    display->framebuffer_server_listening = true;
    display->event_server_listening = true;

    pv_helper_unlock(&display->lock);
    return 0;

cursor_server_fail:
    //teardown dirty server
    libivc_shutdownIvcServer(display->dirty_rectangles_server);
dirty_server_fail:
    //teardown framebuffer server
    libivc_shutdownIvcServer(display->framebuffer_server);
framebuffer_server_fail:
    //teardown event server
    libivc_shutdownIvcServer(display->event_server);
event_server_fail:
    display->cursor_image_server_listening = false;
    display->dirty_rectangles_server_listening = false;
    display->framebuffer_server_listening = false;
    display->event_server_listening = false;

    pv_helper_unlock(&display->lock);
    return -EINVAL;
}

int consumer_create_pv_display_backend(struct pv_display_consumer *consumer,
                                       struct pv_display_backend **d,
                                       domid_t domid,
                                       uint32_t event_port,
                                       uint32_t framebuffer_port,
                                       uint32_t dirty_rectangles_port,
                                       uint32_t cursor_bitmap_port,
                                       void *opaque)
{
    struct pv_display_backend *display;

    __PV_HELPER_TRACE__;

    display = pv_helper_malloc(sizeof(*display));

    if(!display) {
        pv_display_error("Could not allocate enough memory for a new PV display object!\n")
        *d = NULL;
        return -ENOMEM;
    }

    //Initialize our object's lock, and immediately lock it.
    //This is important, to ensure that none of our callbacks are executed before the object
    //is completely initialized.
    pv_helper_mutex_init(&display->lock);
    pv_helper_mutex_init(&display->fatal_lock);

    //When set true, pending events will not be processed
    display->disconnected = false;

    pv_helper_lock(&display->lock);

    display->set_driver_data = pv_display_backend_set_driver_data;
    display->get_driver_data = pv_display_backend_get_driver_data;
    display->start_servers = pv_display_backend_start_servers;
    display->disconnect_display = pv_display_backend_display_disconnect;
    display->driver_data = opaque;

    display->finish_framebuffer_connection = finish_framebuffer_connection;
    display->finish_event_connection = finish_event_connection;
    display->finish_dirty_rect_connection = finish_dirty_rect_connection;
    display->finish_cursor_connection = finish_cursor_connection;

    display->domid = domid;
    display->event_port = event_port;
    display->framebuffer_port = framebuffer_port;
    display->cursor_bitmap_port = cursor_bitmap_port;
    display->dirty_rectangles_port = dirty_rectangles_port;

    //
    // Connection Registration Functions
    //
    display->register_framebuffer_connection_handler = display_register_framebuffer_connection_handler;
    display->register_dirty_rect_connection_handler = display_register_dirty_rect_connection_handler;
    display->register_cursor_image_connection_handler = display_register_cursor_image_connection_handler;
    display->register_event_connection_handler = display_register_event_connection_handler;

    //
    // Event Registration Functions
    //
    display->register_dirty_rectangle_handler = display_register_dirty_rectangle_handler;
    display->register_move_cursor_handler = display_register_move_cursor_handler;
    display->register_update_cursor_handler = display_register_update_cursor_handler;
    display->register_set_display_handler = display_register_set_display_handler;
    display->register_blank_display_handler = display_register_blank_display_handler;
    display->register_fatal_error_handler = display_register_fatal_error_handler;

    pv_helper_unlock(&display->lock);

    *d = display;

    return 0;
}

static int consumer_display_list(struct pv_display_consumer *consumer, struct dh_display_info *displays, uint32_t display_count)
{
    int rc;
    __PV_HELPER_TRACE__;

    //Determine the total size of our advertisement payload.
    size_t payload_size = sizeof(struct dh_display_list) + sizeof(struct dh_display_info) * display_count;

    // Allocate space
    struct dh_display_list* display_list = pv_helper_malloc(payload_size);

    if(!display_list) {
        pv_display_error("Couldn't allocate memory for host display list.");
        return -ENOMEM;
    }

    display_list->num_displays = display_count;
    memcpy(display_list->displays, displays, display_count * sizeof(*displays));

    //... and send it via IVC.
    rc = __send_packet(consumer->control_channel, PACKET_TYPE_CONTROL_HOST_DISPLAY_LIST,
                       display_list, payload_size);

    if(rc) {
      pv_display_error("Unable to send a list of host displays! (%d)", rc);
    }

    pv_helper_free(display_list);

    //Indicate success.
    return rc;
}

int consumer_add_display(struct pv_display_consumer *consumer,
                         uint32_t key,
                         uint32_t event_port,
                         uint32_t framebuffer_port,
                         uint32_t dirty_rectangles_port,
                         uint32_t cursor_bitmap_port)
{
    int rc;

    //Determine the total size of our advertisement payload.
    struct dh_add_display payload;

    __PV_HELPER_TRACE__;

    payload.key = key;
    payload.event_port = event_port;
    payload.framebuffer_port = framebuffer_port;
    payload.dirty_rectangles_port = dirty_rectangles_port;
    payload.cursor_bitmap_port = cursor_bitmap_port;

    //... and send it via IVC.
    rc = __send_packet(consumer->control_channel, PACKET_TYPE_CONTROL_ADD_DISPLAY,
                       &payload, sizeof(payload));

    if(rc) {
        pv_display_error("Unable to send an add host displays! (%d)", rc);
    }

    //Indicate success.
    return 0;
}

int consumer_remove_display(struct pv_display_consumer *consumer, uint32_t key)
{
    int rc;

    //Determine the total size of our advertisement payload.
    struct dh_remove_display payload;

    __PV_HELPER_TRACE__;

    payload.key = key;

    //... and send it via IVC.
    rc = __send_packet(consumer->control_channel, PACKET_TYPE_CONTROL_REMOVE_DISPLAY,
                       &payload, sizeof(payload));

    if(rc) {
        pv_display_error("Unable to send an remove host displays! (%d)", rc);
    }

    //Indicate success.
    return 0;
}

static void consumer_destroy(struct pv_display_consumer *consumer)
{
  if(consumer->control_channel_server_listening) {
      libivc_shutdownIvcServer(consumer->control_channel_server);
      consumer->control_channel_server = NULL;
      consumer->control_channel_server_listening = false;

      if(consumer->fatal_error_handler)
          consumer->fatal_error_handler(consumer);

      pv_helper_free(consumer);
  }
}

static void consumer_register_control_connection_handler(struct pv_display_consumer *consumer, control_connection_handler handler)
{
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->new_control_connection = handler;

    pv_helper_unlock(&consumer->lock);
}

static void consumer_register_driver_capabilities_request_handler(struct pv_display_consumer *consumer, driver_capabilities_request_handler handler)
{
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->driver_capabilities_handler = handler;

    pv_helper_unlock(&consumer->lock);
}

static void consumer_set_driver_data(struct pv_display_consumer *consumer, void *data)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);

    consumer->data = data;

    pv_helper_unlock(&consumer->lock);
}

static void *consumer_get_driver_data(struct pv_display_consumer *consumer)
{
    __PV_HELPER_TRACE__;

    return consumer->data;
}

static void consumer_register_display_advertised_list_request_handler(struct pv_display_consumer *consumer, advertised_list_request_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->advertised_list_handler = handler;

    pv_helper_unlock(&consumer->lock);
}

static void consumer_register_set_display_request_handler(struct pv_display_consumer *consumer, set_display_request_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->set_display_handler = handler;

    pv_helper_unlock(&consumer->lock);
}

static void consumer_register_display_no_longer_available_request_handler(struct pv_display_consumer *consumer, display_no_longer_available_request_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->display_no_longer_available_handler = handler;

    pv_helper_unlock(&consumer->lock);
}

static void consumer_register_text_mode_request_handler(struct pv_display_consumer *consumer, text_mode_request_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->text_mode_handler = handler;

    pv_helper_unlock(&consumer->lock);
}

static void consumer_register_fatal_error_handler(struct pv_display_consumer *consumer, fatal_consumer_error_handler handler)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&consumer->lock);

    //Update the registration.
    consumer->fatal_error_handler = handler;

    pv_helper_unlock(&consumer->lock);
}

static int
consumer_start_server(struct pv_display_consumer *consumer)
{
    int rc;

    pv_helper_lock(&consumer->lock);

    //Set up the main control channel connection.
    rc = __create_control_server(consumer);

    if(unlikely(rc)) {
        pv_helper_unlock(&consumer->lock);

        pv_helper_free(consumer);

        return -ENXIO;
    }
    pv_helper_unlock(&consumer->lock);
    return 0;
}

int create_pv_display_consumer_with_conn_id(struct pv_display_consumer **display_consumer, domid_t guest_domain, uint16_t control_port, uint64_t conn_id, void *opaque)
{
    //First, allocate the new display-consumer structure.
    struct pv_display_consumer *consumer = pv_helper_malloc(sizeof(*consumer));

    __PV_HELPER_TRACE__;

    //If we couldn't allocate a new display consumer, return an error code.
    if(!consumer)
        return -ENOMEM;

    //Initialize our display provider's fields:
    consumer->rx_domain    = guest_domain;
    consumer->control_port = control_port;
    consumer->conn_id      = conn_id;
    consumer->data        =  opaque;
    consumer->current_packet_header.length = 0;

    //... and the lock that protects the display provider.
    pv_helper_mutex_init(&consumer->lock);
    pv_helper_lock(&consumer->lock);

    consumer->create_pv_display_backend = consumer_create_pv_display_backend;
    consumer->finish_control_connection = finish_control_connection;
    consumer->set_driver_data = consumer_set_driver_data;
    consumer->get_driver_data = consumer_get_driver_data;
    consumer->display_list = consumer_display_list;
    consumer->add_display = consumer_add_display;
    consumer->remove_display = consumer_remove_display;
    consumer->destroy_display = consumer_destroy_display;
    consumer->start_server = consumer_start_server;
    consumer->destroy = consumer_destroy;

    consumer->register_control_connection_handler = consumer_register_control_connection_handler;
    consumer->register_driver_capabilities_request_handler = consumer_register_driver_capabilities_request_handler;
    consumer->register_display_advertised_list_request_handler = consumer_register_display_advertised_list_request_handler;
    consumer->register_set_display_request_handler = consumer_register_set_display_request_handler;
    consumer->register_display_no_longer_available_request_handler = consumer_register_display_no_longer_available_request_handler;
    consumer->register_text_mode_request_handler = consumer_register_text_mode_request_handler;
    consumer->register_fatal_error_handler = consumer_register_fatal_error_handler;

    *display_consumer = consumer;

    pv_helper_unlock(&consumer->lock);

    return 0;
}

int destroy_pv_display_consumer(struct pv_display_consumer *consumer)
{
  if(!consumer) {
    return -EINVAL;
  }

  pv_helper_lock(&consumer->lock);
  consumer->create_pv_display_backend = NULL;
  consumer->set_driver_data = NULL;
  consumer->get_driver_data = NULL;
  consumer->display_list = NULL;
  consumer->add_display = NULL;
  consumer->remove_display = NULL;
  consumer->destroy_display = NULL;
  consumer->destroy = NULL;

  if(consumer->control_channel_server_listening) {
    libivc_shutdownIvcServer(consumer->control_channel_server);
    consumer->control_channel_server = NULL;
    consumer->control_channel_server_listening = false;
  }

  pv_helper_unlock(&consumer->lock);

  return 0;
}

int create_pv_display_consumer(struct pv_display_consumer **display_consumer, domid_t guest_domain, uint16_t control_port, void *opaque)
{
	return create_pv_display_consumer_with_conn_id(display_consumer, guest_domain, control_port, 0, opaque);
}

