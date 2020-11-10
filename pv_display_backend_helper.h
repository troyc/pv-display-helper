//
// PV Display Helper
//
// Copyright (C) 2016 - 2017 Assured Information Security, Inc. All rights reserved.
//
#ifndef PV_DISPLAY_BACKEND_HELPER__H
#define PV_DISPLAY_BACKEND_HELPER__H

#include "common.h"

struct pv_display_backend;
struct pv_display_consumer;

typedef void (*framebuffer_connection_handler)(void *opaque, struct libivc_client *client);
typedef void (*dirty_rect_connection_handler)(void *opaque, struct libivc_client *client);
typedef void (*cursor_image_connection_handler)(void *opaque, struct libivc_client *client);
typedef void (*event_connection_handler)(void *opaque, struct libivc_client *client);

typedef void (*dirty_rectangle_request_handler)(struct pv_display_backend *display,
                                                uint32_t x, uint32_t y,
                                                uint32_t width, uint32_t height);
typedef void (*move_cursor_request_handler)(struct pv_display_backend *display,
                                            uint32_t x, uint32_t y);
typedef void (*update_cursor_request_handler)(struct pv_display_backend *display,
                                              uint32_t xhot, uint32_t yhot, uint32_t show);
typedef void (*set_display_request_handler)(struct pv_display_backend *display,
                                            uint32_t width, uint32_t height,
                                            uint32_t stride);
typedef void (*blank_display_request_handler)(struct pv_display_backend *display,
                                              uint32_t reason);

/**
 * Fatal Display Error Handler
 *
 * Handles any unrecoverable error that occurs in w PV display-- intended to allow
 * the owning driver to handle recovery/reconnection.
 *
 * @param display The display which suffered the unrecoverable error.
 *
 */
typedef void (*fatal_display_backend_error_handler)(struct pv_display_backend *display);

/**
 * PV Display "Object"
 * Represents an active PV display's backend, as created by a PV display consumer.
 */
struct pv_display_backend
{
    //"Big" lock for the display object.
    //Used to ensure exclusive access to the given display object.
    pv_helper_mutex lock;
    pv_helper_mutex fatal_lock;

    //
    // Fields
    //

    //Any driver data associated with the given display.
    //Not used by the helper; but useful to provide information about any data that
    //needs to be cleaned up upon destruction.
    void *driver_data;

    // Target domain information
    uint16_t domid;
    uint16_t event_port;
    uint16_t framebuffer_port;
    uint16_t cursor_bitmap_port;
    uint16_t dirty_rectangles_port;

    //The Display Handler key associated with the given display.
    uint32_t key;

    //The width and height of the display.
    uint32_t width;
    uint32_t height;

    //The stride used in the framebuffer's backing store.
    uint32_t stride;

    //A pointer to the shared framebuffer for the given display.
    //If NULL, the framebuffer has not yet been set up.
    void *framebuffer;
    size_t framebuffer_size;

    //A structure storing information about any PV cursor
    //associated with the display.
    struct pv_cursor cursor;

    //Flag to indicate that display has disconnected
    bool disconnected;

    //
    // Required Connections
    //

    //The IVC connection used to store the relevant framebuffer.
    bool framebuffer_server_listening;
    struct libivc_server *framebuffer_server;
    struct libivc_client *framebuffer_connection;

    //The IVC connection used to exchange per-display event data with the Display Handler.
    bool event_server_listening;
    struct libivc_server *event_server;
    struct libivc_client *event_connection;

    //
    // Optional Connections
    //

    //The IVC connection used to share dirty region data.
    bool dirty_rectangles_server_listening;
    struct libivc_server *dirty_rectangles_server;
    struct libivc_client *dirty_rectangles_connection;

    //The IVC connection used to share the cursor image.
    bool cursor_image_server_listening;
    struct libivc_server *cursor_image_server;
    struct libivc_client *cursor_image_connection;

    // Connection handlers
    framebuffer_connection_handler new_framebuffer_connection_handler;
    dirty_rect_connection_handler  new_dirty_rect_connection_handler;
    cursor_image_connection_handler new_cursor_connection_handler;
    event_connection_handler new_event_connection_handler;

    void (*finish_framebuffer_connection)(struct pv_display_backend *display, struct libivc_client *client);
    void (*finish_event_connection)(struct pv_display_backend *display, struct libivc_client *client);
    void (*finish_dirty_rect_connection)(struct pv_display_backend *display, struct libivc_client *client);
    void (*finish_cursor_connection)(struct pv_display_backend *display, struct libivc_client *client);

    void (*register_framebuffer_connection_handler)(struct pv_display_backend *display,
                                                    framebuffer_connection_handler handler);
    void (*register_dirty_rect_connection_handler)(struct pv_display_backend *display,
                                                   dirty_rect_connection_handler handler);
    void (*register_cursor_image_connection_handler)(struct pv_display_backend *display,
                                                     cursor_image_connection_handler handler);
    void (*register_event_connection_handler)(struct pv_display_backend *display,
                                              event_connection_handler handler);

    /**
     * @return The display driver data associated with the given display.
     */
    void *(*get_driver_data)(struct pv_display_backend *display);
    void (*set_driver_data)(struct pv_display_backend *display, void *data);

    int (*start_servers)(struct pv_display_backend *display);

    //
    // Event Registration Functions
    //
    void (*register_dirty_rectangle_handler)(struct pv_display_backend *display,
                                             dirty_rectangle_request_handler handler);
    void (*register_move_cursor_handler)(struct pv_display_backend *display,
                                         move_cursor_request_handler handler);
    void (*register_update_cursor_handler)(struct pv_display_backend *display,
                                           update_cursor_request_handler handler);
    void (*register_set_display_handler)(struct pv_display_backend *display,
                                         set_display_request_handler handler);
    void (*register_blank_display_handler)(struct pv_display_backend *display,
                                           blank_display_request_handler handler);

    //Register an Fatal Error handler
    void (*register_fatal_error_handler)(struct pv_display_backend *display,
                                         fatal_display_backend_error_handler error_handler);
    void (*disconnect_display)(struct pv_display_backend *display);

    //
    // Event Handlers
    //
    dirty_rectangle_request_handler dirty_rectangle_handler;
    move_cursor_request_handler move_cursor_handler;
    update_cursor_request_handler update_cursor_handler;
    set_display_request_handler set_display_handler;
    blank_display_request_handler blank_display_handler;

    fatal_display_backend_error_handler fatal_error_handler;

    //A data structure storing the header for the packet currently being
    //recieved. If this packet is valid, it will have a non-zero length.
    struct dh_header current_packet_header;
};


/**
 * PV Display consumer function prototypes
 *
 *
 */
typedef void (*control_connection_handler)(void *opaque, struct libivc_client *client);

typedef void (*driver_capabilities_request_handler)(struct pv_display_consumer *consumer,
        struct dh_driver_capabilities *request);

typedef void (*advertised_list_request_handler)(struct pv_display_consumer *consumer,
        struct dh_display_advertised_list *request);

typedef void (*display_no_longer_available_request_handler)(struct pv_display_consumer *consumer,
        struct dh_display_no_longer_available *request);

typedef void (*text_mode_request_handler)(struct pv_display_consumer *consumer,
        bool force);

typedef void (*fatal_consumer_error_handler)(struct pv_display_consumer *consumer, bool disconnect);

/**
 * PV Display Consumer "Object"
 * Represents a Display Handler PV display consumer.
 */
struct pv_display_consumer
{

    //"Big" lock for the display provider object.
    //Used to ensure exclusive access to the given display provider.
    pv_helper_mutex lock;

    //
    // Fields
    //

    //The domain ID for the domain to which we are connected.
    domid_t rx_domain;

    //The port on which control communications have been initialized.
    uint16_t control_port;

    //IVC connection id
    uint64_t conn_id;

    //The libivc server used to setup the control channel.
    bool control_channel_server_listening;
    struct libivc_server *control_channel_server;

    //The libivc channel used to exchange infrequent control information.
    struct libivc_client *control_channel;

    //The module/object that owns the given plugin.
    void *data;


    //A data structure storing the header for the packet currently being
    //recieved. If this packet is valid, it will have a non-zero length.
    struct dh_header current_packet_header;

    //
    // Methods
    //

    int (*create_pv_display_backend)(struct pv_display_consumer *consumer,
                                    struct pv_display_backend **display,
                                    domid_t domid,
                                    uint32_t event_port,
                                    uint32_t framebuffer_port,
                                    uint32_t dirty_rectangles_port,
                                     uint32_t cursor_bitmap_port,
                                     void *opaque);

    void (*set_driver_data)(struct pv_display_consumer *consumer, void *data);
    void *(*get_driver_data)(struct pv_display_consumer *consumer);
    int (*start_server)(struct pv_display_consumer *consumer);

    /**
     * Advertises the available displays for a guest to process.
     * This is typically sent in response to a driver capabilities packet, but can be received at any time.
     *
     * @param consumer The relevant PV display consumer object.
     * @param host_display_list Packet containing the dh_display_info information for each display.
     * @param display_count The number of displays to be to provide to the guest.
     */
    int (*display_list)(struct pv_display_consumer *consumer,
                        struct dh_display_info *displays,
                        uint32_t display_count);

    /**
     * Creates a new PV Display object, which represents an individual display -- as typically provided by a display provider.
     * Note that creating a display will not immediately make it usable-- to user a display, one must call its update_resolution
     * method.
     *
     * @param consumer The relevant PV display consumer object.
     * @param key The key to be associated with the given display.
     * @param display The host side representation of the new display for the given tx_domain.
     * @param event_port The port to be associated with the given display's event communication.
     * @param framebuffer_port The port to be associated with the given display's framebuffer connection.
     * @param dirty_rectangle_port The port to be associated with the given display's dirty rectangle connection.
     * @param cursor_bitmap_port The port to be associated with the given display's cursor connection.
     *
     */
    int (*add_display)(struct pv_display_consumer *consumer,
                       uint32_t key,
                       uint32_t event_port,
                       uint32_t framebuffer_port,
                       uint32_t dirty_rectangles_port,
                       uint32_t cursor_bitmap_port);


    /**
     * Notifies the guest that the display has been removed.
     *
     * Sends the dh_remove_display packet to the guest for the display associated with
     * the key. This can be sent by the display handler at any point.
     *
     * @param consumer The relevant PV display consumer object.
     * @param key The key associated with the display to be removed from the guest.
     *
     */
    int (*remove_display)(struct pv_display_consumer *consumer,
                          uint32_t key);

    /**
     * Destroy a display via the consumer
     *
     **/
    void (*destroy_display)(struct pv_display_consumer *consumer,
                            struct pv_display_backend *display);

    //Destructor for the PV display provider object. Frees any memory associated
    //with the given object, and terminates all relevant connections.
    void (*destroy)(struct pv_display_consumer *consumer);

    void (*finish_control_connection)(struct pv_display_consumer *consumer, void *client);

    //
    // Event Registration Functions
    //

    //
    void (*register_control_connection_handler)(struct pv_display_consumer *consumer,
                                                control_connection_handler handler);

    //Register a driver capabilities request handler handler.
    void (*register_driver_capabilities_request_handler)(struct pv_display_consumer *consumer,
                                                         driver_capabilities_request_handler handler);

    //Register a display advertised list request handler.
    void (*register_display_advertised_list_request_handler)(struct pv_display_consumer *consumer,
                                                             advertised_list_request_handler handler);

    //Register a set display request handler.
    void (*register_set_display_request_handler)(struct pv_display_consumer *consumer,
                                                 set_display_request_handler handler);

    //Register an display no longer available handler.
    void (*register_display_no_longer_available_request_handler)(struct pv_display_consumer *consumer,
                                                                 display_no_longer_available_request_handler handler);

    //Register a text mode handler
    void (*register_text_mode_request_handler)(struct pv_display_consumer *consumer,
                                               text_mode_request_handler handler);

    //Register an Fatal Error handler
    void (*register_fatal_error_handler)(struct pv_display_consumer *consumer,
                                         fatal_consumer_error_handler handler);

    //
    // Registerable Event Handlers;
    // see documentation for the delegate types above.
    //

    //Allow for library consumers to handle the control channel registration
    //in the thread they choose
    control_connection_handler new_control_connection;

    //Guest driver capabilities to be processed
    driver_capabilities_request_handler driver_capabilities_handler;

    //Advertised list request
    advertised_list_request_handler advertised_list_handler;

    //Set Display Request
    set_display_request_handler set_display_handler;

    //Display no longer available request
    display_no_longer_available_request_handler display_no_longer_available_handler;

    //Text mode request
    text_mode_request_handler text_mode_handler;

    //Fatal Provider Error
    fatal_consumer_error_handler fatal_error_handler;
};

int consumer_create_pv_display_backend(struct pv_display_consumer *consumer,
                                       struct pv_display_backend **d,
                                       domid_t domid,
                                       uint32_t event_port,
                                       uint32_t framebuffer_port,
                                       uint32_t dirty_rectangles_port,
                                       uint32_t cursor_bitmap_port,
                                       void *opaque);

int create_pv_display_consumer(struct pv_display_consumer **display_consumer, domid_t provider_domain, uint16_t control_port, void *opaque);

int destroy_pv_display_consumer(struct pv_display_consumer *display_consumer);

int create_pv_display_consumer_with_conn_id(struct pv_display_consumer **display_consumer, domid_t provider_domain, uint16_t control_port, uint64_t conn_id, void *opaque);

#endif
