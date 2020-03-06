//
// OpenXT Paravirtualized Display Helpers for the Display Handler
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
// Author: Kyle J. Temkin  <temkink@ainfosec.com>
//

#ifndef __PV_DISPLAY_HELPER_H__
#define __PV_DISPLAY_HELPER_H__

#include "common.h"

/******************************************************************************/
/* Event / Request Handlers                                                   */
/******************************************************************************/

/**
 * Host Display List Handler
 *
 * Handles a Host Display List event, in which the host sends a list of displays
 * it would like the PV Driver to handle. This acts a as a hint for the PV
 * driver, which is expected to advertise a list of displays it would like to
 * provide as a result using advertise_displays.
 *
 * @param display The display provider for which the host displays are changing.
 * @param displays A pointer to an array of dh_display_info structures, which describe the
 *    host displays and their layout.
 * @param num_displays The number of entries in the displays array.
 */
typedef void (*host_display_change_event_handler)(struct pv_display_provider *provider,
        struct dh_display_info *displays, uint32_t num_displays);


/**
 * Add Display Request Handler
 *
 * Handles an Add Display Request, in which the host sends connection information
 * for a new framebuffer connection, and requests that the PV Driver connect to it,
 * and begin providing a new framebuffer (and asociated communications.)
 *
 * @param display The display provider which has receievd the Add Display request.
 * @param request The Add Display Request, which contains the information necessary
 *    to connect to the given display.
 *
 */
typedef void (*add_display_request_handler)(struct pv_display_provider *provider,
        struct dh_add_display *request);


/**
 * Remove Display Request Handler
 *
 * Handles an Remove Display Request, which notifies a display that the Display Handler
 * is no longer interested in working with it.
 *
 * @param display The display provider which has receievd the Remove Display request.
 * @param request The Remove Display Request, which contains the information necessary
 *    to connect to the given display.
 *
 */
typedef void (*remove_display_request_handler)(struct pv_display_provider *provider,
        struct dh_remove_display *request);


/**
 * Fatal Display Provider Error Handler
 *
 * Handles any unrecoverable error that occurs in w PV display-- intended to allow
 * the owning driver to handle recovery/reconnection.
 *
 * @param provider The provider which suffered the unrecoverable error.
 *
 */
typedef void (*fatal_provider_error_handler)(struct pv_display_provider *provider);


/**
 * Fatal Display Error Handler
 *
 * Handles any unrecoverable error that occurs in w PV display-- intended to allow
 * the owning driver to handle recovery/reconnection.
 *
 * @param display The display which suffered the unrecoverable error.
 *
 */
typedef void (*fatal_display_error_handler)(struct pv_display *display);


/******************************************************************************/
/* Iteration Helper Functions                                                 */
/******************************************************************************/

/**
 * Callback function for iteration over a list of PV displays.
 *
 * Used to allow the caller to execute a function on each of a list of PV  displays.
 */
typedef int (*display_iteration_callback)(struct pv_display *display);


/**
 * Callback function to ease searching for a provider that matches a given connection,
 */
typedef bool (*provider_connection_filter)(struct pv_display_provider *provider,
        struct libivc_client *client);


/**
 * Callback function to ease searching for a provider that matches a given connection,
 */
typedef bool (*display_connection_filter)(struct pv_display *display,
        struct libivc_client *client);


/**
 * Callback function to help with the location of a PV display provider, given a
 * particular client.
 */
typedef struct pv_display *(*pv_display_locator)(struct libivc_client *client);


/******************************************************************************/
/* Data Structures                                                            */
/******************************************************************************/

/**
 * PV Display "Object"
 * Represents an active PV display, as created by a PV display provider.
 */
struct pv_display
{
    //"Big" lock for the display object.
    //Used to ensure exclusive access to the given display object.
    pv_helper_mutex lock;


    //
    // Fields
    //

    //Any driver data associated with the given display.
    //Not used by the helper; but useful to provide information about any data that
    //needs to be cleaned up upon destruction.
    void *driver_data;

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

    //
    // Required Connections
    //

    //The IVC connection used to store the relevant framebuffer.
    struct libivc_client *framebuffer_connection;

    //The IVC connection used to exchange per-display event data with the Display Handler.
    struct libivc_client *event_connection;

    //
    // Optional Connections
    //

    //The IVC connection used to share dirty region data.
    struct libivc_client *dirty_rectangles_connection;

    //The IVC connection used to share the cursor image.
    struct libivc_client *cursor_image_connection;

    //
    // Methods
    //

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
    int (*reconnect)(struct pv_display *display,
        struct dh_add_display *request, domid_t rx_domain);

    /**
     * Sets the private per-driver data for the given display.
     *
     * @param display The display for which the data should be associated.
     * @param data The data to be associated with the given display.
     */
    void (*set_driver_data)(struct pv_display *display, void *data);


    /**
     * @return The display driver data associated with the given display.
     */
    void *(*get_driver_data)(struct pv_display *display);


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
    int (*change_resolution)(struct pv_display *display, uint32_t width, uint32_t height, uint32_t stride);


    /**
     * Marks a given region of the shared framebuffer as requiring a redraw ("dirty"),
     * and requests that the host redraw a given region.
     *
     * @param display The PV display whose region is to be invalidated.
     * @param x, y, width, height -- The four bounds of the "dirty rectangle" to be invalidated.
     *
     * @param int 0 on success, or an error code otherwise.
     */
    int (*invalidate_region)(struct pv_display *display, uint32_t x, uint32_t y, uint32_t width, uint32_t height);


    /**
     * @return True iff the given display currently supports a hardware cursor.
     */
    int (*supports_cursor)(struct pv_display *display);


    /**
     * Sets the "hot spot" (see above) for the PV cursor associated with
     * this display.
     *
     * @param display The display whose hardware cursor should be updatd.
     * @param hotspot_x The X coordinate of the cursor's hot spot.
     * @param hotspot_y The Y coordinate of the cursor's hot spot.
     * @return Zero on success, or an error code on failure.
     */
    int (*set_cursor_hotspot)(struct pv_display *display, uint32_t hotspot_x, uint32_t hotspot_y);

    /**
     * Sets the PV cursor's visibility.
     *
     * @param display The display whose hardware cursor should be updatd.
     * @param visible True iff the cursor should be rendered.
     * @return Zero on success, or an error code on failure.
     */
    int (*set_cursor_visibility)(struct pv_display *display, bool visible);


    /**
     * Moves the display's hardware cursor.
     *
     * @param display The display whose cursor is to be updated.
     * @param x The new X coordiante for the cursor on the display framebuffer.
     * @param y The new Y coordiante for the cursor on the display framebuffer.
     *
     * @return 0 on success, or an error code on failure.
     */
    int (*move_cursor)(struct pv_display *display, uint32_t x, uint32_t y);


    /**
     * Loads a cursor image into the PV display's cursor buffer,
     * if possible.
     *
     * @param display The display for which the cursor image is to be populated.
     * @param image A pointer to an ARGB8888 image to be loaded.
     * @param width The width (max 64) of the image to be loaded.
     * @param height The height (max 64) of the image to be loaded.
     */
    int (*load_cursor_image)(struct pv_display *display, void *image,
        uint8_t source_width, uint8_t source_height);

    /**
     * Blank a given display
     *
     * @param display Display that should be either blanked or restored from a blanked state.
     * @param dpms True if the display is blanked for sleep, and false if for a modesetting
     *        operation.
     * @param blank True iff the display should be blanked.
     */
     int (*blank_display)(struct pv_display *display, bool dpms, bool blank);

    /**
     * Destroys the given framebuffer, freeing its associated memory.
     */
    void (*destroy)(struct pv_display *display);


    //
    // Event Registration Functions
    //

    //Register an Fatal Error handler
    void (*register_fatal_error_handler)(struct pv_display *display, fatal_display_error_handler error_handler);


    //
    // Event Handlers
    //
    fatal_display_error_handler fatal_error_handler;


};


/**
 * PV Display Provider "Object"
 * Represents a Display Handler PV display provider.
 */
struct pv_display_provider
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

    //The libivc channel used to exchange infrequent control information.
    struct libivc_client *control_channel;

    //Driver capabilities (negotiating protocol)
    uint32_t capabilities;

    //The module/object that owns the given plugin.
    void *owner;

    //A data structure storing the header for the packet currently being
    //recieved. If this packet is valid, it will have a non-zero length.
    struct dh_header current_packet_header;

    //
    // Methods
    //

    /**
     * Advertises the PV Driver's capabilities to the host.
     * This packet is typically sent at the beginning of any connection with the Display Handler.
     *
     * @param provider The relevant PV display provider object.
     * @param max_displays The maximum number of displays the given plugin can handle, or PV_INTERFACE_MAX_DISPLAYS
     *    to indicate acceptance of any number of displays within the Display Handler's max.
     * @return 0 on success, or an error code on failure.
     */
    int (*advertise_capabilities)(struct pv_display_provider *provider, uint32_t max_displays);

    /**
     * Advertises a collection of displays that the PV Driver would like to provide.
     * This is typically sent in response to a host display list, but can be received at any time.
     *
     * @param provider The relevant PV display provider object.
     * @param displays An array of displays to be advertised.
     * @param display_count The number of displays to be advertised.
     */
    int (*advertise_displays)(struct pv_display_provider *provider, struct dh_display_info *displays, uint32_t display_count);


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
    int (*create_display)(struct pv_display_provider *provider, struct pv_display **new_display,
                          struct dh_add_display *request, uint32_t width, uint32_t height, uint32_t stride, void *initial_contents);


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
    int (*destroy_display)(struct pv_display_provider *provider, struct pv_display *display);

    /**
     * Forces the given display into "text mode", ensuring that only displays that support
     * emulating text mode are displayed. For now, this should only be used by the QEMU display driver.
     *
     * @param provider The display provider for the QEMU instance requesting text mode.
     * @param force_text_mode True iff the domain should be forced into "text mode".
     */
    int (*force_text_mode)(struct pv_display_provider *provider, bool force_text_mode);

    //Destructor for the PV display provider object. Frees any memory associated
    //with the given object, and terminates all relevant connections.
    void (*destroy)(struct pv_display_provider *display);


    //
    // Event Registration Functions
    //

    //Register a Host Display Changed event handler.
    void (*register_host_display_change_handler)(struct pv_display_provider *provider, host_display_change_event_handler event_handler);

    //Register an Add Display Request handler.
    void (*register_add_display_request_handler)(struct pv_display_provider *provider, add_display_request_handler request_handler);

    //Register a Remove Display Request handler.
    void (*register_remove_display_request_handler)(struct pv_display_provider *provider, remove_display_request_handler request_handler);

    //Register an Fatal Error handler
    void (*register_fatal_error_handler)(struct pv_display_provider *provider, fatal_provider_error_handler error_handler);

    //
    // Registerable Event Handlers;
    // see documentation for the delegate types above.
    //

    //Host Display has Changed
    host_display_change_event_handler host_display_change_handler;

    //Add Display Request
    add_display_request_handler add_display_handler;

    //Add Display Request
    remove_display_request_handler remove_display_handler;

    //Fatal Provider Error
    fatal_provider_error_handler fatal_error_handler;


};

/******************************************************************************/
/* Public Interface                                                           */
/******************************************************************************/

/**
 * Create a new PV display provider object, and start up its control channel.
 *
 * @param pv_display_provider Out argument to recieve the newly-created display provider object.
 * @param owner The device object that owns the given display provider. Not used internally-- but can be accessed from events and callbacks.
 * @param display_domain The domain ID for the domain that will recieve our display information, typically domain 0.
 * @param control_port The port number on which the display module will connect.
 */
#ifdef _WIN32
__declspec(dllexport)
#endif
int create_pv_display_provider(struct pv_display_provider **display_provider, domid_t display_domain, uint16_t control_port);
int create_pv_display_provider_with_conn_id(struct pv_display_provider **display_provider, domid_t display_domain, uint16_t control_port, uint64_t conn_id);

void try_to_read_header(struct pv_display_provider *provider);
void try_to_receive_control_packet(struct pv_display_provider *provider);

#endif
