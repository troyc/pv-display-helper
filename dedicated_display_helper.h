// 
// OpenXT Paravirtualized Display Helpers for the Display Handler
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
// Author: Kyle J. Temkin  <temkink@ainfosec.com>
//

#ifndef __DEDICATED_DISPLAY_HELPER_H__
#define __DEDICATED_DISPLAY_HELPER_H__

#include "pv_display_helper.h"

/******************************************************************************/
/* Forward Declarations                                                       */
/******************************************************************************/

struct dedicated_display_provider;


/******************************************************************************/
/* Event Handler Callbacks                                                    */
/******************************************************************************/

/**
 * Fatal Dedicated Provider Error Handler
 *
 * Handles any unrecoverable error that occurs in w PV display-- intended to allow
 * the owning driver to handle recovery/reconnection.
 *
 * @param provider The provider which suffered the unrecoverable error.
 *
 */
typedef void (*fatal_dedicated_error_handler)(struct dedicated_display_provider *provider, void* userData);


/******************************************************************************/
/* Data Structures                                                            */
/******************************************************************************/


/**
 * Dedicated Display Provider "Object"
 * Represents a Display Handler dedicated display reporting "provider"--
 * essentially a subset of the 
 */
struct dedicated_display_provider
{
    //"Big" lock for the display object.
    //Used to ensure exclusive access to the given display object.
    pv_helper_mutex lock;

    //
    // Fields
    //

    // The core pv_display_provider that handles all of our methods. We essentially
    // are implementing the equivalent to a pattern in which dedicated_display_provider
    // and pv_display_provider share a common  "base class", but without a lot of the C
    // hacks typically used to simulate inheritance.
    struct pv_display_provider * core_provider;

    //
    // Methods
    //

    /**
     * Advertises a collection of displays that the PV Driver would like to provide.
     * This is typically sent in response to a host display list, but can be received at any time.
     *
     * @param provider The relevant PV display provider object.
     * @param displays An array of displays to be advertised.
     * @param display_count The number of displays to be advertised.
     */
    int (*advertise_displays)(struct dedicated_display_provider *provider, struct dh_display_info *displays, uint32_t display_count);

    /**
     * Destructor for the PV display provider object. Frees any memory associated
     * with the given object, and terminates all relevant connections.
     *
     * @param provider The provider to be destroyed.
     */
    void (*destroy)(struct dedicated_display_provider *provider);


    /**
     * Registers a fatal error handler for the dedicated display provider object.
     * This method will be called if the conneciton state is unrecoverable.
     */
    void (*register_fatal_error_handler)(struct dedicated_display_provider *provider, fatal_dedicated_error_handler error_handler, void* userData);


    //
    // Event Handlers
    //
    fatal_dedicated_error_handler fatal_error_handler;
    void* user_data;
};

/******************************************************************************/
/* Public Interface                                                           */
/******************************************************************************/

/**
 * Windows symbol export declarations.
 */
#ifdef WIN32
    #ifdef COMPILING_DLL
        #define dll_exported __declspec(dllexport)
    #else
        #define dll_exported
    #endif
#else
    #define dll_exported
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Create a new dedicated display provider object, and start up its control channel.
     *
     * @param pv_display_provider Out argument to recieve the newly-created display provider object.
     * @param owner The device object that owns the given display provider. Not used internally-- but can be accessed from events and callbacks.
     * @param display_domain The domain ID for the domain that will recieve our display information, typically domain 0.
     * @param control_port The port number on which the display module will connect.
     */
	dll_exported int create_dedicated_display_provider(struct dedicated_display_provider **display_provider, domid_t display_domain, uint16_t control_port);

#ifdef __cplusplus
}
#endif

#endif
