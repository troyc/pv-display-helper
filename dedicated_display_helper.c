// 
// OpenXT Paravirtualized Display Helpers for the Display Handler
//
// Copyright (C) 2016 Assured Information Security, Inc. All rights reserved.
// Author: Kyle J. Temkin  <temkink@ainfosec.com>
//

#include "dedicated_display_helper.h"


/******************************************************************************/
/* Dedicated Display Provider Methods                                         */
/******************************************************************************/

/**
 * Advertises all known displays, from the guest perspective-- with the goal of
 * conveying the size and location of dedicated displays. This can also be set for
 *
 * @param provider The Display Provider via which the advertised information will be communicated.
 * @param displays An array of dh_display_info objects, which will be advertised to the Display Handler.
 * @param display_count The number of displays to be advertised.
 *
 * @return 0 on success, or an error code on failure.
 */
static int provider_advertise_displays(struct dedicated_display_provider *provider, struct dh_display_info *displays, uint32_t display_count)
{
    __PV_HELPER_TRACE__;
    pv_display_checkp(provider, -EINVAL);

    // Delegate to our internal provider.
    return provider->core_provider->advertise_displays(provider->core_provider,
        displays, display_count);
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
static void provider_destroy(struct dedicated_display_provider *provider)
{
    __PV_HELPER_TRACE__;
    pv_display_checkp(provider);

    // Destroy our inner provider...
    provider->core_provider->destroy(provider->core_provider);

    // ... and our outer one.
    pv_helper_free(provider);
}



/**
 * Handles registration of a fatal error handler for PV display providers.
 * Currently only allows registration of a single handler.
 *
 * @param provider The display event for which the handler should be registered.
 * @param handler The callback function which should be called to handle unrecoverable errors.
 */
#if defined _WIN32
//False positive AFAICT
#pragma warning(suppress: 28167)
#endif
static void provider_register_fatal_error_handler(struct dedicated_display_provider *provider, fatal_dedicated_error_handler handler, void* userData)
{
    __PV_HELPER_TRACE__;
    pv_helper_lock(&provider->lock);

    //Update the registration.
    provider->fatal_error_handler = handler;
    provider->user_data = userData;

    pv_helper_unlock(&provider->lock);
}


/**
 * Handles any error that occurs in a Dedicated Display Provider's inner provider,
 * and forwards them to the provider's fatal error handler, if possible.
 *
 * @param core_provider The inner provider that triggered the fatal error.
 */
static void __handle_fatal_core_provider_error(struct pv_display_provider *core_provider)
{
    struct dedicated_display_provider *provider;

    __PV_HELPER_TRACE__;
    pv_display_checkp(core_provider);
    pv_display_checkp(core_provider->owner);

    // Get the dedicated display provider that owns the error'ing core_provider...
    provider = core_provider->owner;

    //... and trigger its fatal error handler, if possible.
    if(provider->fatal_error_handler)
        provider->fatal_error_handler(provider, provider->user_data);
}

/**
 * Create a new PV display provider object, and start up its control channel.
 *
 * @param pv_display_provider Out argument to receive the newly-created display provider object.
 * @param display_domain The domain ID for the domain that will receive our display information, typically domain 0.
 * @param control_port The port number on which the display module will connect.
 * @param connection_id The connection ID (unique ID) for the given connection. 
 */
#if defined _WIN32
//Can't figure out what is triggering this warning. 
#pragma warning(suppress: 28167)
#endif
int create_dedicated_display_provider(struct dedicated_display_provider **display_provider, domid_t display_domain, uint16_t control_port)
{
    int rc;

    // First, allocate the new display-provider structure.
    struct dedicated_display_provider *provider = pv_helper_malloc(sizeof(*provider));
    struct pv_display_provider *core_provider;

    __PV_HELPER_TRACE__;

    // If we couldn't allocate a new display provider, return an error code.
    if(!provider)
        return -ENOMEM;

    // Attempt to create an inner display provider, which establishes our control connection.
    rc = create_pv_display_provider(&core_provider, display_domain, control_port);
    if(rc || !core_provider)
    {
        pv_display_debug("Couldn't create a display provider (%d), aborting!\n", rc);
        pv_helper_free(provider);
        return rc;
    }

    // Create the lock that will protect our provider.
    pv_helper_mutex_init(&provider->lock);
    pv_helper_lock(&provider->lock);

    // Update our internal record of our core provider, and set its parent accordingly.
    provider->core_provider = core_provider;
    core_provider->owner    = provider;

    // Register an internal error handler; this will be responsible for triggering any user-provided
    // error handler.
    core_provider->register_fatal_error_handler(core_provider, __handle_fatal_core_provider_error);

    // Register our methods.
    provider->register_fatal_error_handler = provider_register_fatal_error_handler;
    provider->advertise_displays           = provider_advertise_displays;
    provider->destroy                      = provider_destroy;

    //Finally, unlock the PV display provider, making it ready for use.
    pv_helper_unlock(&provider->lock);

    // Indicate success, and return our new provider.
    *display_provider = provider;
    return 0;
}


