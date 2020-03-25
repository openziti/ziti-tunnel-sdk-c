/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * @file ziti_tunneler.h
 * @brief Defines the macros, functions, typedefs and constants required to implement a Ziti
 * tunneler application.
 */

#ifndef NF_ZITI_TUNNELER_SDK_ZITI_TUNNELER_H
#define NF_ZITI_TUNNELER_SDK_ZITI_TUNNELER_H

#include "nf/ziti.h"

/**
 * @brief Initializes a Ziti Edge identity.
 *
 * This function is used to initialize a Ziti Edge identity. The Ziti C SDK is based around the [libuv](http://libuv.org/)
 * library and is maintains similar semantics.  This function is used to setup the chain of callbacks
 * needed once the loop begins to execute.
 *
 * This function will initialize the Ziti C SDK using the default TLS engine [mbed](https://tls.mbed.org/). If a
 * different TLS engine is desired use NF_init_with_tls().
 *
 * @param config location of identity configuration
 * @param loop libuv event loop
 * @param init_cb callback to be called when initialization is complete
 * @param init_ctx additional context to be passed into #nf_init_cb callback
 *
 * @return #ZITI_OK or corresponding #ZITI_ERRORS
 *
 * @see NF_init_with_tls()
 */
extern int NF_tunneler_init(const char* config, uv_loop_t* loop, nf_init_cb init_cb, void* init_ctx);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* NF_ZITI_TUNNELER_SDK_ZITI_TUNNELER_H */
