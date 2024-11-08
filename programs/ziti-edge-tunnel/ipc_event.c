// Copyright 2024 NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>
#include <uv.h>
#include <tlsuv/queue.h>
#include <ziti/model_support.h>
#include <ziti/ziti_log.h>

#include "instance-config.h"

extern void send_tunnel_status(char* status);

struct event_conn_s {
    uv_pipe_t *event_client_conn;
    LIST_ENTRY(event_conn_s) _next_event;
};
// list to store the event connections
static LIST_HEAD(events_list, event_conn_s) event_clients_list = LIST_HEAD_INITIALIZER(event_clients_list);

static uv_pipe_t event_server;

static int sizeof_event_clients_list() {
    struct event_conn_s *event_client;
    int size = 0;
    LIST_FOREACH(event_client, &event_clients_list, _next_event) {
        size++;
    }

    if (size == 0) {
        return size;
    }

    int current_size = size;

    // clean up closed event connection from the list
    for (int idx = 0; idx < size; idx++) {
        struct event_conn_s *del_event_client = NULL;
        LIST_FOREACH(del_event_client, &event_clients_list, _next_event) {
            if (del_event_client->event_client_conn == NULL) {
                break;
            }
        }
        if (del_event_client) {
            LIST_REMOVE(del_event_client, _next_event);
            free(del_event_client);
            current_size--;
        } else {
            // break from for loop
            break;
        }
    }

    return current_size;

}

static void on_events_client(uv_stream_t *s, int status) {
    int current_events_channels = sizeof_event_clients_list();
    uv_pipe_t* event_conn = malloc(sizeof(uv_pipe_t));
    uv_pipe_init(s->loop, event_conn, 0);
    uv_accept(s, (uv_stream_t *) event_conn);
    struct event_conn_s *event_client_conn = calloc(1, sizeof(struct event_conn_s));
    event_client_conn->event_client_conn = event_conn;
    LIST_INSERT_HEAD(&event_clients_list, event_client_conn, _next_event);
    ZITI_LOG(DEBUG,"Received events client connection request, count: %d", ++current_events_channels);

    // send status message immediately
    send_tunnel_status("status");
}

void on_write_event(uv_write_t* req, int status) {
    if (status < 0) {
        ZITI_LOG(ERROR,"Could not sent events message. Write error %s\n", uv_err_name(status));
        if (status == UV_EPIPE) {
            struct event_conn_s *event_client;
            LIST_FOREACH(event_client, &event_clients_list, _next_event) {
                if (event_client->event_client_conn == (uv_pipe_t*) req->handle) {
                    break;
                }
            }
            if (event_client) {
                uv_close((uv_handle_t *) event_client->event_client_conn, (uv_close_cb) free);
                event_client->event_client_conn = NULL;
                int current_event_connection_count = sizeof_event_clients_list();
                ZITI_LOG(WARN,"Events client connection closed, count : %d", current_event_connection_count);

            }

        }
    } else {
        ZITI_LOG(TRACE,"Events message is sent.");
    }
    if (req->data) {
        free(req->data);
    }
    free(req);
}

void send_events_message(const void *message, to_json_fn to_json_f, bool displayEvent) {
    size_t data_len = 0;
    char *json = to_json_f(message, MODEL_JSON_COMPACT, &data_len);
    if (json == NULL) {
        ZITI_LOG(ERROR, "failed to serialize event");
        return;
    }
    if (displayEvent) {
        ZITI_LOG(DEBUG,"Events Message => %s", json);
    }

    if (!LIST_EMPTY(&event_clients_list)) {
        struct event_conn_s *event_client;
        int events_deleted = 0;
        LIST_FOREACH(event_client, &event_clients_list, _next_event) {
            int err = 0;
            if (event_client->event_client_conn != NULL) {
                uv_buf_t buf;
                data_len = data_len + strlen("\n") + 1;
                buf.base = calloc(data_len, sizeof(char));
                snprintf(buf.base, data_len, "%s\n", json);
                buf.len = strlen(buf.base);
                uv_write_t *wr = calloc(1, sizeof(uv_write_t));
                wr->data = buf.base;
                err = uv_write(wr, (uv_stream_t *)event_client->event_client_conn, &buf, 1, on_write_event);
            }
            if (err < 0){
                ZITI_LOG(ERROR,"Events client write operation failed, received error - %s", uv_err_name(err));
                if (err == UV_EPIPE) {
                    uv_close((uv_handle_t *) event_client->event_client_conn, (uv_close_cb) free);
                    event_client->event_client_conn = NULL;
                    events_deleted++;
                    ZITI_LOG(WARN,"Events client connection closed");
                }
            }
        }
        if (events_deleted > 0) {
            int current_event_connection_count = sizeof_event_clients_list();
            ZITI_LOG(WARN,"Events client connection current count : %d", current_event_connection_count);
        }

    }
    free(json);
}



int start_event_socket(uv_loop_t *l, const char *eventsockfile) {

    if (uv_is_active((const uv_handle_t *) &event_server)) {
        return 0;
    }

    uv_fs_t fs;
    uv_fs_unlink(l, &fs, eventsockfile, NULL);

    CHECK_UV(uv_pipe_init(l, &event_server, 0));
    CHECK_UV(uv_pipe_bind(&event_server, eventsockfile));
    CHECK_UV(uv_pipe_chmod(&event_server, UV_WRITABLE | UV_READABLE));

    uv_unref((uv_handle_t *) &event_server);

    CHECK_UV(uv_listen((uv_stream_t *) &event_server, 0, on_events_client));

    return 0;

    uv_err:
    return -1;
}
