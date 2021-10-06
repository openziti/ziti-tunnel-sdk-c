/*
 Copyright 2019-2021 NetFoundry Inc.

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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "uv.h"

static char eventsockfile[] = "\\\\.\\pipe\\ziti-edge-tunnel-event.sock";

static void cmd_alloc(uv_handle_t *s, size_t sugg, uv_buf_t *b) {
    b->base = malloc(sugg);
    b->len = sugg;
}

static void on_response(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    if (len > 0) {
        printf("received response <%.*s>\n", (int) len, b->base);
    } else {
        fprintf(stderr,"Read Response error %s\n", uv_err_name(len));
    }
}

void on_connect(uv_connect_t* connect, int status){
    if (status < 0) {
        puts("failed to connect!");
    } else {
        puts("connected!");
        int res = uv_read_start((uv_stream_t *) connect->handle, cmd_alloc, on_response);
        if (res != 0) {
            printf("UV read error %s\n", uv_err_name(res));
        }
    }
}

static uv_loop_t* connect_and_read_message(char sockfile[],uv_connect_t* connect, uv_pipe_t* client_handle) {
    uv_loop_t* loop = uv_default_loop();

    int res = uv_pipe_init(loop, client_handle, 0);
    if (res != 0) {
        printf("UV client handle init failed %s\n", uv_err_name(res));
        return NULL;
    }

    uv_pipe_connect(connect, client_handle, sockfile, on_connect);

    return loop;
}

int main(int argc, char *argv[]) {
    uv_pipe_t client_handle;
    uv_connect_t* connect = (uv_connect_t*)malloc(sizeof(uv_connect_t));

    uv_loop_t* loop = connect_and_read_message(eventsockfile, connect, &client_handle);

    if (loop == NULL) {
        printf("Cannot run UV loop, loop is null");
        return 1;
    }

    int res = uv_run(loop, UV_RUN_DEFAULT);
    if (res != 0) {
        printf("UV run error %s\n", uv_err_name(res));
        return 1;
    }
    uv_close((uv_handle_t *)&client_handle, NULL);
    return 0;
}


