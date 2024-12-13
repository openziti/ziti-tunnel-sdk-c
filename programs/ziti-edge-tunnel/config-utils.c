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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include <ziti/ziti_model.h>
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include "tlsuv/http.h"

#if __linux__
#include <pwd.h>
#include <unistd.h>
#endif
#if _WIN32
#define realpath(rel, abs) _fullpath(abs, rel, PATH_MAX)
#endif

typedef struct api_update_req_s {
    uv_work_t wr;
    char *identifier;
    char *config_json;
    int err;
    const char *errmsg;
} api_update_req;


static int update_file(const char *path, char *content, size_t content_len) {
#define CHECK_UV(desc, op) do{ \
    uv_fs_req_cleanup(&fs_req); \
    rc = op;             \
    if (rc < 0) {           \
        ZITI_LOG(ERROR, "op[" desc "] failed: %d(%s)", rc, uv_strerror(rc)); \
        goto DONE;               \
    }} while(0)

    int rc = 0;
    uv_fs_t fs_req = {0};
    CHECK_UV("check exiting config", uv_fs_stat(NULL, &fs_req, path, NULL));
    uint64_t mode = fs_req.statbuf.st_mode;

    char backup[FILENAME_MAX];
    snprintf(backup, sizeof(backup), "%s.bak", path);
    CHECK_UV("create backup", uv_fs_rename(NULL, &fs_req, path, backup, NULL));

    uv_os_fd_t f;
    CHECK_UV("open new config", f = uv_fs_open(NULL, &fs_req, path, UV_FS_O_WRONLY | UV_FS_O_CREAT, (int) mode, NULL));
    uv_buf_t buf = uv_buf_init(content, content_len);
    CHECK_UV("write new config", uv_fs_write(NULL, &fs_req, f, &buf, 1, 0, NULL));
    CHECK_UV("close new config", uv_fs_close(NULL, &fs_req, f, NULL));

    DONE:
    return rc;
#undef CHECK_UV
}

#define CHECK_UV(desc, op) do{ \
int rc = op;             \
if (rc < 0) {           \
req->err = rc;           \
req->errmsg = uv_strerror(rc); \
ZITI_LOG(ERROR, "op[" desc "] failed: %d(%s)", req->err, req->errmsg); \
goto DONE;               \
}} while(0)

static void update_config(uv_work_t *wr) {
    api_update_req *req = wr->data;
    const char *config_file = req->identifier;
    size_t cfg_len;
    char *cfg_buf = NULL;
    uv_file f;

    ziti_config cfg = {0};
    ziti_config new_cfg = {0};
    if (ziti_load_config(&cfg, config_file) != ZITI_OK) {
        ZITI_LOG(ERROR, "failed to parse config file[%s]", config_file);
        req->err = -1;
        req->errmsg = "failed to parse existing config";
        goto DONE;
    }

    parse_ziti_config(&new_cfg, req->config_json, strlen(req->config_json));

    // attempt to update CA bundle external to config file
    if (strncmp(cfg.id.ca, "file://", strlen("file://")) == 0) {
        struct tlsuv_url_s path_uri;
        CHECK_UV("parse CA bundle path", tlsuv_parse_url(&path_uri, cfg.id.ca));
        const char *path = path_uri.path;
        CHECK_UV("update CA bundle file", update_file(path, (char*)new_cfg.id.ca, strlen(new_cfg.id.ca)));
        free((void*)new_cfg.id.ca);
        new_cfg.id.ca = cfg.id.ca;
        cfg.id.ca = NULL;
    }

    bool write_new_cfg = true;

    if (write_new_cfg) {
        cfg_buf = ziti_config_to_json(&new_cfg, 0, &cfg_len);
        CHECK_UV("update config", update_file(config_file, cfg_buf, cfg_len));
    }
    DONE:
    free_ziti_config(&cfg);
    free_ziti_config(&new_cfg);
    free(cfg_buf);
}

static void update_config_done(uv_work_t *wr, int err) {
    api_update_req *req = wr->data;
    if (req->err != 0) {
        ZITI_LOG(ERROR, "failed to update config file[%s]: %d(%s)", req->identifier, req->err, req->errmsg);
    } else {
        ZITI_LOG(INFO, "updated config file ztx[%s]", req->identifier);
    }
    free(req->config_json);
    free(req->identifier);
    free(req);
}

void update_identity_config(uv_loop_t *l, const char *identifier, const char *cfg_json) {
    if (identifier) {
        api_update_req *req = calloc(1, sizeof(api_update_req));
        req->wr.data = req;
        req->identifier = strdup(identifier);
        req->config_json = strdup(cfg_json);
        uv_queue_work(l, &req->wr, update_config, update_config_done);
    }
}

char* resolve_directory(const char* path) {
    char* resolved_path = (char*)malloc(PATH_MAX);
    if (access(path, F_OK) != -1) {
        //means the file exists right where it is, use realpath and normalize it and continue
        if (realpath(path, resolved_path) == NULL) {
            //how could we get here?
            printf("path does not exist or permission denied: %s\n", resolved_path);
            exit(1);
        }
    } else {
        if (realpath(path, resolved_path) == NULL) {
            //how could we get here?
            printf("path does not exist or permission denied: %s\n", resolved_path);
            exit(1);
        }
    }
    return resolved_path;
}

