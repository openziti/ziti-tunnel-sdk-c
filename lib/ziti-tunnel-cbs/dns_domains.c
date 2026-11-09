/*
 Copyright NetFoundry Inc.

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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ziti/ziti_dns.h>
#include <ziti/ziti_log.h>

// shortest parent domain that names are merged into, e.g. "example.com"
#define MIN_MERGE_LABELS 2

struct domain_group {
    const char *parent; // owned by the groups map
    size_t count;
};

static int cmp_names(const void *a, const void *b) {
    return strcmp(*(char *const *) a, *(char *const *) b);
}

// largest groups first, then by name so the result does not depend on hash order
static int cmp_groups(const void *a, const void *b) {
    const struct domain_group *ga = a, *gb = b;
    if (ga->count != gb->count) {
        return ga->count > gb->count ? -1 : 1;
    }
    return strcmp(ga->parent, gb->parent);
}

static int label_count(const char *name) {
    int n = 1;
    for (const char *p = name; *p; p++) {
        if (*p == '.') n++;
    }
    return n;
}

// the parent of name (which has `labels` labels) that has `depth` labels. points into name
static const char *parent_at(const char *name, int labels, int depth) {
    const char *p = name;
    for (int i = depth; i < labels; i++) {
        p = strchr(p, '.') + 1;
    }
    return p;
}

// true if name equals or is below one of the reserved domains
static bool is_reserved(const model_map *reserved, const char *name) {
    for (const char *p = name; p != NULL; p = strchr(p, '.') ? strchr(p, '.') + 1 : NULL) {
        if (model_map_get((model_map *) reserved, p) != NULL) {
            return true;
        }
    }
    return false;
}

// drop names below another name in the list: a routing domain already covers all of its subdomains
static size_t drop_covered(char **domains, size_t count) {
    // on allocation failure, names are kept: merging still works, it just merges more than needed
    model_map all = {0};
    for (size_t i = 0; i < count; i++) {
        model_map_set(&all, domains[i], (void *) 1);
    }

    size_t kept = 0;
    for (size_t i = 0; i < count; i++) {
        bool covered = false;
        for (const char *p = strchr(domains[i], '.'); p != NULL && !covered; p = strchr(p + 1, '.')) {
            covered = model_map_get(&all, p + 1) != NULL;
        }
        if (covered) {
            free(domains[i]);
        } else {
            domains[kept++] = domains[i];
        }
    }
    model_map_clear(&all, NULL);
    return kept;
}

// merge groups of names below a common parent with `depth` labels, largest groups first,
// until at most `limit` names are left or no group is left at this depth
static size_t merge_at_depth(char **domains, size_t count, size_t limit, int depth, const model_map *reserved) {
    model_map groups = {0};
    for (size_t i = 0; i < count; i++) {
        int labels = label_count(domains[i]);
        if (labels < depth) continue;
        const char *parent = parent_at(domains[i], labels, depth);
        if (is_reserved(reserved, parent)) continue;
        uintptr_t n = (uintptr_t) model_map_get(&groups, parent);
        model_map_set(&groups, parent, (void *) (n + 1));
    }

    size_t num_groups = 0;
    struct domain_group *candidates = calloc(model_map_size(&groups) + 1, sizeof(struct domain_group));
    if (candidates == NULL) {
        model_map_clear(&groups, NULL);
        return count;
    }
    const char *parent;
    const void *n;
    MODEL_MAP_FOREACH(parent, n, &groups) {
        if ((uintptr_t) n > 1) {
            candidates[num_groups].parent = parent;
            candidates[num_groups].count = (uintptr_t) n;
            num_groups++;
        }
    }
    qsort(candidates, num_groups, sizeof(struct domain_group), cmp_groups);

    // merging a group of k names saves k - 1 entries
    model_map merged = {0};
    size_t remaining = count;
    for (size_t i = 0; i < num_groups && remaining > limit; i++) {
        model_map_set(&merged, candidates[i].parent, (void *) 1);
        remaining -= candidates[i].count - 1;
    }
    free(candidates);

    size_t kept = count;
    if (model_map_size(&merged) > 0) {
        kept = 0;
        for (size_t i = 0; i < count; i++) {
            int labels = label_count(domains[i]);
            const char *p = labels >= depth ? parent_at(domains[i], labels, depth) : NULL;
            uintptr_t state = p ? (uintptr_t) model_map_get(&merged, p) : 0;
            if (state == 0) {
                domains[kept++] = domains[i];
            } else if (state == 1) {
                // first name of the group is replaced by the parent, the others are dropped
                char *merged_name = strdup(p);
                if (merged_name == NULL) {
                    // keep this name; the next name of the group tries again
                    domains[kept++] = domains[i];
                    continue;
                }
                model_map_set(&merged, p, (void *) 2);
                free(domains[i]);
                domains[kept++] = merged_name;
            } else {
                free(domains[i]);
            }
        }
    }

    model_map_clear(&merged, NULL);
    model_map_clear(&groups, NULL);
    return kept;
}

size_t ziti_dns_compact_domains(char **domains, size_t limit, const char *const *reserved) {
    size_t count = 0;
    while (domains[count] != NULL) count++;
    if (count <= limit) {
        return count;
    }

    size_t original = count;
    count = drop_covered(domains, count);

    model_map reserved_set = {0};
    for (const char *const *r = reserved; r && *r; r++) {
        if (**r != '\0' && strcmp(*r, ".") != 0) {
            model_map_set(&reserved_set, *r, (void *) 1);
        }
    }

    int max_labels = 0;
    for (size_t i = 0; i < count; i++) {
        int labels = label_count(domains[i]);
        if (labels > max_labels) max_labels = labels;
    }

    for (int depth = max_labels - 1; depth >= MIN_MERGE_LABELS && count > limit; depth--) {
        count = merge_at_depth(domains, count, limit, depth, &reserved_set);
    }
    model_map_clear(&reserved_set, NULL);

    domains[count] = NULL;
    qsort(domains, count, sizeof(char *), cmp_names);
    ZITI_LOG(INFO, "compacted %zu DNS names to %zu routing domains (limit %zu)", original, count, limit);
    return count;
}
