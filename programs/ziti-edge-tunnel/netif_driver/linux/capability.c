#include "capability.h"

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <linux/capability.h>
#include <sysexits.h>

#include <ziti/ziti_log.h>

#ifndef _LINUX_CAPABILITY_VERSION_1
#  define _LINUX_CAPABILITY_VERSION_1  0x19980330
#endif

#ifndef _LINUX_CAPABILITY_U32S_1
#  define _LINUX_CAPABILITY_U32S_1      1
#endif

#ifndef _LINUX_CAPABILITY_VERSION_3
#  define _LINUX_CAPABILITY_VERSION_3   0x20080522
#endif

#ifndef _LINUX_CAPABILITY_U32S_3
#  define _LINUX_CAPABILITY_U32S_3      2
#endif

/* declarations not provided */
extern int capget(cap_user_header_t cap_header, cap_user_data_t cap_data);
extern int capset(cap_user_header_t cap_header, const cap_user_data_t cap_data);

#ifndef ZITI_TUNNELER_SDK_HAVE_CAPGET
/**
 * not all libc's provide wrappers
 */

#include <unistd.h>
#include <sys/syscall.h>

int
capget(cap_user_header_t header, cap_user_data_t data)
{
    return (int) syscall(SYS_capget, header, data);
}

int
capset(cap_user_header_t header, const cap_user_data_t data)
{
    return (int) syscall(SYS_capset, header, data);
}

#endif /* ZITI_TUNNELER_SDK_HAVE_CAPGET */

struct cap_struct {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3 > _LINUX_CAPABILITY_U32S_1 ? _LINUX_CAPABILITY_U32S_3 : _LINUX_CAPABILITY_U32S_1];
};

static __thread struct {
    struct cap_struct saved_cap;
    bool armed;
} thread_state = {
  .saved_cap.header = { _LINUX_CAPABILITY_VERSION_3 },
};

static int
ziti__cap_assert(unsigned long linux_cap_mask, unsigned long flags)
{
    struct cap_struct cap = { .header = thread_state.saved_cap.header };
    struct cap_struct saved_cap;
    int sys_rc;

    (void) flags;

    sys_rc = capget(&cap.header, cap.data);
    /**
     * Fallback to _LINUX_CAPABILITY_VERSION_1 when signalled
     */
    if (sys_rc && errno == EINVAL && cap.header.version < thread_state.saved_cap.header.version) {
        cap.header.version = _LINUX_CAPABILITY_VERSION_1;
        sys_rc = capget(&cap.header, cap.data);
    }

    if (sys_rc < 0) {
        int saved_errno = errno;

        ZITI_LOG(ERROR, "failed to get thread's capabilities: (%d) %s",
            -saved_errno, strerror(saved_errno));
        return -saved_errno;
    }

    saved_cap = cap;

    cap.data[0].effective |= linux_cap_mask;
    cap.data[0].permitted |= linux_cap_mask;

    /**
     * Don't calling capset() if no new capabilities are needed.
     */
    if ((cap.data[0].effective ^ saved_cap.data[0].effective) == 0
        && (cap.data[0].permitted ^ saved_cap.data[0].permitted) == 0)
        goto out;

    sys_rc = capset(&cap.header, cap.data);
    if (sys_rc < 0) {
        int saved_errno = errno;

        ZITI_LOG(ERROR, "failed to raise thread's capabilities: (%d) %s",
            -saved_errno, strerror(saved_errno));
        return -saved_errno;
    }

    if (!thread_state.armed)
        thread_state.saved_cap = saved_cap;

    thread_state.armed = true;

out:
    return 0;
}

static int
ziti__cap_restore(void)
{
    int sys_rc;

    if (!thread_state.armed) {
        sys_rc = capget(&thread_state.saved_cap.header, thread_state.saved_cap.data);
        if (sys_rc < 0) {
            int saved_errno = errno;

            ZITI_LOG(ERROR, "failed to restore thread's capabilities: (%d) %s",
                -saved_errno, strerror(saved_errno));
            return -saved_errno;
        }
        thread_state.armed = false;
    }

    return 0;
}

#define ZITI__LINUX_CAP_VALID(capability)                              \
  static_assert(CAP_TO_INDEX(capability)==0, "capability ordinal is too large for the available bit set.")

ZITI__LINUX_CAP_VALID(CAP_NET_ADMIN);
ZITI__LINUX_CAP_VALID(CAP_SYS_ADMIN);

void
ziti_cap_assert(unsigned long cap_mask)
{
    unsigned long linux_cap_mask =
      ((cap_mask & ZITI_CAP_NETADMIN) ? CAP_TO_MASK(CAP_NET_ADMIN) : 0)
      | ((cap_mask & ZITI_CAP_SYSADMIN) ? CAP_TO_MASK(CAP_SYS_ADMIN) : 0);
    int saved_errno = errno;

    if (ziti__cap_assert(linux_cap_mask, 0) < 0)
        exit(EX_NOPERM);

    errno = saved_errno;
}

void
ziti_cap_restore(void)
{
    int saved_errno = errno;
    int sys_rc;

    sys_rc = ziti__cap_restore();
    if (sys_rc < 0)
        exit(EX_NOPERM);

    errno = saved_errno;
}
