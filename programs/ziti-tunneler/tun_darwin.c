// original code: https://gist.github.com/wxdao/8a0c83ed6cb2a141d1176499e3f6fc48

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>

/**
 * open a utun device
 * @param num populated with the unit number of the utun device that was opened
 * @return file descriptor to opened utun
 *
 * set up interface address and routes:
 * - ifconfig utun2 169.254.1.2/32 169.254.1.2
 * - route add -host 2.2.2.2 -interface utun2
 * - route add -host 1.2.3.4 -interface utun2
 */
int open_utun(char *tun_name, size_t tun_name_len, char *error, size_t error_len) {
    int fd;
    struct sockaddr_ctl addr;
    struct ctl_info info;

    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to create control socket: %s", strerror(errno));
        }
        return -1;
    }

    memset(&info, 0, sizeof (info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
    if (ioctl(fd, CTLIOCGINFO, &info) == -1) {
        if (error != NULL) {
            snprintf(error, error_len, "ioctl(CTLIOCGINFO) failed: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 1; // utunX where X is sc_unit-1

    do {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            break;
        }
        // TODO debug logger
        printf("connect utun%d failed: %s\n", addr.sc_unit - 1, strerror(errno));
    } while (addr.sc_unit++ < 255);

    if (addr.sc_unit > 255) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open utun device: %s", strerror(errno));
        }
        close(fd);
        return -1;
    }

    if (tun_name != NULL) {
        struct ifreq ifname_req;
        socklen_t ifname_req_size = sizeof(ifname_req);
        if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &ifname_req, &ifname_req_size) == -1) {
            if (error != NULL) {
                snprintf(error, error_len, "failed to get ifname: %s", strerror(errno));
                close(fd);
                return -1;
            }
        }
        strncpy(tun_name, ifname_req.ifr_name, tun_name_len);
    }

    return fd;
}