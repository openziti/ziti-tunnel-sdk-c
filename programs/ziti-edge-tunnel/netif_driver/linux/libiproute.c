#include <linux/rtnetlink.h>
#define _GNU_SOURCE
#include "libiproute.h"


#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/fib_rules.h>

#include <ziti/ziti_model.h>
#include <ziti/ziti_log.h>

#ifndef NLMSG_BUFSIZE
#  define NLMSG_BUFSIZ  8192UL
#endif

struct nlmsg_batch {
  union {
    uint8_t buf[NLMSG_BUFSIZ];
    struct nlmsghdr nlh;
  };
  ptrdiff_t pos; // current iterator position
  ptrdiff_t len; // end of data
  bool trunc;    // overflowed or truncated
};

#define NLMSG_BATCH_NLMSGHDR(batch, off) ((struct nlmsghdr *)&((batch)->buf[NLMSG_ALIGN(off)]))

#define NLMSG_BATCH_ITER(batch)   NLMSG_BATCH_NLMSGHDR((batch),(batch)->pos)

#define NLMSG_BATCH_TAIL(batch)   NLMSG_BATCH_NLMSGHDR((batch),(batch)->len)

struct rtnetlink {
    int sd;
    uint32_t port;
    uint32_t seqno;

    union {
      struct nlmsg_batch req;
      struct nlmsg_batch reply;
    };
};

static const char whitespace[] = " \t\n\r";
static const int timeout = 5; // seconds

static inline bool
streq(const char s1[static 1],const char s2[static 1])
{
  return strcmp(s1, s2) == 0;
}

static inline bool
startswith(const char prefix[restrict static 1], const char string[restrict static 1])
{
    size_t len = strlen(prefix);
    return strncmp(string, prefix, len + !len) == 0;
}

static void
nlmsg_batch_reset(struct nlmsg_batch *msg, size_t size)
{
    bool overflow = size > NLMSG_BUFSIZ;

    msg->pos = 0;
    msg->len = overflow ? NLMSG_BUFSIZ : size;
    msg->trunc = overflow;
}

static uint8_t *
nlmsg_batch_buf(struct nlmsg_batch *msg)
{
    return msg->buf;
}

static ptrdiff_t
nlmsg_batch_bufsize(const struct nlmsg_batch *msg)
{
    (void) msg;
    return NLMSG_BUFSIZ;
}

static ptrdiff_t
nlmsg_batch_length(const struct nlmsg_batch *msg)
{
    return msg->len;
}

static ptrdiff_t
nlmsg_batch_room(const struct nlmsg_batch *msg)
{
    return NLMSG_BUFSIZ - NLMSG_ALIGN(msg->len);
}

// iterator
static struct nlmsghdr *
nlmsg_batch_first(struct nlmsg_batch *batch)
{
    return &batch->nlh;
}

static bool
nlmsg_batch_ok(struct nlmsg_batch *msg)
{
    struct nlmsghdr *nlh = NLMSG_BATCH_ITER(msg);
    ptrdiff_t remain = msg->len - msg->pos;

    return NLMSG_OK(nlh, remain);
}

static struct nlmsghdr *
nlmsg_batch_next(struct nlmsg_batch *msg)
{
  struct nlmsghdr *nlh = NLMSG_BATCH_ITER(msg);

  msg->pos += NLMSG_ALIGN(nlh->nlmsg_len);
  return NLMSG_BATCH_ITER(msg);
}

static bool
nlmsg_batch_trunc(struct nlmsg_batch *msg)
{
    return msg->trunc;
}

static bool
nlmsg_batch_more(struct nlmsg_batch *msg)
{
    return msg->pos != msg->len;
}

// construction
static struct nlmsghdr *
nlmsg_batch_put(struct nlmsg_batch *msg, int paylen)
{
    if (!msg->trunc && NLMSG_SPACE(paylen) <= nlmsg_batch_room(msg))
        return NLMSG_BATCH_TAIL(msg);
    return NULL;
}

static bool
nlmsg_batch_push(struct nlmsg_batch *msg)
{
    struct nlmsghdr *nlh = NLMSG_BATCH_TAIL(msg);
    bool ok = NLMSG_OK(nlh, nlmsg_batch_room(msg));

    if (ok)
        msg->len = NLMSG_ALIGN(msg->len) + nlh->nlmsg_len;
    else
        msg->trunc = true;

    return ok;
}

static int
netlink_socket(struct rtnetlink *h, int proto)
{
    int sd;

    sd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, proto);
    if (sd < 0)
        return -errno;

    int rcvbuf = 2*NLMSG_BUFSIZ;
    if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf) < 0) {
        int saved_errno = errno;

        ZITI_LOG(INFO, "Failed to configure SO_RCVBUF on socket: %d/%s",
            saved_errno, strerror(saved_errno));
    }

    int sndbuf = 2*NLMSG_BUFSIZ;
    if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf) < 0) {
        int saved_errno = errno;

        ZITI_LOG(INFO, "Failed to configure SO_SNDBUF on socket: %d/%s",
            saved_errno, strerror(saved_errno));
    }

    struct timeval timeo = { .tv_sec = timeout };
    if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof timeo) < 0) {
        int saved_errno = errno;

        ZITI_LOG(INFO, "Failed to configure SO_RCVTIMEO on socket: %d/%s",
            saved_errno, strerror(saved_errno));
    }

    int cap_ack = 1;
    if (setsockopt(sd, SOL_NETLINK, NETLINK_CAP_ACK, &cap_ack, sizeof cap_ack) < 0) {
        int saved_errno = errno;

        ZITI_LOG(INFO, "Failed to set NETLINK_CAP_ACK on socket: %d/%s",
            saved_errno, strerror(saved_errno));
    }

#ifdef NETLINK_GET_STRICT_CHK
    int strict_chk = 1;
    if (setsockopt(sd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &strict_chk, sizeof strict_chk) < 0) {
        int saved_errno = errno;

        ZITI_LOG(INFO, "Failed to set NETLINK_GET_STRICK_CHK on socket: %d/%s",
            saved_errno, strerror(saved_errno));
    }
#endif

    struct sockaddr_nl nl_sa = { .nl_family = AF_NETLINK };
    if (bind(sd, (struct sockaddr *) &nl_sa, sizeof nl_sa) < 0) {
close_and_exit:;
        int saved_errno = errno;
        return (void) close(sd), -saved_errno;
    }

    socklen_t nl_salen = sizeof nl_sa;
    if (getsockname(sd, (struct sockaddr *)&nl_sa, &nl_salen) < 0) {
        goto close_and_exit;
    }

    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) < 0) {
        goto close_and_exit;
    }

    h->sd = sd;
    h->port = nl_sa.nl_pid;
    h->seqno = t.tv_nsec;

    return 0;
}

static char *
next_token(char **ps)
{
    char *s, *r;

    if (!ps)
        return NULL;

    s = *ps;

    // trim leading whitespace
    s += strspn(s, whitespace);
    // find end of token
    r = s + strcspn(s, whitespace);
    // store starting place
    *ps = r + !!*r;
    // terminate token
    *r = '\0';

    return *s ? s : NULL;
}

static int
get_u32(const char *s, uint32_t *pu32)
{
    // skip leading whitespace
    s += strspn(s, whitespace);

    // save sign
    int minus = s[0] == '-';
    s += (minus || s[0] == '+' );

    // decode base
    int base = 10;
    if (s[0] == '0' && s[1]) {
        switch(s[1]) {
        case 'B': case 'b':
            base = 2;
            s += 2;
            break;
        case 'O': case 'o':
            base = 8;
            s += 2;
            break;
        case 'X': case 'x':
            base = 16;
            s += 2;
            break;
        default:
            base = 8;
            s += 1;
        }
    }

    errno = 0;
    char *ep;
    unsigned long ul = strtoul(s, &ep, base);

    if (ul == 0 && errno != 0)
        return -errno;

    if (s == ep)
        return -EINVAL;

    if (!(ul <= UINT32_MAX))
        return -ERANGE;

    *pu32 = minus ? -ul : ul;

    return 0;
}

void
rtnetlink_free(rtnetlink h)
{
    if (h) {
        if (h->sd > -1)
            (void) close(h->sd);
        free(h);
    }
}

int
rtnetlink_new(rtnetlink *ph)
{
    struct rtnetlink *h;
    int err;

    h = calloc(1, sizeof(*h));
    if (!h)
        return -ENOMEM;

    *h = (struct rtnetlink) { .sd = -1 };

    if ((err = netlink_socket(h, NETLINK_ROUTE)) < 0)
        goto error;

    *ph = h;

    return 0;

error:
    free(h);
    *ph = NULL;
    return err;
}

static int
rtattr_put(struct nlmsghdr *nlh, size_t maxsize, int type, const void *restrict data, int dlen)
{
    struct rtattr *rta;
    int alen = RTA_LENGTH(dlen);

    if (NLMSG_ALIGN(nlh->nlmsg_len) > maxsize || RTA_ALIGN(alen) > maxsize - NLMSG_ALIGN(nlh->nlmsg_len)) {
        ZITI_LOG(ERROR, "netlink message length will exceeds bounds (%zu)", maxsize);
        return -ENOMEM;
    }

    rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = alen;
    if (data) {
        memcpy(RTA_DATA(rta), data, dlen);
    } else {
        // memcpy should never have a null parameter
    }
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(alen);
    return 0;
}

static int
rtattr_put32(struct nlmsghdr *nlh, int maxsize, int type, uint32_t u32)
{
  return rtattr_put(nlh, maxsize, type, &u32, sizeof u32);
}

static int
get_error(const struct nlmsghdr *restrict nlh)
{
    const struct nlmsgerr *restrict nle;

    if (nlh->nlmsg_type != NLMSG_ERROR)
        return -ENOMSG;

    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof *nle))
        return -EBADMSG;

    nle = NLMSG_DATA(nlh);

    return nle->error;
}

static int
netlink_call(struct rtnetlink *h)
{
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    uint32_t seqno = h->seqno;
    unsigned int ntx = 0;
    ssize_t sysrc;

    for (struct nlmsghdr *nlh = nlmsg_batch_first(&h->req); nlmsg_batch_ok(&h->req); nlh = nlmsg_batch_next(&h->req)) {

        if ((nlh->nlmsg_flags & NLM_F_REQUEST) != NLM_F_REQUEST) {
            // debug
        }

        nlh->nlmsg_flags |= NLM_F_ACK;

        nlh->nlmsg_seq = seqno + ntx;

        ++ntx;
    }

    h->seqno += ntx;

    do {
        sysrc = sendto(h->sd, nlmsg_batch_buf(&h->req), nlmsg_batch_length(&h->req),
            0, (struct sockaddr *)&sa, sizeof(sa));
    } while (sysrc < 0 && errno == EINTR);

    if (sysrc < 0)
        return errno == ENOBUFS ? -EAGAIN : -errno;

    unsigned int nrx = 0;
    while(true) {
        socklen_t salen = sizeof(sa);
        do {
            sysrc = recvfrom(h->sd, nlmsg_batch_buf(&h->reply), nlmsg_batch_bufsize(&h->reply),
                MSG_TRUNC, (struct sockaddr *)&sa, &salen);
        } while (sysrc < 0 && errno == EINTR);

        if (sysrc < 0)
            return errno == EAGAIN ? -ETIMEDOUT : -errno;

        nlmsg_batch_reset(&h->reply, (size_t) sysrc);

        if (salen != sizeof sa || sa.nl_family != AF_NETLINK) {
            // debug
            return -ENOPROTOOPT;
        }

        if (sa.nl_pid != 0U) {
            // warn
            continue;
        }

        if (sa.nl_groups != 0U) {
            // warn
            continue;
        }

        int err = 0;
        for (struct nlmsghdr *nlh = nlmsg_batch_first(&h->reply); nlmsg_batch_ok(&h->reply); nlh = nlmsg_batch_next(&h->reply)) {

            if (nlh->nlmsg_pid != h->port) {
                // warn
                continue;
            }

            // seqno may wrap
            if (nlh->nlmsg_seq - seqno >= ntx) {
                // warn
                continue;
            }

            if (nlh->nlmsg_type != NLMSG_ERROR)
                continue;

            nrx++;

            // record first error
            if (!err)
                err = get_error(nlh);
        }

        // if all expected messages are received, return error
        if (ntx == nrx)
            return err;

        if (nlmsg_batch_trunc(&h->reply)) {
            // warn
            return -ENOMEM;
        }

        if (nlmsg_batch_more(&h->reply)) {
            // warn
            return -EBADMSG;
        }

        // receive the next batch of messages
    }
}


static int
iprule_modify(rtnetlink h, iprule_modify_type cmd, char rule[static 1])
{
    struct nlmsghdr *nlh;
    struct fib_rule_hdr *frh;
    char *s, *t;
    int maxsize;
    int ret;

    nlmsg_batch_reset(&h->req, 0);

    if (!(nlh = nlmsg_batch_put(&h->req, sizeof *frh)))
        return -ENOMEM;

    maxsize = nlmsg_batch_room(&h->req);

    *nlh = (struct nlmsghdr) {
        .nlmsg_len = NLMSG_LENGTH(sizeof(*frh)),
        .nlmsg_flags = NLM_F_REQUEST,
    };

    frh = NLMSG_DATA(nlh);
    *frh = (struct fib_rule_hdr) {
        .family = AF_UNSPEC,
        .action = FR_ACT_UNSPEC,
    };

    switch (cmd) {
    case IPRULE_ADD:
        nlh->nlmsg_type = RTM_NEWRULE;
        nlh->nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
        frh->action = FR_ACT_TO_TBL;
        break;
    case IPRULE_DEL:
        nlh->nlmsg_type = RTM_DELRULE;
        break;
    default:
        return -EINVAL;
    }

    s = rule;

    while ((t = next_token(&s))) {

        if (streq(t, "not")) {
            frh->flags |= FIB_RULE_INVERT;
        } else if (streq(t, "from")
            || streq(t, "to")) {
            int is_src = t[0] == 'f';

            if ((t = next_token(&s)) == 0)
                goto invalid_argument;

            ziti_address prefix = { 0 };
            if (parse_ziti_address_str(&prefix, t) < 0)
                goto invalid_argument;

            if (prefix.type != ziti_address_cidr)
                goto invalid_argument;

            frh->family = prefix.addr.cidr.af;

            int type;
            if (is_src) {
                frh->src_len = prefix.addr.cidr.bits;
                type = FRA_SRC;
            } else {
                frh->dst_len = prefix.addr.cidr.bits;
                type = FRA_DST;
            }

            size_t iplen = prefix.addr.cidr.af == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
            if (prefix.addr.cidr.bits > 0
                && (ret = rtattr_put(nlh, maxsize, type, &prefix.addr.cidr.ip, iplen)) < 0)
                goto done;
        } else if (streq(t, "fwmark")) {
            char *slash;
            uint32_t fwmark, fwmask;

            if ((t = next_token(&s)) == 0)
                goto invalid_argument;

            if ((slash = strchr(t, '/')))
                *slash = '\0';

            if (get_u32(t, &fwmark) < 0)
                goto invalid_argument;

            if ((ret = rtattr_put32(nlh, maxsize, FRA_FWMARK, fwmark)) < 0)
                goto done;

            if (slash) {
                if (get_u32(slash+1, &fwmask) < 0)
                    goto invalid_argument;

                if ((ret = rtattr_put32(nlh, maxsize, FRA_FWMASK, fwmark)) < 0)
                    goto done;
            }
        } else if (startswith(t, "preference")
                   || startswith(t, "priority")) {
            uint32_t pref;

            if ((t = next_token(&s)) == 0)
                goto invalid_argument;

            if (get_u32(t, &pref) < 0)
                goto invalid_argument;

            if ((ret = rtattr_put32(nlh, maxsize, FRA_PRIORITY, pref)) < 0)
                goto done;

        } else if (startswith(t, "table")
                    || startswith(t, "lookup")) {
            uint32_t tid;

            if ((t = next_token(&s)) == 0)
                goto invalid_argument;

            if (get_u32(t, &tid) < 0)
                goto invalid_argument;

            frh->action = FR_ACT_TO_TBL;

            if (tid > 255) {
                frh->table = RT_TABLE_UNSPEC;
                if ((ret = rtattr_put32(nlh, maxsize, FRA_TABLE, tid)) < 0)
                    goto done;
            } else {
                frh->table = tid;
            }
        } else {
invalid_argument:
             return -EINVAL;
        }
    }

    nlmsg_batch_push(&h->req);

    ret = netlink_call(h);
done:
    return ret;
}

int
zt_iprule_modify(rtnetlink h, iprule_modify_type cmd, const char *rule, ...)
{
    va_list ap;
    char *str;
    int ret;

    va_start(ap, rule);
    ret = vasprintf(&str, rule, ap);
    va_end(ap);

    if (ret < 0)
        return -ENOMEM;

    ret = iprule_modify(h, cmd, str);

    free(str);

    return ret;
}
