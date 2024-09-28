#ifndef ZITI_TUNNELER_SDK_LIBIPROUTE_H
#define ZITI_TUNNELER_SDK_LIBIPROUTE_H

typedef struct rtnetlink *rtnetlink;

typedef enum {
  IPRULE_ADD = 1,
  IPRULE_DEL,
} iprule_modify_type;

extern int rtnetlink_new(rtnetlink*);
extern void rtnetlink_free(rtnetlink);

extern int zt_iprule_modify(rtnetlink h, iprule_modify_type cmd, const char *rule, ...);

#endif /* !ZITI_TUNNELER_SDK_LIBIPROUTE_H */
