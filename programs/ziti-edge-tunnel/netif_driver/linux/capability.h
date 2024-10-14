#ifndef ZITI_TUNNELER_SDK_NETIF_LINUX_CAPABILITY_H
#define ZITI_TUNNELER_SDK_NETIF_LINUX_CAPABILITY_H

// mask
enum {
  ZITI_CAP_NETADMIN = 1UL << 0,
  ZITI_CAP_SYSADMIN = 1UL << 1,
};

extern void ziti_cap_assert(unsigned long capabilities);
extern void ziti_cap_restore(void);

#endif /* ZITI_INCLUDED_NETIF_LINUX_CAPABILITY_H */
