
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

extern int open_utun(char *tun_name, size_t tun_name_len, char *error, size_t error_len);

int main(int argc, char *argv[]) {
    char error[256];
    char tun_name[16];
    int tun_fd = open_utun((char *) &tun_name, sizeof(tun_name), error, sizeof(error));
    if (tun_fd < 0) {
        printf("error opening tun: %s\n", error);
        return 1;
    }
    printf("opened %s\n", tun_name);

    char buf[4096];
    int nr;
    while ((nr = read(tun_fd, buf, sizeof(buf))) >= 0) {
        printf("read %d bytes\n", nr);
    }
    printf("error reading %s: %s\n", tun_name, strerror(errno));
    close(tun_fd);
    return 0;
}