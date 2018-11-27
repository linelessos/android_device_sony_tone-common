#include "common.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#define LOG_TAG "FPC COMMON"

#include <log/log.h>
#include <sys/ioctl.h>

err_t fpc_set_power(int poweron)
{
    int fd, ret = -1;

    fd = open("/dev/fingerprint", O_RDWR);
    if (fd < 0) {
        ALOGE("Error opening FPC device\n");
        return -1;
    }
    ret = ioctl(fd, FPC_IOCWPREPARE, poweron);
    if (ret < 0) {
        ALOGE("Error preparing FPC device\n");
        close(fd);
        return -1;
    }
    close(fd);

    return 1;
}

err_t fpc_get_power(void)
{
    int fd, ret = -1;
    uint32_t reply = -1;

    fd = open("/dev/fingerprint", O_RDWR);
    if (fd < 0) {
        ALOGE("Error opening FPC device\n");
        return -1;
    }
    ret = ioctl(fd, FPC_IOCRPREPARE, &reply);
    if (ret < 0) {
        ALOGE("Error preparing FPC device\n");
        close(fd);
        return -1;
    }
    close(fd);

    if (reply > 1)
        return -1;

    return reply;
}

err_t fpc_poll_irq(void)
{
    int fd, ret = -1;
    uint32_t arg = 0;

    fd = open("/dev/fingerprint", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        ALOGE("Error opening FPC device\n");
        return -1;
    }

    ret = ioctl(fd, FPC_IOCRIRQPOLL, &arg);
    if (ret < 0) {
        ALOGE("Error polling FPC device\n");
        close(fd);
        return -1;
    }
    close(fd);

    ALOGV("Interrupt status: %d\n", arg);

    /* 0 means that the interrupt didn't fire */
    if (arg == 0)
        return -1;

    return (err_t)arg;
}
