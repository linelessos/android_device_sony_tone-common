#include "EgisFpDevice.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include "FormatException.hpp"

struct ioctl_cmd {
    int interurpt_mode;
    int detect_period;
    int detect_threshold;
};

EgisFpDevice::EgisFpDevice() {
    mFd = open(DEV_PATH, O_RDWR);

    if (mFd < 0)
        throw FormatException("Failed to open fingerprint device! fd=%d, strerror=%s", mFd, strerror(errno));
}

EgisFpDevice::~EgisFpDevice() {
    if (mFd)
        close(mFd);
    mFd = 0;
}

int EgisFpDevice::Reset() const {
    return ioctl(mFd, ET51X_IOCWRESET);
}

int EgisFpDevice::Enable() const {
    return ioctl(mFd, ET51X_IOCWPREPARE, 1);
}

int EgisFpDevice::Disable() const {
    return ioctl(mFd, ET51X_IOCWPREPARE, 0);
}

/**
 * Returns true when a POLLIN event was triggered
 * (meaning something happened on the fp device).
 */
bool EgisFpDevice::WaitInterrupt(int timeout) const {
    struct pollfd pfd = {.fd = mFd, .events = POLLIN};
    int rc = poll(&pfd, 1, timeout);
    if (rc == -1)
        throw FormatException("Poll error");
    return rc && pfd.revents & POLLIN;
}

int EgisFpDevice::GetDescriptor() const {
    return mFd;
}
