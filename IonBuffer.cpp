#include "IonBuffer.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/msm_ion.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>

#define LOG_TAG "FPC"
#include <log/log.h>

int IonBuffer::ion_dev_fd = -1;

int IonBuffer::IonDev() {
    if (ion_dev_fd >= 0)
        return ion_dev_fd;

    ion_dev_fd = open("/dev/ion", O_RDONLY);
    LOG_ALWAYS_FATAL_IF(ion_dev_fd < 0, "Failed to open /dev/ion: %s", strerror(errno));

    return ion_dev_fd;
}

IonBuffer::IonBuffer(size_t sz) : mRequestedSize(sz), mSize((sz + ION_ALIGN_MASK) & ~ION_ALIGN_MASK) {
    int rc = 0;

    int ion_fd = IonDev();

    /* Allocate buffer */

    struct ion_allocation_data ion_alloc_data = {
        .len = mSize,
        .align = ION_ALIGN,
        .heap_id_mask = ION_HEAP(ION_QSECOM_HEAP_ID),
    };

    rc = ioctl(ion_fd, ION_IOC_ALLOC, &ion_alloc_data);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to allocate ION buffer");

    mHandle = ion_alloc_data.handle;

    /* Map buffer to fd */

    struct ion_fd_data ifd_data = {
        .handle = mHandle,
    };

    rc = ioctl(ion_fd, ION_IOC_MAP, &ifd_data);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to map ION buffer");

    mFd = ifd_data.fd;

    mMapped = (unsigned char *)mmap(NULL, mSize,
                                    PROT_READ | PROT_WRITE,
                                    MAP_SHARED, ifd_data.fd, 0);
    LOG_ALWAYS_FATAL_IF(mMapped == MAP_FAILED, "Failed to mmap ION buffer");
}

IonBuffer::~IonBuffer() {
    int rc = 0;

    if (mMapped) {
        rc = munmap(mMapped, mSize);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to munmap ION buffer");
        mMapped = nullptr;
    }

    if (mFd >= 0) {
        rc = close(mFd);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to close ION buffer");
        mFd = -1;
    }

    if (mHandle) {
        struct ion_handle_data handle_data = {.handle = mHandle};
        rc = ioctl(IonDev(), ION_IOC_FREE, &handle_data);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to free ION buffer");
        mHandle = 0;
    }

    mSize = -1;
}

IonBuffer::IonBuffer(IonBuffer &&other) {
    std::swap(mSize, other.mSize);
    std::swap(mFd, other.mFd);
    std::swap(mHandle, other.mHandle);
    std::swap(mMapped, other.mMapped);
}

IonBuffer &IonBuffer::operator=(IonBuffer &&other) {
    // Invoke move constructor:
    return *new (this) IonBuffer(std::move(other));
}

size_t IonBuffer::size() const {
    return mSize;
}

size_t IonBuffer::requestedSize() const {
    return mRequestedSize;
}

int IonBuffer::fd() const {
    return mFd;
}

void *IonBuffer::operator()() {
    return mMapped;
}

const void *IonBuffer::operator()() const {
    return mMapped;
}
