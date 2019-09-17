/**
 *
 *
 */

#include "ion_buffer.h"

#define LOG_TAG "FPC"
#include <log/log.h>

#define ION_ALIGN 0x1000
#define ION_ALIGN_MASK (ION_ALIGN - 1)

__BEGIN_DECLS

static int open_ion_device() {
    int ion_dev_fd = open("/dev/ion", O_RDONLY);

    LOG_ALWAYS_FATAL_IF(ion_dev_fd < 0, "Failed to open /dev/ion: %s", strerror(errno));

    return ion_dev_fd;
}

int32_t qcom_km_ion_memalloc(struct qcom_km_ion_info_t *handle, size_t size) {
    size_t aligned_size = (size + ION_ALIGN_MASK) & ~ION_ALIGN_MASK;
    int rc = 0;

    int ion_fd = open_ion_device();

    /* Allocate buffer */

    struct ion_allocation_data ion_alloc_data = {
        .len = aligned_size,
        .align = ION_ALIGN,
        .heap_id_mask = ION_HEAP(ION_QSECOM_HEAP_ID),
    };

    rc = ioctl(ion_fd, ION_IOC_ALLOC, &ion_alloc_data);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to allocate ION buffer");

    ion_user_handle_t user_handle = ion_alloc_data.handle;

    /* Map buffer to fd */

    struct ion_fd_data ifd_data = {
        .handle = user_handle,
    };

    rc = ioctl(ion_fd, ION_IOC_MAP, &ifd_data);
    LOG_ALWAYS_FATAL_IF(rc, "Failed to map ION buffer");

    int data_fd = ifd_data.fd;

    /* Map buffer to memory */

    unsigned char *mapped = (unsigned char *)mmap(NULL, aligned_size,
                                                  PROT_READ | PROT_WRITE,
                                                  MAP_SHARED, ifd_data.fd, 0);
    LOG_ALWAYS_FATAL_IF(mapped == MAP_FAILED, "Failed to mmap ION buffer");

    *handle = (struct qcom_km_ion_info_t){
        .ion_fd = ion_fd,
        .ifd_data_fd = data_fd,
        .handle = user_handle,
        .ion_sbuffer = mapped,
        .sbuf_len = aligned_size,
        .req_len = size,
    };

    return 0;
}

int32_t qcom_km_ion_dealloc(struct qcom_km_ion_info_t *handle) {
    int rc = 0;

    if (handle->ion_sbuffer) {
        rc = munmap(handle->ion_sbuffer, handle->sbuf_len);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to munmap ION buffer");
        handle->ion_sbuffer = NULL;
    }

    if (handle->ifd_data_fd >= 0) {
        rc = close(handle->ifd_data_fd);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to close ION buffer");
        handle->ifd_data_fd = -1;
    }

    if (handle->handle) {
        struct ion_handle_data handle_data = {.handle = handle->handle};
        rc = ioctl(handle->ion_fd, ION_IOC_FREE, &handle_data);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to free ION buffer");
        handle->handle = 0;
    }

    if (handle->ion_fd >= 0) {
        rc = close(handle->ion_fd);
        LOG_ALWAYS_FATAL_IF(rc, "Failed to close ION device");
        handle->ion_fd = -1;
    }

    return rc;
}

__END_DECLS
