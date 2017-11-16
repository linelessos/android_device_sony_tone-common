#ifndef FINGERPRINT_COMMON_H
#define FINGERPRINT_COMMON_H

#include <stdint.h>

#define FPC_IOC_MAGIC	0x1145
#define FPC_IOCWPREPARE	_IOW(FPC_IOC_MAGIC, 0x01, int)
#define FPC_IOCWDEVWAKE _IOW(FPC_IOC_MAGIC, 0x02, int)
#define FPC_IOCWRESET	_IOW(FPC_IOC_MAGIC, 0x03, int)
#define FPC_IOCRPREPARE _IOR(FPC_IOC_MAGIC, 0x81, int)
#define FPC_IOCRDEVWAKE _IOR(FPC_IOC_MAGIC, 0x82, int)
#define FPC_IOCRIRQ	_IOR(FPC_IOC_MAGIC, 0x83, int)

enum {
    FPC_PWROFF = 0,
    FPC_PWRON = 1,
};

typedef int32_t err_t;
err_t fpc_set_power(int poweron);
err_t fpc_get_power(void);
err_t sysfs_write(char *path, char *s);
err_t sys_fs_irq_poll(char *path);

#endif //FINGERPRINT_COMMON_H
