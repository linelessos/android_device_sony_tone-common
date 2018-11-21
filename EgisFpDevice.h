#pragma once

class EgisFpDevice {
    static constexpr auto DEV_PATH = "/dev/esfp0";

    static constexpr auto IOC_SENSOR_RESET = 4;
    static constexpr auto IOC_INTERRUPT_TRIGGER_INIT = 0xa4;
    static constexpr auto IOC_INTERRUPT_TRIGGER_CLOSE = 0xa5;

    int mFd = 0;

   public:
    EgisFpDevice();
    ~EgisFpDevice();

    int Reset();
    int EnableInterrupt();
    int DisableInterrupt();
    bool WaitInterrupt(int timeout = -1);
    int GetDescriptor() const;
};
