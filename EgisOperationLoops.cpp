// TODO: Come up with a much better name!

#include "EgisOperationLoops.h"
#include <unistd.h>

#define LOG_TAG "FPC ET"
#include <log/log.h>

void EgisOperationLoops::ProcessOpcode(const command_buffer_t &cmd) {
    switch (cmd.step) {
        case Step::NotReady:
            usleep(1000 * cmd.timeout);
            break;
        case Step::Error:
            dev.Reset();
            break;
        case Step::WaitFingerprint:
            // TODO: Might never need this, as the two cases
            // (auth | enroll) should wait on the device and event pipe.
            dev.WaitInterrupt();
            break;
        default:
            break;
    }
}

int EgisOperationLoops::ConvertReturnCode(int rc) {
    // TODO: Check if this is still accurate.

    if (rc <= 0)
        return rc;
    if (rc > 0x3d)
        return 0;
    switch (rc) {
        case 0x15:
            return ~0x25;
        case 0x1d:
            return -1;
        case 0x24:
        case 0x25:
        case 0x26:
        case 0x28:
            return ~0x6;  // -5
        case 0x30:
            return ~0x5;  // -6: recalibrate
    }
    ALOGE("Invalid return code %x", rc);
    return -1;
}

int EgisOperationLoops::Prepare() {
    auto lockedBuffer = GetLockedAPI();
    auto &cmdIn = lockedBuffer.GetRequest().command_buffer;
    const auto &cmdOut = lockedBuffer.GetResponse().command_buffer;
    // Initial Step is 1:
    cmdIn.step = Step::Init;

    // Process step until it is 0 (meaning done):
    while (1 /*TODO: not cancelled*/) {
        int rc = SendPrepare(lockedBuffer);
        rc = ConvertReturnCode(rc);
        ALOGD("Prepare rc = %d, next step = %d", rc, cmdOut.step);
        if (rc) return rc;

        ProcessOpcode(cmdOut);

        if (cmdOut.step == Step::Done)
            // Preparation complete
            return 0;

        cmdIn.step = cmdOut.step;
    }
}
