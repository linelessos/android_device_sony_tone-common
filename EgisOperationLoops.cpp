// TODO: Come up with a much better name!

#if PLATFORM_SDK_VERSION >= 28
#include <bits/epoll_event.h>
#endif
#include <string.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <unistd.h>
#include <algorithm>
#include "EgisOperationLoops.h"
#include "FormatException.hpp"

#define LOG_TAG "FPC ET"
#define LOG_NDEBUG 0
#include <log/log.h>

EgisOperationLoops::EgisOperationLoops(uint64_t deviceId) : mDeviceId(deviceId) {
    event_fd = eventfd((eventfd_t)AsyncState::Idle, EFD_NONBLOCK);
    if (event_fd < 0)
        throw FormatException("Failed to create eventfd: %s", strerror(errno));
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
        throw FormatException("Failed to create epoll: %s", strerror(errno));

    {
        struct epoll_event ev = {
            .data.fd = event_fd,
            .events = EPOLLIN,
        };
        int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &ev);
        if (rc)
            throw FormatException("Failed to add eventfd to epoll: %s", strerror(errno));
    }
    {
        struct epoll_event ev = {
            .data.fd = dev.GetDescriptor(),
            .events = EPOLLIN,
        };
        int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
        if (rc)
            throw FormatException("Failed to add eventfd to epoll: %s", strerror(errno));
    }

    int rc = pthread_create(&thread, NULL, ThreadStart, this);
    if (rc)
        throw FormatException("Failed to start pthread: %d %s", rc, strerror(errno));
}

void *EgisOperationLoops::ThreadStart(void *arg) {
    auto instance = static_cast<EgisOperationLoops *>(arg);
    instance->RunThread();
    return nullptr;
}

void EgisOperationLoops::RunThread() {
    ALOGD("Async thread up");
    for (;;) {
        // NOTE: Not using WaitForEvent() here, because we are not interested
        // in wakeups from the fp device, only in events.
        struct pollfd pfd = {
            .fd = event_fd,
            .events = POLLIN,
        };
        int cnt = poll(&pfd, 1, -1);
        if (cnt <= 0) {
            ALOGW("Infinite poll returned with %d", cnt);
            continue;
        }

        auto nextState = ReadState();
        currentState = nextState;
        switch (nextState) {
            case AsyncState::Idle:
                ALOGW("Unexpected AsyncState %lu", nextState);
                break;
            case AsyncState::Cancel:
                // Nothing in progress - still notify that the current operation was cancelled.
                ALOGW("Unexpected AsyncState::Cancel - nothing in progress");
                NotifyError(FingerprintError::ERROR_CANCELED);
                break;
            case AsyncState::Authenticating:
                // TODO
                break;
            case AsyncState::Enrolling:
                EnrollAsync();
                break;
        }
        currentState = AsyncState::Idle;
    }
}

void EgisOperationLoops::ProcessOpcode(const command_buffer_t &cmd) {
    switch (cmd.step) {
        case Step::NotReady:
            ALOGV("%s: Device not ready, sleeping for %dms", __func__, cmd.timeout);
            usleep(1000 * cmd.timeout);
            break;
        case Step::Error:
            ALOGV("%s: Device error, resetting...", __func__);
            dev.Reset();
            break;
        case Step::WaitFingerprint:
            ALOGE("%s: Expected to wait for finger in non-interactive state!", __func__);
            // Waiting for a finger event (hardware gpio trigger for that matter) should
            // not happen for anything other than enroll and authenticate, where this case
            // is handled explicitly.
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
    ALOGE("Invalid return code %#x", rc);
    return -1;
}

bool EgisOperationLoops::ConvertAndCheckError(int &rc) {
    if ((rc - 0x27 & ~2) == 0 || (rc & ~0x20 /* 0xffffffdf*/) == 0)
        return false;

    rc = ConvertReturnCode(rc);
    return true;
}

EgisOperationLoops::WakeupReason EgisOperationLoops::WaitForEvent(int timeoutSec) {
    dev.EnableInterrupt();
    constexpr auto EVENT_COUNT = 2;
    struct epoll_event events[EVENT_COUNT];
    int cnt = epoll_wait(epoll_fd, events, EVENT_COUNT, 1000 * timeoutSec);
    dev.DisableInterrupt();

    if (cnt < 0) {
        ALOGE("epoll_wait failed: %s", strerror(errno));
        // Let the current operation continue as if nothing happened:
        return WakeupReason::Timeout;
    }

    if (!cnt)
        return WakeupReason::Timeout;

    // Control events have priority over finger events, since
    // this is probably a request to cancel the current operation.
    for (auto ei = 0; ei < cnt; ++ei)
        if (events[ei].data.fd == event_fd && events[ei].events | EPOLLIN) {
            ALOGV("Waking up due to event");
            return WakeupReason::Event;
        }

    for (auto ei = 0; ei < cnt; ++ei)
        if (events[ei].data.fd == dev.GetDescriptor() && events[ei].events | EPOLLIN) {
            ALOGV("Waking up due to finger");
            return WakeupReason::Finger;
        }

    throw FormatException("Invalid fd source!");
}

bool EgisOperationLoops::MoveToState(AsyncState nextState) {
    ALOGD("Attempting to move to state %lu", nextState);
    // TODO: This is racy (eg. does not look at in-flight state),
    // but it does not matter because async operations are not supposed to be
    // invoked concurrently (how can a device run any combination of authenticate or
    // enroll simultaneously??). The thread will simply reject it in that case.

    // Currently, the service that uses this HAL (FingerprintService.java) calls cancel() in
    // such a case, and only starts the next operation upon receiving FingerprintError::ERROR_CANCELED.

    if (nextState != AsyncState::Cancel && currentState != AsyncState::Idle) {
        ALOGW("Thread already in state %lu, refusing to move to %lu", currentState, nextState);
        return false;
    }

    int rc = eventfd_write(event_fd, (eventfd_t)nextState);
    if (rc) {
        ALOGE("Failed to write next state to eventfd: %s", strerror(errno));
        return false;
    }
    return true;
}

EgisOperationLoops::AsyncState EgisOperationLoops::ReadState() {
    eventfd_t requestedState;
    int rc = eventfd_read(event_fd, &requestedState);
    if (rc) {
        // This is very common when no state is available (read returns 0 bytes when the state is 0).
        // ALOGE("Failed to read next state from eventfd: %s", strerror(errno));
        return AsyncState::Idle;
    }
    return static_cast<AsyncState>(requestedState);
}

bool EgisOperationLoops::CheckAndHandleCancel(EGISAPTrustlet::API &lockedBuffer) {
    auto requestedState = static_cast<eventfd_t>(ReadState());
    if (requestedState & ~static_cast<eventfd_t>(AsyncState::Cancel))
        // The call to eventfd_read consumed an (unexpected and incorrect)
        // state change; warn if that happens.
        ALOGW("%s: Ignoring requested state %lu", __func__, requestedState);

    auto cancelled = requestedState & static_cast<eventfd_t>(AsyncState::Cancel);
    ALOGV("%s: %lu", __func__, cancelled);
    if (cancelled)
        RunCancel(lockedBuffer);
    return cancelled;
}

int EgisOperationLoops::RunCancel(EGISAPTrustlet::API &lockedBuffer) {
    ALOGD("Sending cancel command to TZ");
    int rc = 0;
    auto &cmdIn = lockedBuffer.GetRequest().command_buffer;
    const auto &cmdOut = lockedBuffer.GetResponse().command_buffer;
    do {
        cmdIn.step = Step::Cancel;
        rc = SendCancel(lockedBuffer);
        if (rc)
            break;
    } while (cmdOut.step != Step::Done);
    rc = ConvertReturnCode(rc);
    if (rc)
        ALOGE("Failed to cancel, rc = %d", rc);
    else
        NotifyError(FingerprintError::ERROR_CANCELED);
    return rc;
}

void EgisOperationLoops::NotifyError(FingerprintError e) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback)
        mClientCallback->onError(
            mDeviceId,
            std::min(e, FingerprintError::ERROR_VENDOR),
            e >= FingerprintError::ERROR_VENDOR ? (int32_t)e : 0);
}

void EgisOperationLoops::NotifyRemove(uint32_t fid, uint32_t remaining) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback)
        mClientCallback->onRemoved(
            mDeviceId,
            fid,
            mGid,
            remaining);
}

void EgisOperationLoops::NotifyAcquired(FingerprintAcquiredInfo acquiredInfo) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback)
        mClientCallback->onAcquired(mDeviceId,
                                    std::min(acquiredInfo, FingerprintAcquiredInfo::ACQUIRED_VENDOR),
                                    acquiredInfo >= FingerprintAcquiredInfo::ACQUIRED_VENDOR ? (int32_t)acquiredInfo : 0);
}

void EgisOperationLoops::NotifyEnrollResult(uint32_t fid, uint32_t remaining) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    if (mClientCallback)
        mClientCallback->onEnrollResult(mDeviceId, fid, mGid, remaining);
}

void EgisOperationLoops::NotifyBadImage(int reason) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    FingerprintAcquiredInfo acquiredInfo;
    if (reason & 1 << 1)  // 0x80000002
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_TOO_FAST;
    else if (reason & 1 << 0x1b)  // 0x88000000
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_PARTIAL;
    else if (reason & (1 << 3 | 1 << 7))
        // NOTE: 1 << 3 caused by "redundant image"
        // WARNING: Probably different meaning! (first free vendor code)
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_VENDOR;
    else if (reason & 1 << 0x18)  // 0x81000000
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY;
    else  // 0x80000000 usually
        acquiredInfo = FingerprintAcquiredInfo::ACQUIRED_INSUFFICIENT;

    NotifyAcquired(acquiredInfo);
}

// TODO: Check restart cases
void EgisOperationLoops::EnrollAsync() {
    int rc = 0;
    auto lockedBuffer = GetLockedAPI();
    auto &cmdIn = lockedBuffer.GetRequest().command_buffer;
    auto &cmdOut = lockedBuffer.GetResponse().command_buffer;

    // Intial step is 0, already cleared from GetLockedAPI

    // TODO: check_return_code_error, which does some weird
    // and-ops. On false, converts the return code and calls cancel()

    for (bool finished = false; !finished;) {
        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            rc = SendInitEnroll(lockedBuffer, mSecureUserId);
            ALOGD("Enroll: init step, rc = %d, next step = %d", rc, cmdOut.step);
            // TODO: Check return code, recalibrate on convert()==-6

            if (ConvertAndCheckError(rc))
                return NotifyError((FingerprintError)rc);

            ProcessOpcode(cmdOut);
            cmdIn.step = cmdOut.step;
        } while (cmdOut.step != Step::Done);

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            rc = SendEnroll(lockedBuffer);
            ALOGD("Enroll: step, rc = %d, next step = %d", rc, cmdOut.step);
            // TODO: if convert(rc) == -9, restart from init_enroll

            if (ConvertAndCheckError(rc))
                return NotifyError((FingerprintError)rc);

            if (rc == 0x29) {
                ALOGD("Enroll: \"finished\" rc = %d", rc);
                // TODO: Original code does not notify error here!
                return NotifyError((FingerprintError)rc);
            } else if (rc == 0x27) {
                ALOGD("Enroll: bad image %#x, next step = %d", cmdOut.bad_image_reason, cmdOut.step);
                NotifyBadImage(cmdOut.bad_image_reason);
            }

            else if (!rc)
                // TODO: best-guess. Things such as NotifyBadImage were originally called twice, also on FingerAcquired.
                // cmd.step is usually 0 in case rc!=0
                switch (cmdOut.step) {
                    case Step::WaitFingerprint: {
                        auto reason = WaitForEvent();
                        ALOGD("Enroll: wakeup %d", reason);
                        switch (reason) {
                            case WakeupReason::Timeout:
                                NotifyError(FingerprintError::ERROR_TIMEOUT);
                                // Assuming this is some magic state that causes the TZ to clean up,
                                // followed by an exit (assuming the rc == 0x29).
                                // TODO: That can be tested with an explicit timeout!
                                cmdOut.step = Step::ContinueAfterTimeout;
                                break;
                            case WakeupReason::Event:
                                if (CheckAndHandleCancel(lockedBuffer))
                                    return;
                                break;
                            case WakeupReason::Finger:
                                ALOGV("Enroll: Finger encountered");
                                // Continue processing
                                break;
                        }
                        break;
                    }
                    case Step::FingerDetected:
                        // Nothing.
                        break;
                    case Step::FingerAcquired:
                        NotifyAcquired(FingerprintAcquiredInfo::ACQUIRED_GOOD);
                        break;
                    default:
                        // NOTE: Most cases were handled as duplicates here.
                        ProcessOpcode(cmdOut);
                        break;
                }

            cmdIn.step = cmdOut.step;
        } while (cmdOut.step != Step::Done);

        if (cmdOut.enroll_status == 0x64) {
            ALOGI("Enroll: complete in %d steps", cmdOut.enroll_steps_done);
            // It's possible for enrollment to finish before the predicated amount of steps.
            // In that case, make sure cmd.enroll_steps_required - cmd.enroll_steps_done == 0:
            cmdOut.enroll_steps_done = cmdOut.enroll_steps_required;
            finished = true;
        } else
            ALOGI("Enroll: %d steps remaining", cmdOut.enroll_steps_required - cmdOut.enroll_steps_done);

        // Notify that an enrollment step was done:
        if (!rc)
            NotifyEnrollResult(cmdOut.enroll_finger_id, cmdOut.enroll_steps_required - cmdOut.enroll_steps_done);

        do {
            if (CheckAndHandleCancel(lockedBuffer))
                return;
            rc = SendFinalizeEnroll(lockedBuffer);
            ALOGD("Enroll: finalize step, rc = %d, next step = %d", rc, cmdOut.step);

            if (ConvertAndCheckError(rc))
                return NotifyError((FingerprintError)rc);

            ProcessOpcode(cmdOut);
            cmdIn.step = cmdOut.step;
        } while (cmdOut.step != Step::Done);

        ALOGD("Enroll: Finished single step; done? %d", finished);

        // TODO: Update authenticatorId!!
    }
}

void EgisOperationLoops::SetNotify(const sp<IBiometricsFingerprintClientCallback> callback) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    mClientCallback = callback;
}

int EgisOperationLoops::SetUserDataPath(uint32_t gid, const char *path) {
    mGid = gid;
    return EGISAPTrustlet::SetUserDataPath(path);
}

int EgisOperationLoops::RemoveFinger(uint32_t fid) {
    int rc = 0;

    if (fid == 0) {
        // Delete all fingerprints when fid is zero:
        std::vector<uint32_t> fids;
        rc = GetFingerList(fids);
        if (rc)
            return rc;
        auto remaining = fids.size();
        for (auto fid : fids) {
            rc = EGISAPTrustlet::RemoveFinger(fid);
            if (rc)
                break;
            else
                NotifyRemove(fid, --remaining);
        }
    } else {
        rc = EGISAPTrustlet::RemoveFinger(fid);
        if (!rc)
            NotifyRemove(fid, 0);
    }
    return rc;
}

int EgisOperationLoops::Prepare() {
    auto lockedBuffer = GetLockedAPI();
    auto &cmdIn = lockedBuffer.GetRequest().command_buffer;
    const auto &cmdOut = lockedBuffer.GetResponse().command_buffer;
    // Initial Step is 1:
    cmdIn.step = Step::Init;

    // Process step until it is 0 (meaning done):
    for (;;) {
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
    return -1;
}

bool EgisOperationLoops::Cancel() {
    ALOGI("Requesting thread to cancel current operation...");
    // Always let the thread handle cancel requests to prevent concurrency issues.
    return MoveToState(AsyncState::Cancel);
}

int EgisOperationLoops::Enumerate() {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    std::vector<uint32_t> fids;
    int rc = GetFingerList(fids);
    if (rc)
        return rc;
    auto remaining = fids.size();
    ALOGD("Enumerating %zu fingers", remaining);
    if (!remaining)
        // If no fingerprints exist, notify that the enumeration is done with remaining=0.
        // Use fid=0 to indicate that this is not a fingerprint.
        mClientCallback->onEnumerate(mDeviceId, 0, mGid, 0);
    else
        for (auto fid : fids)
            mClientCallback->onEnumerate(mDeviceId, fid, mGid, --remaining);
    return 0;
}

int EgisOperationLoops::Enroll(const hw_auth_token_t &hat, uint32_t timeoutSec) {
    int rc = SetAuthToken(hat);
    if (rc) {
        ALOGE("Failed to set auth token, rc = %d", rc);
        goto error;
    }

    {
        auto api = GetLockedAPI();

        rc = SetSecureUserId(api, hat.user_id);
        if (rc) {
            ALOGE("Failed to set secure user id, rc = %d", rc);
            goto error;
        }
        mSecureUserId = hat.user_id;

        rc = CheckAuthToken(api);
        if (rc) {
            ALOGE("Authtoken check failed, rc = %d", rc);
            goto error;
        }

        if (MoveToState(AsyncState::Enrolling))
            return 0;
    }

error:
    NotifyError(FingerprintError::ERROR_HW_UNAVAILABLE);
    return rc;
}
