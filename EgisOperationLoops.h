#pragma once

#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprintClientCallback.h>
#include <sys/eventfd.h>
#include <mutex>
#include "EGISAPTrustlet.h"
#include "EgisFpDevice.h"

using ::android::sp;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using ::android::hardware::biometrics::fingerprint::V2_1::FingerprintError;
using ::android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;

/**
 * External wrapper class containing TZ communication logic
 * (Separated from datastructural/architectural choices).
 */
class EgisOperationLoops : public EGISAPTrustlet {
    enum class AsyncState : eventfd_t {
        Idle = 0,
        Cancel = 1,
        Authenticating = 2,
        Enrolling = 4,
    };

    enum class WakeupReason {
        Timeout,
        Event,
        Finger,  // Hardware
    };

    const uint64_t mDeviceId;
    uint32_t mGid;
    sp<IBiometricsFingerprintClientCallback> mClientCallback;
    std::mutex mClientCallbackMutex;

    AsyncState currentState = AsyncState::Idle;
    int epoll_fd;
    int event_fd;
    EgisFpDevice dev;
    pthread_t thread;

   public:
    EgisOperationLoops(uint64_t deviceId);

   private:
    static void *ThreadStart(void *);
    void RunThread();
    void ProcessOpcode(const command_buffer_t &);
    int ConvertReturnCode(int);
    /**
     * Convert error code from the device.
     * Some return codes indicate a special state which do not imply an error has occured.
     * @return True when an error occured.
     */
    bool ConvertAndCheckError(int &);
    WakeupReason WaitForEvent(int timeoutSec = -1);
    bool MoveToState(AsyncState);
    AsyncState ReadState();
    /**
     * Atomically check if the current operation is requested to cancel.
     * If cancelled, TZ cancel will be invoked and the service will be
     * notified before returning.
     */
    bool IsCancelled();
    /**
     * Invoked when an operation encounters a cancellation as requested by cancel() from the Android service.
     * Propagates the cancel operation to the TZ-app so that it can do its cleanup.
     */
    int RunCancel();

    // Temporaries for asynchronous operation:
    uint64_t mSecureUserId;

    // Notify functions:
    void NotifyError(FingerprintError);
    void NotifyRemove(uint32_t fid, uint32_t remaining);
    void NotifyAcquired(FingerprintAcquiredInfo);
    void NotifyEnrollResult(uint32_t fid, uint32_t remaining);
    void NotifyBadImage(int);

    // These should run asynchronously from HAL calls:
    void EnrollAsync();

   public:
    void SetNotify(const sp<IBiometricsFingerprintClientCallback>);
    int SetUserDataPath(uint32_t gid, const char *path);
    int RemoveFinger(uint32_t fid);
    int Prepare();
    bool Cancel();
    int Enumerate();
    int Enroll(const hw_auth_token_t &, uint32_t timeoutSec);
};
