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
    EgisFpDevice mDev;
    uint64_t mAuthenticatorId;

    AsyncState currentState = AsyncState::Idle;
    int epoll_fd;
    int event_fd;
    pthread_t thread;

   public:
    EgisOperationLoops(uint64_t deviceId, EgisFpDevice &&);

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
    bool ConvertAndCheckError(int &, EGISAPTrustlet::API &);
    WakeupReason WaitForEvent(int timeoutSec = -1);
    bool MoveToState(AsyncState);
    AsyncState ReadState();
    /**
     * Atomically check if the current operation is requested to cancel.
     * If cancelled, TZ cancel will be invoked and the service will be
     * notified before returning.
     * Requires a locked buffer to atomically cancel the current operation without
     * interfering with another command.
     */
    bool CheckAndHandleCancel(EGISAPTrustlet::API &);
    /**
     * Invoked when an operation encounters a cancellation as requested by cancel() from the Android service.
     * Propagates the cancel operation to the TZ-app so that it can do its cleanup.
     */
    int RunCancel(EGISAPTrustlet::API &);

    // Temporaries for asynchronous operation:
    uint64_t mSecureUserId;
    hw_auth_token_t mCurrentChallenge;
    int mEnrollTimeout;

    // Notify functions:
    void NotifyError(FingerprintError);
    void NotifyRemove(uint32_t fid, uint32_t remaining);
    void NotifyAcquired(FingerprintAcquiredInfo);
    void NotifyAuthenticated(uint32_t fid, const hw_auth_token_t &hat);
    void NotifyEnrollResult(uint32_t fid, uint32_t remaining);
    void NotifyBadImage(int);

    /**
     * Process the next step of the main section of enroll() or authenticate().
     */
    FingerprintError HandleMainStep(command_buffer_t &, int timeoutSec = -1);

    // These should run asynchronously from HAL calls:
    void EnrollAsync();
    void AuthenticateAsync();

   public:
    uint64_t GetAuthenticatorId();

    void SetNotify(const sp<IBiometricsFingerprintClientCallback>);
    int SetUserDataPath(uint32_t gid, const char *path);
    int RemoveFinger(uint32_t fid);
    int Prepare();
    bool Cancel();
    int Enumerate();
    int Enroll(const hw_auth_token_t &, uint32_t timeoutSec);
    int Authenticate(uint64_t challenge);
};
