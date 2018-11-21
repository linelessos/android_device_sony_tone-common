#pragma once

#include <sys/eventfd.h>
#include "EGISAPTrustlet.h"
#include "EgisFpDevice.h"

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

    AsyncState currentState = AsyncState::Idle;
    int epoll_fd;
    int event_fd;
    EgisFpDevice dev;
    pthread_t thread;

   public:
    EgisOperationLoops();

   private:
    static void *ThreadStart(void *);
    void RunThread();
    void ProcessOpcode(const command_buffer_t &);
    int ConvertReturnCode(int);
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

   public:
    int RemoveFinger(uint32_t fid);
    int Prepare();
    bool Cancel();
};
