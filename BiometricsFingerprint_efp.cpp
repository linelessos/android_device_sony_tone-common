#include "BiometricsFingerprint_efp.h"
#include "FormatException.hpp"

#define LOG_TAG "FPC ET"
#include <log/log.h>

namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {
namespace V2_1 {
namespace implementation {

BiometricsFingerprint_efp::BiometricsFingerprint_efp() {
    QSEEKeymasterTrustlet keymaster;
    mMasterKey = keymaster.GetKey();

    int rc = loops.Prepare();
    if (rc)
        throw FormatException("Prepare failed with rc = %d", rc);

    rc = loops.SetMasterKey(mMasterKey);
    if (rc)
        throw FormatException("SetMasterKey failed with rc = %d", rc);

    mAuthenticatorId = loops.GetRand64();
}

Return<uint64_t> BiometricsFingerprint_efp::setNotify(const sp<IBiometricsFingerprintClientCallback> &clientCallback) {
    std::lock_guard<std::mutex> lock(mClientCallbackMutex);
    mClientCallback = clientCallback;
    // This is here because HAL 2.1 doesn't have a way to propagate a
    // unique token for its driver. Subsequent versions should send a unique
    // token for each call to setNotify(). This is fine as long as there's only
    // one fingerprint device on the platform.
    return reinterpret_cast<uint64_t>(this);
}

Return<uint64_t> BiometricsFingerprint_efp::preEnroll() {
    ALOGE("%s not implemented!", __func__);
    return -1;
}

Return<RequestStatus> BiometricsFingerprint_efp::enroll(const hidl_array<uint8_t, 69> &hat, uint32_t gid, uint32_t timeoutSec) {
    ALOGE("%s not implemented!", __func__);
    return RequestStatus::SYS_UNKNOWN;
}

Return<RequestStatus> BiometricsFingerprint_efp::postEnroll() {
    ALOGE("%s not implemented!", __func__);
    return RequestStatus::SYS_UNKNOWN;
}

Return<uint64_t> BiometricsFingerprint_efp::getAuthenticatorId() {
    return mAuthenticatorId;
}

Return<RequestStatus> BiometricsFingerprint_efp::cancel() {
    ALOGE("%s not implemented!", __func__);
    return RequestStatus::SYS_UNKNOWN;
}

Return<RequestStatus> BiometricsFingerprint_efp::enumerate() {
    std::vector<uint32_t> fids;
    int rc = loops.GetFingerList(fids);
    if (rc)
        return RequestStatus::SYS_UNKNOWN;
    auto remaining = fids.size();
    ALOGD("Enumerating %zu fingers", remaining);
    for (auto fid : fids)
        mClientCallback->onEnumerate(mAuthenticatorId, fid, mGid, --remaining);
    return RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint_efp::remove(uint32_t gid, uint32_t fid) {
    ALOGD("%s:", __func__);
    if (gid != mGid) {
        ALOGE("Change group and userpath through setActiveGroup first!");
        return RequestStatus::SYS_EINVAL;
    }
    return loops.RemoveFinger(fid) ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint_efp::setActiveGroup(uint32_t gid, const hidl_string &storePath) {
    ALOGD("%s: gid = %u, path = %s", __func__, gid, storePath.c_str());
    mGid = gid;
    int rc = loops.SetUserDataPath(storePath.c_str());
    return rc ? RequestStatus::SYS_EINVAL : RequestStatus::SYS_OK;
}

Return<RequestStatus> BiometricsFingerprint_efp::authenticate(uint64_t operationId, uint32_t gid) {
    ALOGE("%s not implemented!", __func__);
    return RequestStatus::SYS_UNKNOWN;
}

}  // namespace implementation
}  // namespace V2_1
}  // namespace fingerprint
}  // namespace biometrics
}  // namespace hardware
}  // namespace android
