#include "EGISAPTrustlet.h"
#include <string.h>
#include "FormatException.hpp"

#define LOG_TAG "FPC ET"
#define LOG_NDEBUG 0
#include <log/log.h>

namespace egistec::ganges {

void log_hex(const char *data, int length) {
    if (length <= 0 || data == NULL)
        return;

    // Trim leading nullsi, 4 bytes at a time:
    int cnt = 0;
    for (; length > 0 && !*(const uint32_t *)data; cnt++, data += 4, length -= 4)
        ;

    // Trim trailing nulls:
    for (; length > 0 && !data[length - 1]; --length)
        ;

    if (length <= 0) {
        ALOGV("All data is 0!");
        return;
    }

    if (cnt)
        ALOGV("Skipped %d integers (%d bytes)", cnt, cnt * 4);

    // Format the byte-buffer into hexadecimals:
    char *buf = (char *)malloc(length * 3 + 10);
    char *base = buf;
    for (int i = 0; i < length; i++) {
        sprintf(buf, "%02X", data[i]);
        buf += 2;
        *buf++ = ' ';

        if (i % 16 == 15 || i + 1 == length) {
            *buf = '\0';
            ALOGV("%s", base);
            buf = base;
        }
    }

    free(base);
}

EGISAPTrustlet::EGISAPTrustlet() : QSEETrustlet("egisap32", 0x2400) {
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &lockedBuffer) {
    // TODO: += !
    lockedBuffer.GetRequest().process = 0xe0;

    struct __attribute__((__packed__)) APIPrefix {
        uint32_t process_id;
        uint32_t no_extra_buffer;
        uint32_t a;
        uint32_t extra_buffer_size;
        union {
            uint64_t b;
            struct {
                uint32_t ret_val;
            };
        };
        union {
            uint64_t c;
            struct {
                uint32_t c2;
                // TODO: Could be little-endian
                uint8_t extra_flags;
            };
        };
    };
    static_assert(offsetof(APIPrefix, extra_buffer_size) == 0xc, "");
    static_assert(offsetof(APIPrefix, b) == 0x10, "");
    static_assert(offsetof(APIPrefix, ret_val) == 0x10, "");
    static_assert(offsetof(APIPrefix, c) == 0x18, "");
    static_assert(offsetof(APIPrefix, extra_flags) == 0x1c, "");
    auto prefix = reinterpret_cast<APIPrefix *>(*lockedBuffer.mLockedBuffer);
    // TODO: Replace with memset?
    prefix->process_id = lockedBuffer.GetRequest().process;
    prefix->b = 0;
    prefix->c = 0;

    prefix->no_extra_buffer = 0;
    prefix->extra_buffer_size = 0;

#if !LOG_NDEBUG
    log_hex(reinterpret_cast<const char *>(&lockedBuffer.GetRequest()), sizeof(trustlet_buffer_t));
#endif

    int rc = QSEETrustlet::SendCommand(prefix, 0x880, prefix, 0x840);
    if (rc) {
        ALOGE("%s failed with rc = %d", __func__, rc);
        return rc;
    }

#if !LOG_NDEBUG
    ALOGV("Response:");
    log_hex(reinterpret_cast<const char *>(&lockedBuffer.GetResponse()), sizeof(trustlet_buffer_t));
#endif

    // struct  __attribute__((__packed__)) APIResponse {
    //     uint64_t padding[2];
    //     uint32_t ret_val;
    //     char data[];
    // };

    // TODO: List expected response codes in an enum.
    rc = prefix->ret_val;
    ALOGE_IF(rc, "%s ret_val = %#x", __func__, rc);
    return rc;
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &buffer, CommandId commandId, uint32_t gid) {
    buffer.GetRequest().command = commandId;
    buffer.GetRequest().gid = gid;
    return SendCommand(buffer);
}

int EGISAPTrustlet::SendCommand(CommandId commandId, uint32_t gid) {
    auto api = GetLockedAPI();
    return SendCommand(api, commandId, gid);
}

int EGISAPTrustlet::SendDataCommand(EGISAPTrustlet::API &buffer, CommandId commandId, const void *data, size_t length, uint32_t gid) {
    auto &req = buffer.GetRequest();
    req.buffer_size = length;
    memcpy(req.data, data, length);

    return SendCommand(buffer, commandId, gid);
}

int EGISAPTrustlet::SendDataCommand(CommandId commandId, const void *data, size_t length, uint32_t gid) {
    auto api = GetLockedAPI();
    return SendDataCommand(api, commandId, data, length, gid);
}

/**
 * Prepare buffer for use.
 */
EGISAPTrustlet::API EGISAPTrustlet::GetLockedAPI() {
    auto lockedBuffer = GetLockedBuffer();
    memset(*lockedBuffer, 0, EGISAPTrustlet::API::BufferSize());
    return lockedBuffer;
}

int EGISAPTrustlet::Calibrate() {
    return SendCommand(CommandId::Calibrate);
}

int EGISAPTrustlet::InitializeAlgo() {
    return SendCommand(CommandId::InitializeAlgo);
}

int EGISAPTrustlet::InitializeSensor() {
    return SendCommand(CommandId::InitializeSensor);
}

int EGISAPTrustlet::SetDataPath(const char *data_path) {
    return SendDataCommand(CommandId::SetDataPath, data_path, strlen(data_path), 1);
}

int EGISAPTrustlet::SetMasterKey(const MasterKey &key) {
    return SendDataCommand(CommandId::SetMasterKey, key.data(), key.size());
}

int EGISAPTrustlet::SetUserDataPath(uint32_t gid, const char *data_path) {
    return SendDataCommand(CommandId::SetUserDataPath, data_path, strlen(data_path), gid);
}

int EGISAPTrustlet::SetWorkMode(uint32_t workMode) {
    // WARNING: Work mode is passed in through gid!
    return SendCommand(CommandId::SetWorkMode, workMode);
}

uint64_t EGISAPTrustlet::GetAuthenticatorId() {
    return -1;
}

}  // namespace egistec::ganges
