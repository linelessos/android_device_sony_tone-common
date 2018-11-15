#include "EGISAPTrustlet.h"
#include <string.h>
#include "FormatException.hpp"

#define LOG_TAG "FPC ET"
#include <log/log.h>

EGISAPTrustlet::EGISAPTrustlet() : QSEETrustlet("egisap32", 0x2400) {
    int rc = SendDataInit();
    if (rc)
        throw FormatException("SendDataInit failed with rc = %d", rc);
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &lockedBuffer) {
    if (lockedBuffer.GetRequest().command == Command::ExtraCommand)
        ALOGD("%s: Sending extra-command %#x", __func__, lockedBuffer.GetRequest().extra_buffer.command);
    else
        ALOGD("%s: Sending command %#x (step = %d)", __func__, lockedBuffer.GetRequest().command, lockedBuffer.GetRequest().command_buffer.step);

    struct __attribute__((__packed__)) APIPrefix {
        uint32_t a;
        char padding[8];
        uint64_t b, c;
    };
    static_assert(offsetof(APIPrefix, b) == 0xc, "");
    static_assert(offsetof(APIPrefix, c) == 0x14, "");
    auto prefix = reinterpret_cast<APIPrefix *>(*lockedBuffer.mLockedBuffer);
    prefix->a = 0xe0;
    prefix->b = 0;
    prefix->c = 0;

    // Always set the fixed size fields of the command and extra buffers, even if they
    // are not used to pass any data.
    lockedBuffer.GetRequest().command_buffer_size = sizeof(command_buffer_t);
    lockedBuffer.GetRequest().extra_buffer_type_size = sizeof(extra_buffer_t);

    int rc = QSEETrustlet::SendCommand(prefix, 0x880, prefix, 0x840);
    if (rc) {
        ALOGE("SendCommand failed with rc = %d", rc);
        return rc;
    }

    return lockedBuffer.GetResponse().result;
}

int EGISAPTrustlet::SendCommand(Command command) {
    auto lockedBuffer = GetLockedAPI();
    lockedBuffer.GetRequest().command = command;
    return SendCommand(lockedBuffer);
}

/**
 * Prepare buffer for use.
 */
EGISAPTrustlet::API EGISAPTrustlet::GetLockedAPI() {
    auto lockedBuffer = GetLockedBuffer();
    memset(*lockedBuffer, 0, EGISAPTrustlet::API::BufferSize());

    return lockedBuffer;
}

int EGISAPTrustlet::SendExtraCommand(EGISAPTrustlet::API &buffer) {
    buffer.GetRequest().command = Command::ExtraCommand;
    return SendCommand(buffer);
}

int EGISAPTrustlet::SendPrepare(EGISAPTrustlet::API &buffer) {
    buffer.GetRequest().command = Command::Prepare;
    return SendCommand(buffer);
}

int EGISAPTrustlet::SendDataInit() {
    return SendCommand(Command::DataInit);
}

int EGISAPTrustlet::SetUserDataPath(const char *path) {
    auto lockedBuffer = GetLockedAPI();
    auto &extra = lockedBuffer.GetRequest().extra_buffer;
    extra.command = ExtraCommand::SetUserDataPath;

    const auto len = strlen(path);
    if (len >= sizeof(extra.string_field) - 1) {
        ALOGE("%s path %s is too long!", __func__, path);
        return -1;
    }

    // Copy terminating null-character:
    memcpy(extra.string_field, path, len + 1);

    return SendExtraCommand(lockedBuffer);
}

uint64_t EGISAPTrustlet::GetRand64() {
    auto lockedBuffer = GetLockedAPI();
    lockedBuffer.GetRequest().extra_buffer.command = ExtraCommand::GetRand64;
    auto rc = SendExtraCommand(lockedBuffer);
    if (rc) {
        // Very unlikely
        ALOGE("%s failed with %d", __func__, rc);
        return -1;
    }
    auto s = lockedBuffer.GetResponse().extra_buffer.data_size;
    if (s != sizeof(uint64_t)) {
        // Very unlikely
        ALOGE("%s returned wrong data size of %d", __func__, s);
        return -1;
    }
    auto rand = *reinterpret_cast<uint64_t *>(lockedBuffer.GetResponse().extra_buffer.data);
    ALOGD("%s: %#lx", __func__, rand);
    return rand;
}

int EGISAPTrustlet::SetMasterKey(MasterKey &key) {
    auto lockedBuffer = GetLockedAPI();
    auto &extra = lockedBuffer.GetRequest().extra_buffer;

    extra.command = ExtraCommand::SetMasterKey;
    extra.data_size = key.size();

    memcpy(extra.data, key.data(), key.size());

    return SendExtraCommand(lockedBuffer);
}
