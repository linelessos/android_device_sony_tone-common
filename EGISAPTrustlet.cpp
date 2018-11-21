#include "EGISAPTrustlet.h"
#include <string.h>
#include "FormatException.hpp"

#define LOG_TAG "FPC ET"
#define LOG_NDEBUG 0
#include <log/log.h>

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

#if !LOG_NDEBUG
    log_hex(reinterpret_cast<const char *>(&lockedBuffer.GetRequest()), sizeof(trustlet_buffer_t));
#endif

    int rc = QSEETrustlet::SendCommand(prefix, 0x880, prefix, 0x840);
    if (rc) {
        ALOGE("SendCommand failed with rc = %d", rc);
        return rc;
    }

#if !LOG_NDEBUG
    ALOGV("Response:");
    log_hex(reinterpret_cast<const char *>(&lockedBuffer.GetResponse()), sizeof(trustlet_buffer_t));
#endif

    return lockedBuffer.GetResponse().result;
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &buffer, Command command) {
    buffer.GetRequest().command = command;
    return SendCommand(buffer);
}

int EGISAPTrustlet::SendCommand(Command command) {
    auto lockedBuffer = GetLockedAPI();
    return SendCommand(lockedBuffer, command);
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
    return SendCommand(buffer, Command::ExtraCommand);
}

int EGISAPTrustlet::SendPrepare(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::Prepare);
}

int EGISAPTrustlet::SendCancel(EGISAPTrustlet::API &api) {
    return SendCommand(api, Command::Cancel);
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

int EGISAPTrustlet::GetFingerList(std::vector<uint32_t> &list) {
    auto lockedBuffer = GetLockedAPI();
    auto &extraIn = lockedBuffer.GetRequest().extra_buffer;
    const auto &extraOut = lockedBuffer.GetResponse().extra_buffer;
    extraIn.command = ExtraCommand::GetFingerList;
    int rc = SendExtraCommand(lockedBuffer);
    if (!rc) {
        ALOGD("GetFingerList reported %d fingers", extraOut.number_of_prints);
        std::copy(extraOut.finger_list, extraOut.finger_list + extraOut.number_of_prints, std::back_inserter(list));
    }
    return rc;
}

int EGISAPTrustlet::RemoveFinger(uint32_t fid) {
    auto lockedBuffer = GetLockedAPI();
    auto &extra = lockedBuffer.GetRequest().extra_buffer;
    extra.command = ExtraCommand::RemoveFinger;
    extra.remove_fid = fid;
    return SendExtraCommand(lockedBuffer);
}

uint64_t EGISAPTrustlet::GetRand64() {
    auto lockedBuffer = GetLockedAPI();
    auto &extraIn = lockedBuffer.GetRequest().extra_buffer;
    const auto &extraOut = lockedBuffer.GetResponse().extra_buffer;
    extraIn.command = ExtraCommand::GetRand64;
    auto rc = SendExtraCommand(lockedBuffer);
    if (rc) {
        // Very unlikely
        ALOGE("%s failed with %d", __func__, rc);
        return -1;
    }
    auto s = extraOut.data_size;
    if (s != sizeof(uint64_t)) {
        // Very unlikely
        ALOGE("%s returned wrong data size of %d", __func__, s);
        return -1;
    }
    auto rand = *reinterpret_cast<const uint64_t *>(extraOut.data);
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
