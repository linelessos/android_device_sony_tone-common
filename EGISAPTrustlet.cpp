#include "EGISAPTrustlet.h"
#include <string.h>

EGISAPTrustlet::EGISAPTrustlet() : QSEETrustlet("egisap32", EGISAPTrustlet::API::MinBufferSize()) {
    SendDataInit();
}

int EGISAPTrustlet::SendCommand(EGISAPTrustlet::API &lockedBuffer) {
    int rc = QSEETrustlet::SendCommand(&lockedBuffer.GetRequest(), sizeof(trustlet_buffer_t), &lockedBuffer.GetResponse(), sizeof(trustlet_buffer_t));
    if (rc)
        return rc;

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
    auto tb = reinterpret_cast<trustlet_buffer_t *>(*lockedBuffer);
    memset(tb, 0, sizeof(trustlet_buffer_t));

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

int EGISAPTrustlet::SetMasterKey(MasterKey &key) {
    auto lockedBuffer = GetLockedAPI();
    auto &extra = lockedBuffer.GetRequest().extra_buffer;

    extra.command = ExtraCommand::SetMasterKey;
    extra.data_size = key.size();

    memcpy(extra.data, key.data(), key.size());

    return SendExtraCommand(lockedBuffer);
}
