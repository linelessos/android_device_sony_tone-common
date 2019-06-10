#pragma once

#include <arpa/inet.h>
#include <hardware/hw_auth_token.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include "QSEEKeymasterTrustlet.h"
#include "QSEETrustlet.h"

namespace egistec::ganges {

enum class CommandId : uint32_t {
    SetMasterKey = 0,
    InitializeAlgo = 1,
    InitializeSensor = 2,
    Calibrate = 6,

    GetPrintIds = 0x16,
    SetWorkMode = 0x17,
    SetUserDataPath = 0x19,
    SetDataPath = 0x19,
    GetAuthenticatorId = 0x20,
};

/**
 * The datastructure through which this userspace HAL communicates with the TZ app.
 */
typedef struct {
    uint32_t process;
    CommandId command;
    uint32_t gid;
    uint32_t fid;
    uint32_t buffer_size;
    char data[];
} trustlet_buffer_t;

static_assert(sizeof(trustlet_buffer_t) == 0x14, "trustlet_buffer_t not of expected size!");

class EGISAPTrustlet : public QSEETrustlet {
   protected:
    class API {
        // TODO: Could be a templated class defined in QSEETrustlet.

        static inline constexpr auto RequestOffset = 0x5c;
        static inline constexpr auto ResponseOffset = 0x14;

        QSEETrustlet::LockedIONBuffer mLockedBuffer;

       public:
        inline API(QSEETrustlet::LockedIONBuffer &&lockedBuffer) : mLockedBuffer(std::move(lockedBuffer)) {
        }

        inline trustlet_buffer_t &GetRequest() {
            return *reinterpret_cast<trustlet_buffer_t *>((ptrdiff_t)*mLockedBuffer + RequestOffset);
        }

        inline trustlet_buffer_t &GetResponse() {
            return *reinterpret_cast<trustlet_buffer_t *>((ptrdiff_t)*mLockedBuffer + ResponseOffset);
        }

        inline void MoveResponseToRequest() {
            memmove(&GetRequest(), &GetResponse(), sizeof(trustlet_buffer_t));
        }

        static inline constexpr size_t BufferSize() {
            return sizeof(trustlet_buffer_t) + std::max(RequestOffset, ResponseOffset);
        }

        friend class EGISAPTrustlet;
    };

   public:
    EGISAPTrustlet();

    int SendCommand(API &);
    int SendCommand(API &, CommandId, uint32_t gid = 0);
    int SendCommand(CommandId, uint32_t gid = 0);
    int SendDataCommand(API &, CommandId, const void *data, size_t length, uint32_t gid = 0);
    int SendDataCommand(CommandId, const void *data, size_t length, uint32_t gid = 0);
    API GetLockedAPI();

    int Calibrate();
    int InitializeAlgo();
    int InitializeSensor();
    int SetDataPath(const char *);
    int SetMasterKey(const MasterKey &);
    int SetUserDataPath(uint32_t gid, const char *);
    int SetWorkMode(uint32_t);
    uint64_t GetAuthenticatorId();
};

}  // namespace egistec::ganges
