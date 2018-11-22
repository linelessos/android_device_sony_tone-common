#pragma once

#include <arpa/inet.h>
#include <hardware/hw_auth_token.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include "QSEEKeymasterTrustlet.h"
#include "QSEETrustlet.h"

typedef struct {
    int qty;
    int corner_count;
    int coverage;
    int mat1[2];
    int mat2[3];
    int other;
} match_result;

static_assert(offsetof(match_result, mat1) == 0xc, "");
static_assert(offsetof(match_result, mat2) == 0x14, "");
static_assert(offsetof(match_result, other) == 0x20, "");

enum class Step : uint32_t {
    Done = 0,
    Init = 1,
    WaitFingerprint = 4,
    FingerDetected = 5,
    FingerAcquired = 6,
    NotReady = 7,
    Error = 8,  // Indication for a reset
    Cancel = 0x19,
    ContinueAfterTimeout = 0x25,
};

/**
 * Default command structure.
 * This mostly encapsulates generic communication.
 */
typedef struct {
    Step step;
    int timeout;
    int bad_image_reason;
    int pading0[2];
    int match_score;
    int padding1;
    int enroll_status;
    int enroll_steps_done;
    int enroll_steps_required;

    char padding2[0x30 - 0x28];

    uint32_t zeroed_for_enroll;

    uint32_t finger_id;
    int32_t finger_list[5];
    int finger_count;

    char padding3[0x10];
    match_result match_result;

    char padding4[0x100 - sizeof(match_result)];

    int match_result_length;
    uint32_t enroll_finger_id;
} command_buffer_t;

static_assert(sizeof(command_buffer_t) == 0x168, "buffer_168 has wrong size!");
static_assert(offsetof(command_buffer_t, bad_image_reason) == 0x8, "");
static_assert(offsetof(command_buffer_t, match_score) == 0x14, "");
static_assert(offsetof(command_buffer_t, enroll_status) == 0x1c, "");
static_assert(offsetof(command_buffer_t, zeroed_for_enroll) == 0x30, "");
static_assert(offsetof(command_buffer_t, finger_id) == 0x34, "");
static_assert(offsetof(command_buffer_t, finger_list) == 0x38, "");
static_assert(offsetof(command_buffer_t, finger_count) == 0x4c, "");
static_assert(offsetof(command_buffer_t, match_result) == 0x60, "");
static_assert(offsetof(command_buffer_t, match_result_length) == 0x160, "");
static_assert(offsetof(command_buffer_t, enroll_finger_id) == 0x164, "");

enum class ExtraCommand : uint32_t {
    SetUserDataPath = 0,
    SetAuthToken = 1,
    /*SetAnd?*/ CheckAuthToken = 2,
    GetFingerList = 3,
    SetSecureUserId = 0xa,
    RemoveFinger = 0xb,
    GetRand64 = 0xd,
    GetChallenge = 0xe,
    ClearChallenge = 0xf,
    SetMasterKey = 0x10,
};

/**
 * A secondary API to process so-called "extra" commands.
 */
typedef struct {
    char string_field[0xff];
    // The print to remove:
    uint32_t remove_fid;
    // The number of prints that are stored/returned in the finger_list field:
    int32_t number_of_prints;
    // NOTE: This field is duplicated across structures:
    uint64_t secure_user_id;
    int32_t finger_list[5];
    ExtraCommand command;

    // Field for arbitrary data:
    char data[0x200];
    int32_t data_size;

    uint32_t padding1;
} extra_buffer_t;

static_assert(sizeof(extra_buffer_t) == 0x330, "");
static_assert(offsetof(extra_buffer_t, remove_fid) == 0x100, "");
static_assert(offsetof(extra_buffer_t, number_of_prints) == 0x104, "");
static_assert(offsetof(extra_buffer_t, secure_user_id) == 0x108, "");
static_assert(offsetof(extra_buffer_t, command) == 0x124, "");
static_assert(offsetof(extra_buffer_t, data) == 0x128, "");
static_assert(offsetof(extra_buffer_t, data_size) == 0x328, "");

enum class Command : uint32_t {
    Prepare = 0,
    Cleanup = 1,
    InitEnroll = 2,
    Enroll = 3,
    FinalizeEnroll = 4,
    Cancel = 8,
    ExtraCommand = 0xa,
    DataInit = 0x10,
    DataUninit = 0x11,
};

/**
 * The datastructure through which this userspace HAL communicates with the TZ app.
 */
typedef struct {
    Command command;
    uint32_t padding0;
    uint32_t unused_return_command;
    uint32_t result;

    uint64_t padding1;

    uint32_t command_buffer_size;  // either 0 or sizeof(command_buffer)

    uint32_t extra_buffer_in_size;       // Number of bytes that are passed in through the extra_buffer;
    uint32_t extra_buffer_max_out_size;  // Maximum number of bytes that may be passed back through extra_buffer
    uint32_t extra_buffer_type_size;     // Total number of bytes in the extra_buffer field. Either 0 or sizeof(extra_buffer)

    char padding2[0x10];

    uint32_t extra_buffer_out_size;  // Actual number of bytes that have been passed back through extra_buffer

    uint32_t padding3;

    command_buffer_t command_buffer;
    extra_buffer_t extra_buffer;

    uint64_t padding4;

    uint32_t padding5;  // NOTE: This value is set to 0 only for command 6 (do_identify). TODO: Check if the value is set to something sensible on return.
    uint32_t padding6;
    uint32_t secure_user_id;  // user_id from the HAT during enroll. TODO: This field is replicated across multiple structures!
    uint64_t padding7;
} trustlet_buffer_t;

static_assert(sizeof(trustlet_buffer_t) == 0x4f8, "trustlet_buffer_t not of expected size!");
static_assert(offsetof(trustlet_buffer_t, command_buffer_size) == 0x18, "");
static_assert(offsetof(trustlet_buffer_t, extra_buffer_type_size) == 0x24, "");
static_assert(offsetof(trustlet_buffer_t, secure_user_id) == 0x4e8, "");

// TODO: Move to another file?
// Non-packed version of hw_auth_token_t, used in communication to TZ.
typedef struct {
    uint8_t version;
    // Implicit 7-byte padding
    uint64_t challenge;
    uint64_t user_id;
    uint64_t authenticator_id;
    uint32_t authenticator_type;
    // Implicit 4-byte padding
    uint64_t timestamp;
    uint8_t hmac[0x20];
} ets_authen_token_t;
static_assert(offsetof(ets_authen_token_t, challenge) == 0x8, "");
static_assert(offsetof(ets_authen_token_t, timestamp) == 0x28, "");

class EGISAPTrustlet : public QSEETrustlet {
   protected:
    class API {
        // TODO: Could be a templated class defined in QSEETrustlet.

        static constexpr auto RequestOffset = 0x5c;
        static constexpr auto ResponseOffset = 0x14;

        QSEETrustlet::LockedIONBuffer mLockedBuffer;

       public:
        // TODO: Inline or define in cpp!!!
        API(QSEETrustlet::LockedIONBuffer &&lockedBuffer) : mLockedBuffer(std::move(lockedBuffer)) {
        }

        trustlet_buffer_t &GetRequest() {
            return *reinterpret_cast<trustlet_buffer_t *>((ptrdiff_t)*mLockedBuffer + RequestOffset);
        }

        trustlet_buffer_t &GetResponse() {
            return *reinterpret_cast<trustlet_buffer_t *>((ptrdiff_t)*mLockedBuffer + ResponseOffset);
        }

        void MoveResponseToRequest() {
            memmove(&GetRequest(), &GetResponse(), sizeof(trustlet_buffer_t));
        }

        static constexpr size_t BufferSize() {
            return sizeof(trustlet_buffer_t) + std::max(RequestOffset, ResponseOffset);
        }

        /**
         * Returns extra_buffer.data as a reference to T, and initializes
         * the data_size field to sizeof(T).
         */
        template <typename T>
        T &GetExtraRequestDataBuffer() {
            auto &extra = GetRequest().extra_buffer;
            extra.data_size = sizeof(T);
            return *reinterpret_cast<T *>(extra.data);
        }

        friend class EGISAPTrustlet;
    };

   public:
    EGISAPTrustlet();

    int SendCommand(API &);
    int SendCommand(API &, Command);
    int SendCommand(Command);
    API GetLockedAPI();
    int SendExtraCommand(API &);
    int SendExtraCommand(API &, ExtraCommand);
    int SendExtraCommand(ExtraCommand);

    // Helper calls:
    uint64_t CallFor64BitResponse(ExtraCommand);

    // Normal commands:
    int SendPrepare(API &);
    int SendCancel(API &);
    int SendDataInit();
    int SendInitEnroll(API &, uint64_t);
    int SendEnroll(API &);
    int SendFinalizeEnroll(API &);

    // Extra commands:
    int SetUserDataPath(const char *);
    int SetAuthToken(const hw_auth_token_t &token);
    int CheckAuthToken(API &);
    int GetFingerList(std::vector<uint32_t> &);
    int SetSecureUserId(API &, uint64_t);
    int RemoveFinger(uint32_t);
    uint64_t GetRand64();
    uint64_t GetChallenge();
    int ClearChallenge();
    int SetMasterKey(const MasterKey &);
};
