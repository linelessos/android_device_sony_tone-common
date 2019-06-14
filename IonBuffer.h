#pragma once
#include <stdint.h>
// WARNING: Must include stdint before msm_ion, or it'll miss the size_t definition!
#include <linux/msm_ion.h>

class IonBuffer {
    static constexpr size_t ION_ALIGN = 0x1000;
    static constexpr size_t ION_ALIGN_MASK = ION_ALIGN - 1;

    size_t mRequestedSize, mSize;
    int mFd = -1;
    ion_user_handle_t mHandle = 0;
    void *mMapped = nullptr;

    static int ion_dev_fd;
    static int IonDev();

   public:
    IonBuffer(size_t);
    ~IonBuffer();

    IonBuffer(IonBuffer &&);
    IonBuffer &operator=(IonBuffer &&);
    IonBuffer(IonBuffer &) = delete;
    const IonBuffer &operator=(const IonBuffer &) = delete;

    size_t size() const;
    size_t requestedSize() const;
    int fd() const;

    void *operator()();
    const void *operator()() const;
};

template <typename T>
class TypedIonBuffer : public IonBuffer {
   public:
    TypedIonBuffer() : IonBuffer(sizeof(T)) {
    }

    T *operator()() {
        return (T *)IonBuffer::operator()();
    }
    const T *operator()() const {
        return (T *)IonBuffer::operator()();
    }
    T *operator->() {
        return (T *)IonBuffer::operator()();
    }
    const T *operator->() const {
        return (T *)IonBuffer::operator()();
    }
    T &operator*() {
        return *operator()();
    }
    const T &operator*() const {
        return *operator()();
    }
};
