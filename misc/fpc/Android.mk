ifneq ($(TARGET_DEVICE_NO_FPC), true)
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := android.hardware.biometrics.fingerprint@2.1-service.sony
LOCAL_INIT_RC := android.hardware.biometrics.fingerprint@2.1-service.sony.rc
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := \
    $(call all-subdir-cpp-files) \
    QSEEComFunc.c \
    ion_buffer.c \
    common.c

LOCAL_C_INCLUDES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include
LOCAL_ADDITIONAL_DEPENDENCIES := $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr

# ---------------- FPC ----------------
LOCAL_SRC_FILES += fpc_imp_loire_tone.c
HAS_FPC := true

# ---------------- Egistec ----------------
LOCAL_CFLAGS += \
    -DEGIS_QSEE_APP_NAME=\"egisap32\"

ifneq ($(HAS_FPC),true)
# This file heavily depends on fpc_ implementations from the
# above fpc_imp_* files. There is no sensible default file
# on some platforms, so just remove the file altogether:
LOCAL_SRC_FILES -= BiometricsFingerprint.cpp
endif

LOCAL_SHARED_LIBRARIES := \
    android.hardware.biometrics.fingerprint@2.1 \
    libcutils \
    libdl \
    libhardware \
    libhidlbase \
    libion \
    liblog \
    libutils

LOCAL_CFLAGS += \
    -DPLATFORM_SDK_VERSION=$(PLATFORM_SDK_VERSION) \
    -fexceptions

include $(BUILD_EXECUTABLE)
endif
