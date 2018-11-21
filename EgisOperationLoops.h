#pragma once

#include "EGISAPTrustlet.h"
#include "EgisFpDevice.h"

/**
 * External wrapper class containing TZ communication logic
 * (Separated from datastructural/architectural choices).
 */
class EgisOperationLoops : public EGISAPTrustlet {
    EgisFpDevice dev;
    void ProcessOpcode(const command_buffer_t &);
    int ConvertReturnCode(int);

   public:
    int RemoveFinger(uint32_t fid);
    int Prepare();
    int Cancel();
};
