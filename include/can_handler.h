#pragma once

#include "app_types.h"

namespace App {

bool initCan();
void updateLed();
bool prepareProtectedFrame(const CanFrame& payloadFrame, CanFrame* wireFrame,
                           char* error, size_t errorSize);
bool sendWireFrame(const CanFrame& frame, const char* tag, const char* mode);
bool sendPayloadFrame(const CanFrame& payloadFrame, const char* tag,
                      const char* mode, bool captureTx);
bool sendLegacyText(const char* text, size_t length);
void pollCan();

}  // namespace App
