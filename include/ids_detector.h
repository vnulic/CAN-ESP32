#pragma once

#include "app_types.h"

namespace App {

const char* alertTypeName(AlertType type);
void rememberAlert(const CanFrame& frame, AlertType type);
void inspectFrame(const CanFrame& frame);
bool prepareSpoofFrame(const CanFrame& payloadFrame, CanFrame* wireFrame,
                       char* error, size_t errorSize);

bool activateDefenseForLastAlert(uint32_t durationMs);
void clearExpiredDefenseEntries();
void clearAllDefenseEntries();
uint8_t activeDefenseCount();
bool shouldDropByDefense(const CanFrame& frame);

}  // namespace App
