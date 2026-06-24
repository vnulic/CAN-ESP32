#pragma once

#include "app_types.h"

namespace App {

void logLine(const char* tag, const char* format, ...);
void logInfo(const char* format, ...);
void formatFrame(const CanFrame& frame, char* buffer, size_t size);
void logFrame(const char* tag, const char* mode, const CanFrame& frame);

}  // namespace App
