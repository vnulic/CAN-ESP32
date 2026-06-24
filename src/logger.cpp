#include "logger.h"

#include <cstdarg>
#include <cstdio>

#include "app_config.h"
#include "app_state.h"

namespace App {

void logLine(const char* tag, const char* format, ...) {
  char message[224] = {};
  va_list args;
  va_start(args, format);
  std::vsnprintf(message, sizeof(message), format, args);
  va_end(args);

  Serial.printf("\r\n[%10lu ms] [%s] %s\r\n", millis(), tag, message);
  promptDirty = true;
}

void logInfo(const char* format, ...) {
  if (!verboseLogging) {
    return;
  }

  char message[224] = {};
  va_list args;
  va_start(args, format);
  std::vsnprintf(message, sizeof(message), format, args);
  va_end(args);

  logLine("INFO", "%s", message);
}

void formatFrame(const CanFrame& frame, char* buffer, size_t size) {
  char dataText[3 * kMaxCanDataBytes + 1] = {};
  size_t offset = 0;

  for (uint8_t index = 0; index < frame.dlc && index < kMaxCanDataBytes;
       ++index) {
    const int written =
        std::snprintf(dataText + offset, sizeof(dataText) - offset, "%02X%s",
                      frame.data[index], (index + 1 < frame.dlc) ? " " : "");
    if (written <= 0) {
      break;
    }
    offset += static_cast<size_t>(written);
    if (offset >= sizeof(dataText)) {
      break;
    }
  }

  if (frame.dlc == 0 || dataText[0] == '\0') {
    std::snprintf(dataText, sizeof(dataText), "--");
  }

  std::snprintf(buffer, size, "node=%s id=0x%0*lX type=%s dlc=%u data=%s%s",
                kNodeName, frame.extended ? 8 : 3,
                static_cast<unsigned long>(frame.id),
                frame.extended ? "EXT" : "STD", frame.dlc, dataText,
                frame.legacyText ? " legacy-text" : "");
}

void logFrame(const char* tag, const char* mode, const CanFrame& frame) {
  char summary[224] = {};
  formatFrame(frame, summary, sizeof(summary));
  logLine(tag, "%s %s", mode, summary);
}

}  // namespace App
