#include "terminal_handler.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "app_config.h"
#include "app_state.h"
#include "attack_simulator.h"
#include "can_handler.h"
#include "ids_detector.h"
#include "logger.h"

namespace {

using namespace App;

void printPrompt() {
  Serial.print("can> ");
}

void printPromptWithInput() {
  printPrompt();
  if (inputLength > 0) {
    Serial.write(reinterpret_cast<const uint8_t*>(inputBuffer), inputLength);
  }
}

bool parseUint32Value(const char* text, uint32_t maximum, uint32_t* value) {
  if (text == nullptr || *text == '\0') {
    return false;
  }

  char* end = nullptr;
  const unsigned long parsed = std::strtoul(text, &end, 0);
  if (end == nullptr || *end != '\0' || parsed > maximum) {
    return false;
  }

  *value = static_cast<uint32_t>(parsed);
  return true;
}

bool parseByteValue(const char* text, uint8_t* value) {
  if (text == nullptr || *text == '\0') {
    return false;
  }

  char* end = nullptr;
  const unsigned long parsed = std::strtoul(text, &end, 16);
  if (end == nullptr || *end != '\0' || parsed > 0xFFU) {
    return false;
  }

  *value = static_cast<uint8_t>(parsed);
  return true;
}

char* trim(char* text) {
  while (*text != '\0' &&
         std::isspace(static_cast<unsigned char>(*text)) != 0) {
    ++text;
  }

  if (*text == '\0') {
    return text;
  }

  char* end = text + std::strlen(text) - 1;
  while (end > text &&
         std::isspace(static_cast<unsigned char>(*end)) != 0) {
    *end = '\0';
    --end;
  }

  return text;
}

bool startsWithCommand(const char* text, const char* command) {
  const size_t length = std::strlen(command);
  if (std::strncmp(text, command, length) != 0) {
    return false;
  }

  const char next = text[length];
  return next == '\0' ||
         std::isspace(static_cast<unsigned char>(next)) != 0;
}

bool parsePayloadFrame(char* const* tokens, size_t tokenCount,
                       size_t idIndex, size_t dlcIndex, size_t dataIndex,
                       CanFrame* frame) {
  uint32_t id = 0;
  uint32_t dlc = 0;

  if (!parseUint32Value(tokens[idIndex], 0x1FFFFFFFUL, &id)) {
    logLine("ERROR", "Invalid CAN ID.");
    return false;
  }

  if (!parseUint32Value(tokens[dlcIndex], kMaxUserDataBytes, &dlc)) {
    logLine("ERROR", "Invalid DLC. Maximum is %u.", kMaxUserDataBytes);
    return false;
  }

  if (tokenCount != dataIndex + dlc) {
    logLine("ERROR", "Expected %lu data bytes after DLC=%lu.",
            static_cast<unsigned long>(dlc), static_cast<unsigned long>(dlc));
    return false;
  }

  std::memset(frame, 0, sizeof(*frame));
  frame->id = id;
  frame->extended = (id > 0x7FFU);
  frame->dlc = static_cast<uint8_t>(dlc);

  for (uint8_t index = 0; index < frame->dlc; ++index) {
    if (!parseByteValue(tokens[dataIndex + index], &frame->data[index])) {
      logLine("ERROR", "Invalid data byte at index %u.", index);
      return false;
    }
  }

  return true;
}

const char* captureSourceName(CaptureSource source) {
  switch (source) {
    case CaptureSource::Rx:
      return "RX";
    case CaptureSource::Tx:
      return "TX";
    default:
      return "NONE";
  }
}

}  // namespace

namespace App {

void printBootBanner() {
  Serial.println();
  Serial.println("ESP32 CAN security terminal");
  Serial.printf("Node: %s\r\n", kNodeName);
  Serial.printf("CAN RX/TX: %d/%d\r\n", kCanRxPin, kCanTxPin);
  Serial.printf("Bitrate: %ld bps\r\n", kCanBitrate);
  Serial.printf("Counter protection: %s\r\n",
                ENABLE_COUNTER_PROTECTION ? "ON" : "OFF");
  Serial.println("Type 'help' for commands.");
}

void servicePrompt() {
  if (!promptDirty) {
    return;
  }

  printPromptWithInput();
  promptDirty = false;
}

void printHelp() {
  Serial.println();
  Serial.println("Commands:");
  Serial.println("  send <id> <dlc> <data...>");
  Serial.println("  repeat <id> <period_ms> <dlc> <data...>");
  Serial.println("  repeat stop");
  Serial.println("  dos start <id> <period_ms>");
  Serial.println("  dos stop");
  Serial.println("  replay start [period_ms]");
  Serial.println("  replay stop");
  Serial.println("  fuzz start [period_ms]");
  Serial.println("  fuzz stop");
  Serial.println("  spoof start <id> <period_ms> <dlc> <data...>");
  Serial.println("  spoof stop");
  Serial.println("  defense on [duration_ms]");
  Serial.println("  defense off");
  Serial.println("  defense status");
  Serial.println("  status");
  Serial.println("  verbose on|off");
  Serial.println("  text <message>");
  Serial.println("  help");
  Serial.println();
  Serial.println("Notes:");
  Serial.println("  - Unrecognized lines are sent as legacy text.");
  Serial.println("  - IDs accept decimal or hex, for example 0x123.");
  Serial.println("  - Data bytes are interpreted as hex, for example AA 55 0F.");
  if (ENABLE_COUNTER_PROTECTION) {
    Serial.println("  - Raw CAN payload is limited to 7 bytes.");
    Serial.println("  - The last byte is appended automatically as counter.");
  } else {
    Serial.println("  - Raw CAN payload is up to 8 bytes.");
  }
  promptDirty = true;
}

void printStatus() {
  logLine("STATUS", "node=%s bitrate=%ld rx=%d tx=%d protection=%s",
          kNodeName, kCanBitrate, kCanRxPin, kCanTxPin,
          ENABLE_COUNTER_PROTECTION ? "on" : "off");
  logLine("STATUS", "repeat=%s replay=%s dos=%s fuzz=%s spoof=%s",
          repeatTask.active ? "on" : "off", replayTask.active ? "on" : "off",
          dosTask.active ? "on" : "off", fuzzTask.active ? "on" : "off",
          spoofTask.active ? "on" : "off");

  if (repeatTask.active) {
    logLine("STATUS", "repeat id=0x%0*lX period=%ums",
            repeatTask.payload.extended ? 8 : 3,
            static_cast<unsigned long>(repeatTask.payload.id),
            repeatTask.periodMs);
  }

  if (replayTask.active) {
    logLine("STATUS", "replay period=%ums", replayTask.periodMs);
  }

  if (dosTask.active) {
    logLine("STATUS", "dos id=0x%0*lX period=%ums",
            dosTask.extended ? 8 : 3,
            static_cast<unsigned long>(dosTask.id), dosTask.periodMs);
  }

  if (fuzzTask.active) {
    logLine("STATUS", "fuzz period=%ums seed=0x%08lX", fuzzTask.periodMs,
            static_cast<unsigned long>(fuzzTask.seed));
  }

  if (spoofTask.active) {
    logLine("STATUS", "spoof id=0x%0*lX period=%ums",
            spoofTask.frame.extended ? 8 : 3,
            static_cast<unsigned long>(spoofTask.frame.id),
            spoofTask.periodMs);
  }

  if (lastCapturedFrame.available) {
    char summary[224] = {};
    formatFrame(lastCapturedFrame.frame, summary, sizeof(summary));
    logLine("STATUS", "capture=%s at=%lums %s",
            captureSourceName(lastCapturedFrame.source),
            static_cast<unsigned long>(lastCapturedFrame.atMs), summary);
  } else {
    logLine("STATUS", "capture=none");
  }

  if (lastAlert.available) {
    logLine("STATUS", "last_alert id=0x%0*lX type=%s at=%lums",
            lastAlert.extended ? 8 : 3,
            static_cast<unsigned long>(lastAlert.id),
            alertTypeName(lastAlert.type),
            static_cast<unsigned long>(lastAlert.atMs));
  } else {
    logLine("STATUS", "last_alert=none");
  }

  clearExpiredDefenseEntries();
  logLine("STATUS", "defense_active=%u", activeDefenseCount());
}

void processCommand(char* line) {
  char* trimmed = trim(line);
  if (*trimmed == '\0') {
    return;
  }

  if (startsWithCommand(trimmed, "text")) {
    char* message = trimmed + 4;
    message = trim(message);
    if (*message == '\0') {
      logLine("ERROR", "Usage: text <message>");
      return;
    }
    (void)sendLegacyText(message, std::strlen(message));
    return;
  }

  char tokenBuffer[kInputBufferCapacity] = {};
  std::snprintf(tokenBuffer, sizeof(tokenBuffer), "%s", trimmed);

  char* tokens[20] = {};
  size_t tokenCount = 0;
  char* context = nullptr;
  char* token = strtok_r(tokenBuffer, " \t", &context);

  while (token != nullptr && tokenCount < 20) {
    tokens[tokenCount++] = token;
    token = strtok_r(nullptr, " \t", &context);
  }

  if (tokenCount == 0) {
    return;
  }

  if (std::strcmp(tokens[0], "help") == 0) {
    printHelp();
    return;
  }

  if (std::strcmp(tokens[0], "status") == 0) {
    printStatus();
    return;
  }

  if (std::strcmp(tokens[0], "defense") == 0) {
    if (tokenCount >= 2 && std::strcmp(tokens[1], "on") == 0) {
      uint32_t durationMs = kDefenseBlockDefaultMs;

      if (tokenCount == 3) {
        if (!parseUint32Value(tokens[2], 600000U, &durationMs) ||
            durationMs < 1000U) {
          logLine("ERROR",
                  "Defense duration must be between 1000 and 600000 ms.");
          return;
        }
      } else if (tokenCount > 3) {
        logLine("ERROR", "Usage: defense on [duration_ms]");
        return;
      }

      (void)activateDefenseForLastAlert(durationMs);
      return;
    }

    if (tokenCount == 2 && std::strcmp(tokens[1], "off") == 0) {
      clearAllDefenseEntries();
      logLine("DEFENSE", "All defense blocks cleared.");
      return;
    }

    if (tokenCount == 2 && std::strcmp(tokens[1], "status") == 0) {
      printStatus();
      return;
    }

    logLine("ERROR", "Usage: defense on [duration_ms] | defense off | defense status");
    return;
  }

  if (std::strcmp(tokens[0], "verbose") == 0) {
    if (tokenCount != 2) {
      logLine("ERROR", "Usage: verbose on | verbose off");
      return;
    }

    if (std::strcmp(tokens[1], "on") == 0) {
      verboseLogging = true;
      logLine("STATE", "Verbose logging enabled.");
      return;
    }

    if (std::strcmp(tokens[1], "off") == 0) {
      verboseLogging = false;
      logLine("STATE", "Verbose logging disabled.");
      return;
    }

    logLine("ERROR", "Usage: verbose on | verbose off");
    return;
  }

  if (std::strcmp(tokens[0], "send") == 0) {
    CanFrame frame;
    if (!parsePayloadFrame(tokens, tokenCount, 1, 2, 3, &frame)) {
      return;
    }
    (void)sendPayloadFrame(frame, "TX", "single", true);
    return;
  }

  if (std::strcmp(tokens[0], "repeat") == 0) {
    if (tokenCount == 2 && std::strcmp(tokens[1], "stop") == 0) {
      stopRepeat();
      return;
    }

    if (tokenCount < 4) {
      logLine("ERROR", "Usage: repeat <id> <period_ms> <dlc> <data...>");
      return;
    }

    uint32_t periodMs = 0;
    if (!parseUint32Value(tokens[2], 60000U, &periodMs) ||
        periodMs < kMinPeriodMs) {
      logLine("ERROR", "Repeat period must be >= %u ms.", kMinPeriodMs);
      return;
    }

    CanFrame frame;
    if (!parsePayloadFrame(tokens, tokenCount, 1, 3, 4, &frame)) {
      return;
    }

    repeatTask.active = true;
    repeatTask.payload = frame;
    repeatTask.periodMs = static_cast<uint16_t>(periodMs);
    repeatTask.nextAtMs = millis();
    logLine("STATE", "Repeat transmission started.");
    return;
  }

  if (std::strcmp(tokens[0], "replay") == 0) {
    if (tokenCount == 2 && std::strcmp(tokens[1], "stop") == 0) {
      stopReplay();
      return;
    }

    if (tokenCount >= 2 && std::strcmp(tokens[1], "start") == 0) {
      uint32_t periodMs = kDefaultReplayPeriodMs;
      if (tokenCount == 3) {
        if (!parseUint32Value(tokens[2], 60000U, &periodMs) ||
            periodMs < kMinPeriodMs) {
          logLine("ERROR", "Replay period must be >= %u ms.", kMinPeriodMs);
          return;
        }
      } else if (tokenCount > 3) {
        logLine("ERROR", "Usage: replay start [period_ms]");
        return;
      }

      if (!lastCapturedFrame.available) {
        logLine("ERROR", "No captured frame is available for replay.");
        return;
      }

      replayTask.active = true;
      replayTask.frame = lastCapturedFrame.frame;
      replayTask.periodMs = static_cast<uint16_t>(periodMs);
      replayTask.nextAtMs = millis();
      logLine("STATE", "Replay attack started.");
      return;
    }

    logLine("ERROR", "Usage: replay start [period_ms] | replay stop");
    return;
  }

  if (std::strcmp(tokens[0], "dos") == 0 ||
      std::strcmp(tokens[0], "spam") == 0) {
    if (tokenCount == 2 && std::strcmp(tokens[1], "stop") == 0) {
      stopDos();
      return;
    }

    if (tokenCount != 4 || std::strcmp(tokens[1], "start") != 0) {
      logLine("ERROR", "Usage: dos start <id> <period_ms> | dos stop");
      return;
    }

    uint32_t id = 0;
    uint32_t periodMs = kDefaultDosPeriodMs;
    if (!parseUint32Value(tokens[2], 0x1FFFFFFFUL, &id)) {
      logLine("ERROR", "Invalid CAN ID for DoS.");
      return;
    }

    if (!parseUint32Value(tokens[3], 60000U, &periodMs) ||
        periodMs < kMinPeriodMs) {
      logLine("ERROR", "DoS period must be >= %u ms.", kMinPeriodMs);
      return;
    }

    dosTask.active = true;
    dosTask.id = id;
    dosTask.extended = (id > 0x7FFU);
    dosTask.periodMs = static_cast<uint16_t>(periodMs);
    dosTask.nextAtMs = millis();
    logLine("STATE", "DoS attack started.");
    return;
  }

  if (std::strcmp(tokens[0], "fuzz") == 0) {
    if (tokenCount == 2 && std::strcmp(tokens[1], "stop") == 0) {
      stopFuzz();
      return;
    }

    if (tokenCount < 2 || std::strcmp(tokens[1], "start") != 0 ||
        tokenCount > 3) {
      logLine("ERROR", "Usage: fuzz start [period_ms] | fuzz stop");
      return;
    }

    uint32_t periodMs = kDefaultFuzzPeriodMs;
    if (tokenCount == 3 &&
        (!parseUint32Value(tokens[2], 60000U, &periodMs) ||
         periodMs < kMinPeriodMs)) {
      logLine("ERROR", "Fuzz period must be >= %u ms.", kMinPeriodMs);
      return;
    }

    fuzzTask.active = true;
    fuzzTask.periodMs = static_cast<uint16_t>(periodMs);
    fuzzTask.nextAtMs = millis();
    fuzzTask.seed = millis() ^ 0x13579BDFUL;
    logLine("STATE", "Fuzzing attack started.");
    return;
  }

  if (std::strcmp(tokens[0], "spoof") == 0) {
    if (tokenCount == 2 && std::strcmp(tokens[1], "stop") == 0) {
      stopSpoof();
      return;
    }

    if (tokenCount < 6 || std::strcmp(tokens[1], "start") != 0) {
      logLine("ERROR",
              "Usage: spoof start <id> <period_ms> <dlc> <data...> | spoof stop");
      return;
    }

    uint32_t periodMs = 0;
    if (!parseUint32Value(tokens[3], 60000U, &periodMs) ||
        periodMs < kMinPeriodMs) {
      logLine("ERROR", "Spoof period must be >= %u ms.", kMinPeriodMs);
      return;
    }

    CanFrame payloadFrame;
    if (!parsePayloadFrame(tokens, tokenCount, 2, 4, 5, &payloadFrame)) {
      return;
    }

    CanFrame wireFrame;
    char error[96] = {};
    if (!prepareSpoofFrame(payloadFrame, &wireFrame, error, sizeof(error))) {
      logLine("ERROR", "%s", error);
      return;
    }

    spoofTask.active = true;
    spoofTask.frame = wireFrame;
    spoofTask.periodMs = static_cast<uint16_t>(periodMs);
    spoofTask.nextAtMs = millis();
    spoofTask.mutationStep = 0;
    spoofTask.basePayloadDlc = payloadFrame.dlc;
    std::memset(spoofTask.basePayload, 0, sizeof(spoofTask.basePayload));
    if (payloadFrame.dlc > 0) {
      std::memcpy(spoofTask.basePayload, payloadFrame.data, payloadFrame.dlc);
    }
    logLine("STATE", "Spoofing attack started.");
    return;
  }

  (void)sendLegacyText(trimmed, std::strlen(trimmed));
}

void submitInput() {
  if (inputLength == 0) {
    promptDirty = true;
    return;
  }

  char line[kInputBufferCapacity] = {};
  std::memcpy(line, inputBuffer, inputLength);
  line[inputLength] = '\0';
  const bool hadOverflow = inputOverflow;

  clearInput();

  if (hadOverflow) {
    logLine("ERROR", "Input line was truncated.");
  }

  processCommand(line);
  promptDirty = true;
}

void handleSerialInput() {
  while (Serial.available() > 0) {
    const char ch = static_cast<char>(Serial.read());

    if (ch == '\r') {
      continue;
    }

    if (ch == '\n') {
      Serial.println();
      submitInput();
      continue;
    }

    if (ch == '\b' || ch == 127) {
      if (inputLength > 0) {
        --inputLength;
        inputBuffer[inputLength] = '\0';
        Serial.print("\b \b");
      }
      continue;
    }

    if (inputLength + 1 < kInputBufferCapacity) {
      inputBuffer[inputLength++] = ch;
      inputBuffer[inputLength] = '\0';
      Serial.write(ch);
    } else {
      inputOverflow = true;
    }
  }
}

}  // namespace App
