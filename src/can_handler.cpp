#include "can_handler.h"

#include <CAN.h>

#include <cstdio>

#include "app_config.h"
#include "app_state.h"
#include "ids_detector.h"
#include "logger.h"

namespace {

using namespace App;

void setLed(bool on) {
  digitalWrite(LED_BUILTIN, on ? HIGH : LOW);
}

void pulseLed() {
  setLed(true);
  ledOffAt = millis() + kActivityLedOnMs;
}

bool beginCanPacket(const CanFrame& frame) {
  if (frame.extended) {
    return CAN.beginExtendedPacket(static_cast<long>(frame.id), frame.dlc,
                                   frame.rtr) != 0;
  }

  return CAN.beginPacket(static_cast<int>(frame.id), frame.dlc, frame.rtr) != 0;
}

bool isLegacyTextFrame(const CanFrame& frame) {
  return !frame.extended && !frame.rtr && frame.id == kLegacyTextCanId &&
         frame.dlc >= 1;
}

void handleLegacyTextFrame(const CanFrame& frame) {
  const uint8_t flags = frame.data[0];
  const bool finalChunk = (flags & kLegacyFinalChunkFlag) != 0;

  for (uint8_t index = 1; index < frame.dlc; ++index) {
    if (receivedTextLength + 1 < kTextBufferCapacity) {
      receivedText[receivedTextLength++] = static_cast<char>(frame.data[index]);
      receivedText[receivedTextLength] = '\0';
    } else {
      receivedTextOverflow = true;
    }
  }

  if (!finalChunk) {
    return;
  }

  logLine("RX", "legacy-text text=%s%s",
          receivedTextOverflow ? "(truncated) " : "", receivedText);
  clearReceivedText();
}

}  // namespace

namespace App {

bool initCan() {
  pinMode(LED_BUILTIN, OUTPUT);
  setLed(false);

  CAN.setPins(kCanRxPin, kCanTxPin);
  return CAN.begin(kCanBitrate) != 0;
}

void updateLed() {
  if (ledOffAt != 0 && static_cast<int32_t>(millis() - ledOffAt) >= 0) {
    setLed(false);
    ledOffAt = 0;
  }
}

bool prepareProtectedFrame(const CanFrame& payloadFrame, CanFrame* wireFrame,
                           char* error, size_t errorSize) {
  if (!payloadFrame.extended && payloadFrame.id > 0x7FFU) {
    std::snprintf(error, errorSize, "Standard CAN ID must be <= 0x7FF.");
    return false;
  }

  if (payloadFrame.extended && payloadFrame.id > 0x1FFFFFFFUL) {
    std::snprintf(error, errorSize,
                  "Extended CAN ID must be <= 0x1FFFFFFF.");
    return false;
  }

  if (payloadFrame.dlc > kMaxUserDataBytes) {
    std::snprintf(error, errorSize, "Payload length must be <= %u bytes.",
                  kMaxUserDataBytes);
    return false;
  }

  *wireFrame = payloadFrame;
  wireFrame->legacyText = false;

  if (!wireFrame->rtr && ENABLE_COUNTER_PROTECTION) {
    wireFrame->data[payloadFrame.dlc] = nextCounter++;
    wireFrame->dlc = static_cast<uint8_t>(payloadFrame.dlc + 1);
  }

  return true;
}

bool sendWireFrame(const CanFrame& frame, const char* tag, const char* mode) {
  if (!beginCanPacket(frame)) {
    logLine("ERROR", "Failed to allocate CAN packet.");
    return false;
  }

  if (!frame.rtr && frame.dlc > 0) {
    CAN.write(frame.data, frame.dlc);
  }

  if (!CAN.endPacket()) {
    logLine("ERROR", "CAN transmission failed.");
    return false;
  }

  logFrame(tag, mode, frame);
  pulseLed();
  return true;
}

bool sendPayloadFrame(const CanFrame& payloadFrame, const char* tag,
                      const char* mode, bool captureTx) {
  CanFrame wireFrame;
  char error[96] = {};

  if (!prepareProtectedFrame(payloadFrame, &wireFrame, error, sizeof(error))) {
    logLine("ERROR", "%s", error);
    return false;
  }

  if (!sendWireFrame(wireFrame, tag, mode)) {
    return false;
  }

  if (captureTx) {
    captureFrame(wireFrame, CaptureSource::Tx);
  }

  return true;
}

bool sendLegacyText(const char* text, size_t length) {
  if (text == nullptr || length == 0) {
    logLine("ERROR", "Text message is empty.");
    return false;
  }

  size_t offset = 0;
  while (offset < length) {
    const size_t remaining = length - offset;
    const size_t chunkLength =
        remaining < kLegacyChunkDataBytes ? remaining : kLegacyChunkDataBytes;
    const bool finalChunk = (offset + chunkLength) == length;

    if (CAN.beginPacket(static_cast<int>(kLegacyTextCanId),
                        static_cast<int>(chunkLength + 1)) == 0) {
      logLine("ERROR", "Failed to allocate legacy text packet.");
      return false;
    }

    CAN.write(finalChunk ? kLegacyFinalChunkFlag : 0);
    CAN.write(reinterpret_cast<const uint8_t*>(text + offset), chunkLength);

    if (!CAN.endPacket()) {
      logLine("ERROR", "Legacy text transmission failed.");
      return false;
    }

    offset += chunkLength;
    pulseLed();
  }

  logLine("TX", "legacy-text node=%s text=%.*s", kNodeName,
          static_cast<int>(length), text);
  return true;
}

void pollCan() {
  for (uint8_t processed = 0; processed < kCanPollBurstSize; ++processed) {
    const int packetSize = CAN.parsePacket();
    if (packetSize <= 0) {
      return;
    }

    CanFrame frame;
    frame.id = static_cast<uint32_t>(CAN.packetId());
    frame.extended = CAN.packetExtended();
    frame.rtr = CAN.packetRtr();
    frame.dlc = static_cast<uint8_t>(CAN.packetDlc());

    uint8_t bytesRead = 0;
    while (CAN.available() > 0 && bytesRead < kMaxCanDataBytes) {
      frame.data[bytesRead++] = static_cast<uint8_t>(CAN.read());
    }

    while (CAN.available() > 0) {
      (void)CAN.read();
    }

    frame.legacyText = isLegacyTextFrame(frame);

    if (frame.legacyText) {
      handleLegacyTextFrame(frame);
      pulseLed();
      continue;
    }

    if (shouldDropByDefense(frame)) {
      pulseLed();
      continue;
    }

    logFrame("RX", "bus", frame);
    inspectFrame(frame);
    captureFrame(frame, CaptureSource::Rx);
    pulseLed();
  }
}

}  // namespace App
