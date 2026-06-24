#pragma once

#include <Arduino.h>

namespace App {

struct CanFrame {
  uint32_t id = 0;
  uint8_t data[8] = {};
  uint8_t dlc = 0;
  bool extended = false;
  bool rtr = false;
  bool legacyText = false;
};

enum class CaptureSource : uint8_t {
  None,
  Rx,
  Tx,
};

enum class AlertType : uint8_t {
  None,
  ReplayCounter,
  ReplayDuplicate,
  Dos,
  Fuzzing,
  Spoofing,
  MlAnomaly,
};

struct CapturedFrame {
  bool available = false;
  CanFrame frame{};
  CaptureSource source = CaptureSource::None;
  uint32_t atMs = 0;
};

struct AlertRecord {
  bool available = false;
  uint32_t id = 0;
  bool extended = false;
  AlertType type = AlertType::None;
  CanFrame frame{};
  uint32_t atMs = 0;
};

struct RepeatTask {
  bool active = false;
  CanFrame payload{};
  uint16_t periodMs = 0;
  uint32_t nextAtMs = 0;
};

struct ReplayTask {
  bool active = false;
  CanFrame frame{};
  uint16_t periodMs = 0;
  uint32_t nextAtMs = 0;
};

struct DosTask {
  bool active = false;
  uint32_t id = 0;
  bool extended = false;
  uint16_t periodMs = 0;
  uint32_t nextAtMs = 0;
};

struct FuzzTask {
  bool active = false;
  uint16_t periodMs = 0;
  uint32_t nextAtMs = 0;
  uint32_t seed = 0;
};

struct SpoofTask {
  bool active = false;
  CanFrame frame{};
  uint16_t periodMs = 0;
  uint32_t nextAtMs = 0;
  uint8_t mutationStep = 0;
  uint8_t basePayload[8] = {};
  uint8_t basePayloadDlc = 0;
};

struct FrameTracker {
  bool used = false;
  uint32_t id = 0;
  bool extended = false;
  uint8_t lastData[8] = {};
  uint8_t lastDlc = 0;
  bool hasLastFrame = false;
  uint8_t repeatedCount = 0;
  uint32_t duplicateWindowStart = 0;
  bool duplicateAlerted = false;
  uint16_t frameCount = 0;
  uint32_t dosWindowStart = 0;
  bool dosAlerted = false;
  bool hasCounter = false;
  uint8_t lastCounter = 0;
  uint8_t baselineData[8] = {};
  uint8_t baselineDlc = 0;
  uint8_t baselineSamples = 0;
  bool baselineReady = false;
  bool spoofAlerted = false;
  int8_t lastMlPrediction = -1;
  uint32_t lastMlAlertAt = 0;
  uint32_t lastSeenAt = 0;
  uint8_t seenCount = 0;
  uint32_t firstSeenAt = 0;
};

struct TrafficTracker {
  uint32_t windowStart = 0;
  uint16_t frameCount = 0;
  uint16_t newIdCount = 0;
  uint16_t idChanges = 0;
  uint32_t lastId = 0;
  bool lastIdExtended = false;
  bool hasLastId = false;
  bool fuzzAlerted = false;
};

struct DefenseEntry {
  bool active = false;
  uint32_t id = 0;
  bool extended = false;
  AlertType reason = AlertType::None;
  bool hasSignature = false;
  CanFrame signature{};
  bool hasSpoofBaseline = false;
  uint8_t spoofBaselineData[8] = {};
  uint8_t spoofBaselineDlc = 0;
  uint32_t blockedUntilMs = 0;
  uint32_t lastDropLogAtMs = 0;
};

struct DefenseGuard {
  bool active = false;
  AlertType reason = AlertType::None;
  uint32_t untilMs = 0;
  uint32_t activatedAtMs = 0;
  uint32_t lastAcceptedAtMs = 0;
  uint32_t lastDropLogAtMs = 0;
};

}  // namespace App
