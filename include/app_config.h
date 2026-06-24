#pragma once

#include <Arduino.h>

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

#ifndef APP_NODE_NAME
#define APP_NODE_NAME "ESP32-NODE"
#endif

#ifndef ENABLE_COUNTER_PROTECTION
#define ENABLE_COUNTER_PROTECTION 1
#endif

namespace App {

constexpr const char* kNodeName = APP_NODE_NAME;
constexpr long kCanBitrate = 500E3;
constexpr int kCanRxPin = 27;
constexpr int kCanTxPin = 26;

constexpr uint32_t kLegacyTextCanId = 0x12;
constexpr uint8_t kLegacyFinalChunkFlag = 0x80;
constexpr size_t kLegacyChunkDataBytes = 7;

constexpr size_t kInputBufferCapacity = 128;
constexpr size_t kTextBufferCapacity = 96;
constexpr uint8_t kMaxCanDataBytes = 8;
constexpr uint8_t kMaxUserDataBytes =
    ENABLE_COUNTER_PROTECTION ? 7 : 8;

constexpr uint32_t kActivityLedOnMs = 50;
constexpr uint8_t kCanPollBurstSize = 4;
constexpr uint16_t kMinPeriodMs = 10;
constexpr uint16_t kDefaultReplayPeriodMs = 250;
constexpr uint16_t kDefaultDosPeriodMs = 20;
constexpr uint16_t kDefaultFuzzPeriodMs = 35;
constexpr uint16_t kDefaultSpoofPeriodMs = 120;

constexpr uint32_t kDuplicateWindowMs = 1000;
constexpr uint8_t kDuplicateThreshold = 5;
constexpr uint32_t kDosWindowMs = 1000;
constexpr uint16_t kDosThresholdFps = 60;
constexpr uint8_t kDosMinSampleCount = 3;
constexpr uint32_t kFuzzWindowMs = 1200;
constexpr uint8_t kFuzzMinFrameCount = 6;
constexpr uint8_t kFuzzUniqueIdThreshold = 4;
constexpr uint8_t kFuzzIdChangeThreshold = 5;
constexpr uint8_t kSpoofBaselineMinSamples = 1;
constexpr uint8_t kSpoofChangedByteThreshold = 2;
constexpr uint8_t kSpoofBaselineTolerance = 1;
constexpr bool kEnableMlDetection = false;
constexpr uint32_t kMlAlertCooldownMs = 1200;
constexpr uint32_t kDefenseBlockDefaultMs = 10000;
constexpr uint32_t kDefenseDropLogPeriodMs = 1000;
constexpr uint8_t kDefenseTrustedSeenCount = 2;
constexpr uint16_t kDefenseFuzzMinGapMs = 100;
constexpr uint16_t kDefenseTrustedAgeMs = 500;
constexpr size_t kTrackerCapacity = 16;

}  // namespace App
