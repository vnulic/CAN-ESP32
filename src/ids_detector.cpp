#include "ids_detector.h"

#include <cstring>

#include "app_config.h"
#include "app_state.h"
#include "can_handler.h"
#include "logger.h"
#include "ml_model.h"

namespace {

using namespace App;

FrameTracker* lookupTracker(uint32_t id, bool extended) {
  for (size_t index = 0; index < kTrackerCapacity; ++index) {
    FrameTracker& tracker = trackers[index];
    if (tracker.used && tracker.id == id && tracker.extended == extended) {
      return &tracker;
    }
  }

  return nullptr;
}

FrameTracker* findTracker(uint32_t id, bool extended) {
  FrameTracker* freeSlot = nullptr;
  FrameTracker* oldestSlot = &trackers[0];

  for (size_t index = 0; index < kTrackerCapacity; ++index) {
    FrameTracker& tracker = trackers[index];

    if (tracker.used && tracker.id == id && tracker.extended == extended) {
      return &tracker;
    }

    if (!tracker.used && freeSlot == nullptr) {
      freeSlot = &tracker;
    }

    if (!tracker.used) {
      continue;
    }

    if (tracker.lastSeenAt < oldestSlot->lastSeenAt) {
      oldestSlot = &tracker;
    }
  }

  return (freeSlot != nullptr) ? freeSlot : oldestSlot;
}

void resetTracker(FrameTracker* tracker, uint32_t id, bool extended) {
  std::memset(tracker, 0, sizeof(*tracker));
  tracker->used = true;
  tracker->id = id;
  tracker->extended = extended;
  tracker->lastMlPrediction = -1;
}

DefenseEntry* findDefenseEntry(uint32_t id, bool extended) {
  for (size_t index = 0; index < kTrackerCapacity; ++index) {
    DefenseEntry& entry = defenseEntries[index];
    if (entry.active && entry.id == id && entry.extended == extended) {
      return &entry;
    }
  }

  return nullptr;
}

DefenseEntry* allocateDefenseEntry() {
  DefenseEntry* freeSlot = nullptr;
  DefenseEntry* oldestSlot = &defenseEntries[0];

  for (size_t index = 0; index < kTrackerCapacity; ++index) {
    DefenseEntry& entry = defenseEntries[index];

    if (!entry.active && freeSlot == nullptr) {
      freeSlot = &entry;
    }

    if (entry.blockedUntilMs < oldestSlot->blockedUntilMs) {
      oldestSlot = &entry;
    }
  }

  return (freeSlot != nullptr) ? freeSlot : oldestSlot;
}

void logDefenseDrop(const CanFrame& frame, AlertType reason,
                    uint32_t* lastDropLogAtMs) {
  const uint32_t now = millis();
  if (lastDropLogAtMs != nullptr &&
      *lastDropLogAtMs != 0 &&
      (now - *lastDropLogAtMs) < kDefenseDropLogPeriodMs) {
    return;
  }

  if (lastDropLogAtMs != nullptr) {
    *lastDropLogAtMs = now;
  }

  logLine("DEFENSE", "Dropped frame: reason=%s ID=0x%0*lX",
          alertTypeName(reason), frame.extended ? 8 : 3,
          static_cast<unsigned long>(frame.id));
}

bool shouldDropByFuzzGuard(const CanFrame& frame, uint32_t now) {
  if (!defenseGuard.active || defenseGuard.reason != AlertType::Fuzzing) {
    return false;
  }

  FrameTracker* tracker = lookupTracker(frame.id, frame.extended);
  if (tracker == nullptr || tracker->seenCount < kDefenseTrustedSeenCount) {
    logDefenseDrop(frame, AlertType::Fuzzing, &defenseGuard.lastDropLogAtMs);
    return true;
  }

  if (tracker->firstSeenAt == 0 ||
      (tracker->firstSeenAt + kDefenseTrustedAgeMs) >=
          defenseGuard.activatedAtMs) {
    logDefenseDrop(frame, AlertType::Fuzzing, &defenseGuard.lastDropLogAtMs);
    return true;
  }

  if (defenseGuard.lastAcceptedAtMs != 0 &&
      (now - defenseGuard.lastAcceptedAtMs) < kDefenseFuzzMinGapMs) {
    logDefenseDrop(frame, AlertType::Fuzzing, &defenseGuard.lastDropLogAtMs);
    return true;
  }

  defenseGuard.lastAcceptedAtMs = now;
  return false;
}

uint8_t effectivePayloadLength(const CanFrame& frame) {
  if (ENABLE_COUNTER_PROTECTION && !frame.legacyText && !frame.rtr &&
      frame.dlc > 0) {
    return static_cast<uint8_t>(frame.dlc - 1);
  }

  return frame.dlc;
}

uint8_t changedByteCount(const uint8_t* left, const uint8_t* right,
                        uint8_t length) {
  uint8_t changed = 0;
  for (uint8_t index = 0; index < length; ++index) {
    if (left[index] != right[index]) {
      ++changed;
    }
  }

  return changed;
}

uint8_t spoofRequiredChangedBytes(uint8_t baselineDlc, uint8_t observedDlc) {
  return (baselineDlc <= 2 && observedDlc <= 2) ? 1
                                                 : kSpoofChangedByteThreshold;
}

bool isSpoofPayloadSuspicious(const uint8_t* baselineData,
                              uint8_t baselineDlc,
                              const CanFrame& frame,
                              uint8_t* changedOut = nullptr,
                              uint8_t* payloadLengthOut = nullptr) {
  const uint8_t payloadLength = effectivePayloadLength(frame);
  const uint8_t compareLength =
      (baselineDlc < payloadLength) ? baselineDlc : payloadLength;
  const uint8_t changed =
      changedByteCount(baselineData, frame.data, compareLength) +
      (payloadLength == baselineDlc ? 0 : 1);

  if (changedOut != nullptr) {
    *changedOut = changed;
  }

  if (payloadLengthOut != nullptr) {
    *payloadLengthOut = payloadLength;
  }

  return payloadLength != baselineDlc ||
         changed >= spoofRequiredChangedBytes(baselineDlc, payloadLength);
}

bool framesMatchSignature(const CanFrame& left, const CanFrame& right) {
  if (left.id != right.id || left.extended != right.extended ||
      left.rtr != right.rtr || left.dlc != right.dlc) {
    return false;
  }

  if (left.dlc == 0) {
    return true;
  }

  return std::memcmp(left.data, right.data, left.dlc) == 0;
}

void resetSequenceState(FrameTracker* tracker) {
  tracker->hasLastFrame = false;
  std::memset(tracker->lastData, 0, sizeof(tracker->lastData));
  tracker->lastDlc = 0;
  tracker->repeatedCount = 0;
  tracker->duplicateWindowStart = 0;
  tracker->duplicateAlerted = false;
  tracker->hasCounter = false;
  tracker->lastCounter = 0;
  std::memset(tracker->baselineData, 0, sizeof(tracker->baselineData));
  tracker->baselineDlc = 0;
  tracker->baselineSamples = 0;
  tracker->baselineReady = false;
  tracker->spoofAlerted = false;
}

bool updateTrafficTracker(const CanFrame& frame, bool newIdInWindow) {
  const uint32_t now = millis();
  if (trafficTracker.windowStart == 0 ||
      (now - trafficTracker.windowStart) > kFuzzWindowMs) {
    trafficTracker.windowStart = now;
    trafficTracker.frameCount = 0;
    trafficTracker.newIdCount = 0;
    trafficTracker.idChanges = 0;
    trafficTracker.fuzzAlerted = false;
    trafficTracker.hasLastId = false;
  }

  ++trafficTracker.frameCount;
  if (newIdInWindow) {
    ++trafficTracker.newIdCount;
  }

  if (trafficTracker.hasLastId &&
      (trafficTracker.lastId != frame.id ||
       trafficTracker.lastIdExtended != frame.extended)) {
    ++trafficTracker.idChanges;
  }

  trafficTracker.lastId = frame.id;
  trafficTracker.lastIdExtended = frame.extended;
  trafficTracker.hasLastId = true;

  if (!trafficTracker.fuzzAlerted &&
      trafficTracker.frameCount >= kFuzzMinFrameCount &&
      trafficTracker.newIdCount >= kFuzzUniqueIdThreshold &&
      trafficTracker.idChanges >= kFuzzIdChangeThreshold) {
    rememberAlert(frame, AlertType::Fuzzing);
    logLine("ALERT",
            "FUZZING suspected: unique_ids=%u id_switches=%u window=%lums",
            trafficTracker.newIdCount, trafficTracker.idChanges,
            static_cast<unsigned long>(now - trafficTracker.windowStart));
    trafficTracker.fuzzAlerted = true;
    return true;
  }

  return false;
}

bool updateSpoofBaseline(FrameTracker* tracker, const CanFrame& frame) {
  const uint8_t payloadLength = effectivePayloadLength(frame);
  if (payloadLength == 0) {
    return false;
  }

  if (!tracker->baselineReady) {
    if (tracker->baselineSamples == 0) {
      std::memcpy(tracker->baselineData, frame.data, payloadLength);
      tracker->baselineDlc = payloadLength;
      tracker->baselineSamples = 1;
      tracker->baselineReady =
          tracker->baselineSamples >= kSpoofBaselineMinSamples;
      return false;
    }

    const uint8_t compareLength =
        (tracker->baselineDlc < payloadLength) ? tracker->baselineDlc
                                               : payloadLength;
    const uint8_t changed =
        changedByteCount(tracker->baselineData, frame.data, compareLength);

    if (payloadLength == tracker->baselineDlc &&
        changed <= kSpoofBaselineTolerance) {
      if (tracker->baselineSamples < 0xFFU) {
        ++tracker->baselineSamples;
      }
    } else {
      std::memcpy(tracker->baselineData, frame.data, payloadLength);
      tracker->baselineDlc = payloadLength;
      tracker->baselineSamples = 1;
    }

    if (tracker->baselineSamples >= kSpoofBaselineMinSamples) {
      tracker->baselineReady = true;
    }

    return false;
  }

  uint8_t changed = 0;
  const bool suspicious = isSpoofPayloadSuspicious(
      tracker->baselineData, tracker->baselineDlc, frame, &changed);

  if (!tracker->spoofAlerted && suspicious) {
    rememberAlert(frame, AlertType::Spoofing);
    logLine("ALERT",
            "SPOOFING suspected: ID=0x%0*lX changed_bytes=%u baseline_dlc=%u observed_dlc=%u",
            frame.extended ? 8 : 3, static_cast<unsigned long>(frame.id),
            changed, tracker->baselineDlc, payloadLength);
    tracker->spoofAlerted = true;
    return true;
  }

  if (payloadLength == tracker->baselineDlc &&
      changed <= kSpoofBaselineTolerance) {
    tracker->spoofAlerted = false;
  }

  return false;
}

void runMlDetection(FrameTracker* tracker, const CanFrame& frame,
                    bool updateLastAlert) {
  if (!kEnableMlDetection) {
    tracker->lastMlPrediction = -1;
    tracker->lastMlAlertAt = 0;
    return;
  }

  static Eloquent::ML::Port::RandomForest mlModel;

  float features[10] = {
      static_cast<float>(frame.id),       static_cast<float>(frame.dlc),
      static_cast<float>(frame.data[0]),  static_cast<float>(frame.data[1]),
      static_cast<float>(frame.data[2]),  static_cast<float>(frame.data[3]),
      static_cast<float>(frame.data[4]),  static_cast<float>(frame.data[5]),
      static_cast<float>(frame.data[6]),  static_cast<float>(frame.data[7]),
  };

  const int prediction = mlModel.predict(features);
  if (prediction == 2) {
    tracker->lastMlPrediction = -1;
    return;
  }

  const uint32_t now = millis();
  if (tracker->lastMlPrediction == prediction &&
      (now - tracker->lastMlAlertAt) < kMlAlertCooldownMs) {
    return;
  }

  const char* predictedType = "Unknown";
  AlertType mappedType = AlertType::MlAnomaly;
  if (prediction == 0) {
    predictedType = "DoS";
    mappedType = AlertType::Dos;
  } else if (prediction == 1) {
    predictedType = "Fuzzing";
    mappedType = AlertType::Fuzzing;
  } else if (prediction == 3) {
    predictedType = "Spoofing";
    mappedType = AlertType::Spoofing;
  }

  if (updateLastAlert) {
    rememberAlert(frame, mappedType);
  }
  logLine("ALERT", "ML ANOMALY suspected: ID=0x%0*lX type=%s",
          frame.extended ? 8 : 3, static_cast<unsigned long>(frame.id),
          predictedType);
  tracker->lastMlPrediction = static_cast<int8_t>(prediction);
  tracker->lastMlAlertAt = now;
}

}  // namespace

namespace App {

const char* alertTypeName(AlertType type) {
  switch (type) {
    case AlertType::ReplayCounter:
      return "replay-counter";
    case AlertType::ReplayDuplicate:
      return "replay-duplicate";
    case AlertType::Dos:
      return "dos";
    case AlertType::Fuzzing:
      return "fuzzing";
    case AlertType::Spoofing:
      return "spoofing";
    case AlertType::MlAnomaly:
      return "ml-anomaly";
    default:
      return "none";
  }
}

void rememberAlert(const CanFrame& frame, AlertType type) {
  lastAlert.available = true;
  lastAlert.id = frame.id;
  lastAlert.extended = frame.extended;
  lastAlert.type = type;
  lastAlert.frame = frame;
  lastAlert.atMs = millis();
}

bool prepareSpoofFrame(const CanFrame& payloadFrame, CanFrame* wireFrame,
                       char* error, size_t errorSize) {
  if (!prepareProtectedFrame(payloadFrame, wireFrame, error, errorSize)) {
    return false;
  }

  if (!ENABLE_COUNTER_PROTECTION || wireFrame->rtr ||
      payloadFrame.dlc >= kMaxCanDataBytes || wireFrame->dlc == 0) {
    return true;
  }

  FrameTracker* tracker = lookupTracker(payloadFrame.id, payloadFrame.extended);
  if (tracker != nullptr && tracker->hasCounter) {
    wireFrame->data[payloadFrame.dlc] =
        static_cast<uint8_t>(tracker->lastCounter + 1);
    wireFrame->dlc = static_cast<uint8_t>(payloadFrame.dlc + 1);
    return true;
  }

  if (lastCapturedFrame.available &&
      lastCapturedFrame.frame.id == payloadFrame.id &&
      lastCapturedFrame.frame.extended == payloadFrame.extended &&
      !lastCapturedFrame.frame.rtr &&
      lastCapturedFrame.frame.dlc >= static_cast<uint8_t>(payloadFrame.dlc + 1)) {
    wireFrame->data[payloadFrame.dlc] = static_cast<uint8_t>(
        lastCapturedFrame.frame.data[lastCapturedFrame.frame.dlc - 1] + 1);
    wireFrame->dlc = static_cast<uint8_t>(payloadFrame.dlc + 1);
  }

  return true;
}

void clearExpiredDefenseEntries() {
  const uint32_t now = millis();
  if (defenseGuard.active &&
      static_cast<int32_t>(now - defenseGuard.untilMs) >= 0) {
    defenseGuard.active = false;
    defenseGuard.reason = AlertType::None;
    defenseGuard.untilMs = 0;
    defenseGuard.activatedAtMs = 0;
    defenseGuard.lastAcceptedAtMs = 0;
    defenseGuard.lastDropLogAtMs = 0;
  }

  for (size_t index = 0; index < kTrackerCapacity; ++index) {
    DefenseEntry& entry = defenseEntries[index];
    if (entry.active &&
        static_cast<int32_t>(now - entry.blockedUntilMs) >= 0) {
      entry.active = false;
    }
  }
}

void clearAllDefenseEntries() {
  std::memset(defenseEntries, 0, sizeof(defenseEntries));
  defenseGuard.active = false;
  defenseGuard.reason = AlertType::None;
  defenseGuard.untilMs = 0;
  defenseGuard.activatedAtMs = 0;
  defenseGuard.lastAcceptedAtMs = 0;
  defenseGuard.lastDropLogAtMs = 0;
}

uint8_t activeDefenseCount() {
  uint8_t count = 0;
  for (size_t index = 0; index < kTrackerCapacity; ++index) {
    if (defenseEntries[index].active) {
      ++count;
    }
  }

  return count;
}

bool activateDefenseForLastAlert(uint32_t durationMs) {
  if (!lastAlert.available) {
    logLine("ERROR", "No alert has been recorded yet.");
    return false;
  }

  clearExpiredDefenseEntries();
  const uint32_t activatedAtMs = millis();
  defenseGuard.active = false;
  defenseGuard.reason = AlertType::None;
  defenseGuard.untilMs = 0;
  defenseGuard.activatedAtMs = 0;
  defenseGuard.lastAcceptedAtMs = 0;
  defenseGuard.lastDropLogAtMs = 0;

  AlertType effectiveType = lastAlert.type;
  if (trafficTracker.fuzzAlerted &&
      (activatedAtMs - trafficTracker.windowStart) <= kFuzzWindowMs) {
    effectiveType = AlertType::Fuzzing;
  }

  DefenseEntry* entry = findDefenseEntry(lastAlert.id, lastAlert.extended);
  if (entry == nullptr) {
    entry = allocateDefenseEntry();
  }

  entry->active = true;
  entry->id = lastAlert.id;
  entry->extended = lastAlert.extended;
  entry->reason = effectiveType;
  entry->hasSignature =
      effectiveType == AlertType::ReplayCounter ||
      effectiveType == AlertType::ReplayDuplicate;
  if (entry->hasSignature) {
    entry->signature = lastAlert.frame;
  } else {
    std::memset(&entry->signature, 0, sizeof(entry->signature));
  }
  entry->hasSpoofBaseline = false;
  std::memset(entry->spoofBaselineData, 0, sizeof(entry->spoofBaselineData));
  entry->spoofBaselineDlc = 0;
  entry->lastDropLogAtMs = 0;

  if (effectiveType == AlertType::Spoofing) {
    FrameTracker* tracker = lookupTracker(lastAlert.id, lastAlert.extended);
    if (tracker != nullptr && tracker->baselineReady && tracker->baselineDlc > 0) {
      entry->hasSpoofBaseline = true;
      entry->spoofBaselineDlc = tracker->baselineDlc;
      std::memcpy(entry->spoofBaselineData, tracker->baselineData,
                  tracker->baselineDlc);
    }
  }
  entry->blockedUntilMs = activatedAtMs + durationMs;

  if (effectiveType == AlertType::Fuzzing) {
    defenseGuard.active = true;
    defenseGuard.reason = AlertType::Fuzzing;
    defenseGuard.untilMs = activatedAtMs + durationMs;
    defenseGuard.activatedAtMs = activatedAtMs;
    defenseGuard.lastAcceptedAtMs = 0;
    defenseGuard.lastDropLogAtMs = 0;
  }

  logLine("DEFENSE", "Activated for ID=0x%0*lX reason=%s duration=%lums",
          lastAlert.extended ? 8 : 3,
          static_cast<unsigned long>(lastAlert.id),
          alertTypeName(effectiveType),
          static_cast<unsigned long>(durationMs));
  return true;
}

bool shouldDropByDefense(const CanFrame& frame) {
  clearExpiredDefenseEntries();
  const uint32_t now = millis();

  if (shouldDropByFuzzGuard(frame, now)) {
    return true;
  }

  DefenseEntry* entry = findDefenseEntry(frame.id, frame.extended);
  if (entry == nullptr) {
    return false;
  }

  if (!entry->hasSignature) {
    if (entry->reason == AlertType::Spoofing && entry->hasSpoofBaseline) {
      const bool drop = isSpoofPayloadSuspicious(entry->spoofBaselineData,
                                                 entry->spoofBaselineDlc, frame);
      if (drop) {
        logDefenseDrop(frame, entry->reason, &entry->lastDropLogAtMs);
      }
      return drop;
    }
    logDefenseDrop(frame, entry->reason, &entry->lastDropLogAtMs);
    return true;
  }

  if (entry->hasSignature && framesMatchSignature(frame, entry->signature)) {
    logDefenseDrop(frame, entry->reason, &entry->lastDropLogAtMs);
    return true;
  }

  return false;
}

void inspectFrame(const CanFrame& frame) {
  if (frame.rtr) {
    return;
  }

  bool heuristicAlerted = false;

  FrameTracker* tracker = findTracker(frame.id, frame.extended);
  const bool matchedExisting =
      tracker->used && tracker->id == frame.id && tracker->extended == frame.extended;
  const bool newIdInWindow = !matchedExisting;

  if (!matchedExisting) {
    resetTracker(tracker, frame.id, frame.extended);
  }

  heuristicAlerted = updateTrafficTracker(frame, newIdInWindow) || heuristicAlerted;

  const uint32_t now = millis();
  tracker->lastSeenAt = now;
  if (tracker->firstSeenAt == 0) {
    tracker->firstSeenAt = now;
  }
  if (tracker->seenCount < 0xFFU) {
    ++tracker->seenCount;
  }

  if (tracker->dosWindowStart == 0 ||
      (now - tracker->dosWindowStart) > kDosWindowMs) {
    tracker->dosWindowStart = now;
    tracker->frameCount = 0;
    tracker->dosAlerted = false;
  }

  ++tracker->frameCount;
  const uint32_t elapsedDos = (now - tracker->dosWindowStart) + 1;
  const uint16_t rateFps = static_cast<uint16_t>(
      (static_cast<uint32_t>(tracker->frameCount) * 1000UL) / elapsedDos);

  if (!tracker->dosAlerted &&
      tracker->frameCount >= kDosMinSampleCount &&
      rateFps > kDosThresholdFps) {
    rememberAlert(frame, AlertType::Dos);
    logLine("ALERT",
            "DoS suspected: ID=0x%0*lX rate=%u fps window=%lums",
            frame.extended ? 8 : 3, static_cast<unsigned long>(frame.id),
            rateFps, static_cast<unsigned long>(elapsedDos));
    tracker->dosAlerted = true;
    resetSequenceState(tracker);
    heuristicAlerted = true;
  }

  const bool suppressFrameSpecificChecks =
      tracker->dosAlerted || trafficTracker.fuzzAlerted;
  if (!suppressFrameSpecificChecks) {
    const bool samePayload =
        tracker->hasLastFrame && tracker->lastDlc == frame.dlc &&
        std::memcmp(tracker->lastData, frame.data, frame.dlc) == 0;

    if (!samePayload || tracker->duplicateWindowStart == 0 ||
        (now - tracker->duplicateWindowStart) > kDuplicateWindowMs) {
      tracker->duplicateWindowStart = now;
      tracker->repeatedCount = 1;
      tracker->duplicateAlerted = false;
    } else {
      ++tracker->repeatedCount;
    }

    if (!tracker->duplicateAlerted &&
        tracker->repeatedCount >= kDuplicateThreshold) {
      rememberAlert(frame, AlertType::ReplayDuplicate);
      logLine("ALERT",
              "REPLAY suspected: ID=0x%0*lX repeated=%u window=%lums",
              frame.extended ? 8 : 3, static_cast<unsigned long>(frame.id),
              tracker->repeatedCount,
              static_cast<unsigned long>(kDuplicateWindowMs));
      tracker->duplicateAlerted = true;
      heuristicAlerted = true;
    }

    if (ENABLE_COUNTER_PROTECTION && !frame.legacyText && frame.dlc > 0) {
      const uint8_t observedCounter = frame.data[frame.dlc - 1];
      if (tracker->hasCounter) {
        const uint8_t expectedCounter =
            static_cast<uint8_t>(tracker->lastCounter + 1);
        if (observedCounter != expectedCounter) {
          rememberAlert(frame, AlertType::ReplayCounter);
          logLine(
              "ALERT",
              "REPLAY suspected: ID=0x%0*lX expected_counter=0x%02X observed_counter=0x%02X",
              frame.extended ? 8 : 3, static_cast<unsigned long>(frame.id),
              expectedCounter, observedCounter);
          heuristicAlerted = true;
        }
      }

      tracker->lastCounter = observedCounter;
      tracker->hasCounter = true;
    }

    heuristicAlerted = updateSpoofBaseline(tracker, frame) || heuristicAlerted;

    std::memcpy(tracker->lastData, frame.data, sizeof(tracker->lastData));
    tracker->lastDlc = frame.dlc;
    tracker->hasLastFrame = true;
  }

  runMlDetection(tracker, frame,
                 !heuristicAlerted && !suppressFrameSpecificChecks);
}

}  // namespace App
