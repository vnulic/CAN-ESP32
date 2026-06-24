#pragma once

#include "app_config.h"
#include "app_types.h"

namespace App {

extern char inputBuffer[kInputBufferCapacity];
extern size_t inputLength;
extern bool inputOverflow;
extern bool promptDirty;
extern bool verboseLogging;

extern char receivedText[kTextBufferCapacity];
extern size_t receivedTextLength;
extern bool receivedTextOverflow;

extern uint32_t ledOffAt;
extern uint8_t nextCounter;

extern CapturedFrame lastCapturedFrame;
extern AlertRecord lastAlert;
extern RepeatTask repeatTask;
extern ReplayTask replayTask;
extern DosTask dosTask;
extern FuzzTask fuzzTask;
extern SpoofTask spoofTask;
extern FrameTracker trackers[kTrackerCapacity];
extern TrafficTracker trafficTracker;
extern DefenseEntry defenseEntries[kTrackerCapacity];
extern DefenseGuard defenseGuard;

void captureFrame(const CanFrame& frame, CaptureSource source);
void clearInput();
void clearReceivedText();

}  // namespace App
