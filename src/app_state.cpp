#include "app_state.h"

#include <cstring>

namespace App {

char inputBuffer[kInputBufferCapacity] = {};
size_t inputLength = 0;
bool inputOverflow = false;
bool promptDirty = true;
bool verboseLogging = true;

char receivedText[kTextBufferCapacity] = {};
size_t receivedTextLength = 0;
bool receivedTextOverflow = false;

uint32_t ledOffAt = 0;
uint8_t nextCounter = 0;

CapturedFrame lastCapturedFrame;
AlertRecord lastAlert;
RepeatTask repeatTask;
ReplayTask replayTask;
DosTask dosTask;
FuzzTask fuzzTask;
SpoofTask spoofTask;
FrameTracker trackers[kTrackerCapacity];
TrafficTracker trafficTracker;
DefenseEntry defenseEntries[kTrackerCapacity];
DefenseGuard defenseGuard;

void captureFrame(const CanFrame& frame, CaptureSource source) {
  lastCapturedFrame.available = true;
  lastCapturedFrame.frame = frame;
  lastCapturedFrame.source = source;
  lastCapturedFrame.atMs = millis();
}

void clearInput() {
  inputLength = 0;
  inputOverflow = false;
  inputBuffer[0] = '\0';
}

void clearReceivedText() {
  receivedTextLength = 0;
  receivedTextOverflow = false;
  receivedText[0] = '\0';
}

}  // namespace App
