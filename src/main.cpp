#include <Arduino.h>

#include "app_config.h"
#include "attack_simulator.h"
#include "can_handler.h"
#include "logger.h"
#include "terminal_handler.h"

void setup() {
  Serial.begin(115200);
  delay(300);

  App::printBootBanner();

  if (!App::initCan()) {
    App::logLine("ERROR", "Starting CAN failed.");
    while (true) {
      App::updateLed();
      delay(10);
    }
  }

  App::logInfo("CAN controller ready.");
}

void loop() {
  App::handleSerialInput();
  App::pollCan();
  App::handleSerialInput();
  App::updateTasks();
  App::updateLed();
  App::servicePrompt();
}
