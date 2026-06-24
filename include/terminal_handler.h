#pragma once

namespace App {

void printBootBanner();
void servicePrompt();
void printHelp();
void printStatus();
void processCommand(char* line);
void submitInput();
void handleSerialInput();

}  // namespace App
