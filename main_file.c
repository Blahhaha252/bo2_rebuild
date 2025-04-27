#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <direct.h>
#include "globals.h"

// Steam function declaration
__declspec(dllimport) char __cdecl SteamAPI_RestartAppIfNecessary(int appId);

// function remaps 
//FUN_005dce00 -> main               |  (this_file)
//  FUN_004168c0 ->pre_steam_checks  |  (steam_validation.c)

void _exit(int);
void fast_error_exit(int);


// ######### Main code so far ##########//

int main(void) {
  char cVar1;
  HMODULE hModule;
  FARPROC pSetProcessDPIAware;
  int systemMetric;
  char currentDir[256];

  // Load user32.dll and make process DPI aware if possible
  hModule = LoadLibraryA("user32.dll");
  if (hModule != NULL) {
      pSetProcessDPIAware = GetProcAddress(hModule, "SetProcessDPIAware");
      if (pSetProcessDPIAware != NULL) {
          ((void (*)())pSetProcessDPIAware)();
      }
      FreeLibrary(hModule);
  }

  // Custom startup check
  cVar1 = pre_steam_checks(); //FUN_004168c0
  if (cVar1 != 0) {
      // Set crash handler
      SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_0043b560);

      // Early initialization
      FUN_004e9ff0();
      FUN_0044c150();
      DAT_02b43200 = 0;
      FUN_0064c050();
      FUN_00591710();
      FUN_007343e0(1);
      FUN_007343f0(1);
      FUN_004b8420(1);

      // Sound and Shield setup
      cVar1 = FUN_00682770();
      if (cVar1 == 0) {
          systemMetric = GetSystemMetrics(0x1000);
          if (systemMetric == 0) {
              if (FUN_00449d00(param_3, "nosnd") != 0) {
                  DAT_02b43214 = 1;
              } else if (FUN_00449d00(param_3, "shield") != 0) {
                  DAT_02b43215 = 1;
              }
          } else {
              DAT_02b43214 = 1;
          }
      } else {
          DAT_02b43214 = 1;
      }

      // Main initialization
      if (param_2 == 0) {
          FUN_00548320();
          FUN_00623020();
          FUN_0068a390();
          FUN_008d6d00();
          DAT_02b4468c = param_1;
          FUN_008d6f80();
          SetErrorMode(1);
          FUN_006f99b0();
          FUN_00591560();
          FUN_004456e0(0x900000);
          FUN_00683140();
          FUN_00564d60();
          FUN_0045f5e0(4, 1);
          FUN_005999c0();
          FUN_00471490();
          FUN_00552410();
          FUN_008d7000();
          FUN_005ae120(&DAT_00c26ac5, 0);
          FUN_00471490();

          // Set working directory and focus
          __getcwd(currentDir, sizeof(currentDir));
          SetFocus(DAT_02b44688);

          // Main loop
          while (1) {
              if (DAT_02b44694 == 0) {
                  if (FUN_006a74c0(DAT_02538ac0)) {
                      Sleep(5);
                      continue;
                  }
              }
              Sleep(5);

              if (DAT_02b43200 != 0) {
                  cVar1 = FUN_004ca6d0();
                  if (cVar1 != 0) {
                      if (DAT_02b42200 != 0) {
                          FUN_00449380(&DAT_02b42200);
                          FUN_005a3870();
                          continue;
                      }
                      FUN_00449380("Error quit was not requested in the main thread\n");
                  }
              }
              FUN_005a3870();
          }
      }

      // Shutdown path if not param_2 == 0
      FUN_0066a110();
      FUN_004209e0();
  }

  return 0;
}
