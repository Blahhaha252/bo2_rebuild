#include <windows.h>
#include <string.h>
#include <stdint.h>
#include "steam_validation.h"

//FUN_004168c0 -> pre_steam_checks                          |  (this_file)
//  FUN_00421e60 -> steam_check_environment                 |  (this_file)
//    FUN_004f1fc0 -> flattened                             |  (this_file)
//    FUN_006ce670 -> steam_environment_validate            |  (this_file)
//      FUN_006d7ae0 -> initalize_random_seed (END)         |  (this_file)
//      FUN_005584b0 -> flattened (redudent logic)          |  (this_file)
//        FUN_005ffea0 -> write_steam_data_string (END)     |  (this_file)
//      FUN_005246a0 -> create_or_open_file_mapping (END)   |  (this_file)
//      FUN_0045f5b0 -> map_data_block (end)                |  (this_file)
//    FUN_0040d540 -> patch_random_callback                 |  (this_file)
//      FUN_009af460 -> secure_exit (end)                   |  (this_file)
//    FUN_009ae4f0 -> initialize_exception_handling (END)   |  (this_file)

int initialize_exception_handling(void) {
    SIZE_T query_result;
    IMAGE_DOS_HEADER *current_address = (IMAGE_DOS_HEADER *)0x00400000;
    MEMORY_BASIC_INFORMATION mem_info;

    do {
        query_result = VirtualQuery(current_address, &mem_info, sizeof(mem_info));
        if (query_result == 0) {
            break;
        }

        if ((mem_info.BaseAddress < (PVOID)0x009ae4f1) &&
            ((void *)initialize_exception_handling < (void *)((char *)mem_info.BaseAddress + mem_info.RegionSize))) {
            DAT_034025f0 = mem_info.BaseAddress;
            DAT_034025f4 = (void *)((char *)mem_info.BaseAddress + mem_info.RegionSize);
        }

        current_address = (IMAGE_DOS_HEADER *)((char *)current_address + mem_info.RegionSize);
    } while (DAT_034025f0 == NULL);

    DAT_034025ec = AddVectoredExceptionHandler(1, exception_handler);

    if (DAT_034025ec != NULL && DAT_034025f0 != NULL) {
        return 1;
    }
    return 0;
}



void secure_exit(void) {
    UINT clear_count;
    unsigned char *clear_ptr;
    unsigned char temp_buffer[2048];
    
    // Start clearing from a base stack address (simulated)
    clear_ptr = (unsigned char *)register0x00000010;

    // Calculate how much stack memory to clear
    clear_count = ((uintptr_t)&stack0x00001000 & 0xFFFFF000) - (uintptr_t)&stack0x00000000;

    while (clear_count != 0) {
        *clear_ptr = 0;
        clear_ptr++;
        clear_count--;
    }

    // Fill temp_buffer with newline characters (0x0A)
    memset(temp_buffer, 0x0A, sizeof(temp_buffer));

    // Immediately exit process (will not return)
    ExitProcess(0);
}

void patch_random_callback(char should_patch, int num_callbacks, int base_address) {
    DWORD tick_count;
    
    if (should_patch == 0) {
        if (num_callbacks < 1) {
            return;
        }
        
        if (num_callbacks == 1) {
            *(void **)(base_address - 4) = secure_exit; //FUN_009af460
            return;
        }
        
        DWORD tick_count = GetTickCount();
        int random_index = tick_count % (num_callbacks - 1);

        // Pretend 'stack' starts at some base like &stack0x00000010
        int *stack_base = (int *)&stack0x00000010;

        // Find the address stored at that slot
        int target_address = stack_base[random_index];

        // Patch 4 bytes *before* the target address
        *(void **)(target_address - 4) = secure_exit; //FUN_009af460
    }
}


int map_data_block(void) {
    if (DAT_03402618 == NULL) {
        retrun 0;
    }
    DAT_0340261c = &DAT_00c2e938;
    memcpy(DAT_03402618, &DAT_00c2e938, 0x1000); // 4KB copy
    return 1;
}
int create_or_open_file_mapping(FileMappingInfo *info, HANDLE fileHandle, DWORD protectFlags, DWORD size, LPCSTR name) {
    // Clear output structure
    info->hMapping = NULL;
    info->pView = NULL;
    info->size = 0;

    // Setup security attributes
    SECURITY_DESCRIPTOR securityDescriptor;
    SECURITY_ATTRIBUTES securityAttributes;

    InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&securityDescriptor, TRUE, NULL, FALSE);

    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.lpSecurityDescriptor = &securityDescriptor;
    securityAttributes.bInheritHandle = FALSE;

    HANDLE hMapping;
    
    if (protectFlags == 2) {
        // Open existing mapping
        hMapping = OpenFileMappingA(FILE_MAP_READ, FALSE, name);
    } else {
        // Create new mapping
        hMapping = CreateFileMappingA(fileHandle, &securityAttributes, protectFlags, 0, size, name);
    }

    info->hMapping = hMapping;

    if (hMapping != NULL) {
        DWORD desiredAccess = (protectFlags == 2) ? FILE_MAP_READ : FILE_MAP_READ | FILE_MAP_WRITE;
        LPVOID mappedView = MapViewOfFile(hMapping, desiredAccess, 0, 0, 0);
        info->pView = mappedView;

        if (mappedView != NULL) {
            info->size = size;
            return 1; // Success
        }
    }

    GetLastError(); // retrieve error (optional logging could be added)
    return 0; // Failure
}

int write_steam_data_string(char *buffer, uint32_t bufferSize, uint32_t processId) {
    if (bufferSize < 22) {
        return 0;
    }
    
    strncpy(buffer, "STEAM_DATA.", 11);
    char *writePos = buffer + 11;
    char *endPos = writePos;
    
    do {
        char digit = (processId % 10) + '0';
        *endPos++ = digit;
        processId /= 10;
    } while (processId != 0);
    
    *endPos = '\0';
    
    char *left = buffer + 11;
    char *right = endPos -1;
    
    while (left < right) {
        char temp = *left;
        *left++ = *right;
        *right-- = temp;
    }
    
    return (int)(endPos - buffer);
}


uint32_t initalize_random_seed(void) {
    HMODULE advapiModule;
    typedef BOOLEAN (APIENTRY *RtlGenRandomFunc)(PVOID, ULONG);
    RtlGenRandomFunc RtlGenRandom;

    advapiModule = LoadLibraryA("advapi32.dll");
    if (advapiModule != NULL) {
        RtlGenRandom = (RtlGenRandomFunc)GetProcAddress(advapiModule, "SystemFunction036");
        FreeLibrary(advapiModule);

        if (RtlGenRandom != NULL) {
            if (RtlGenRandom(&DAT_03402620, 0x1000)) {
                DAT_03402610 = *(uint32_t*)&DAT_03402620;
                return 1;
            }
        }
    }

    return 0;
}


int steam_environment_validate(void) {
    bool randomSuccess;
    bool stringSuccess;
    bool mappingSuccess;
    char localBuffer[260];
    DWORD tickCount;

    randomSuccess = initialize_random_seed(); //FUN_006d7ae0

    if (randomSuccess) {
        // Set pointer for later usage (DAT_0340260c = &DAT_03403620)
        DAT_0340260c = &DAT_03403620;

        // Write STEAM_DATA.<pid> string (flattened: FUN_005584b0 -> FUN_005ffea0)
        stringSuccess = (write_steam_data_string(localBuffer, sizeof(localBuffer), GetCurrentProcessId()) != 0);

        if (!stringSuccess) {
            // If string write failed, entire validation fails
            mappingSuccess = false;
        } else {
            // validate mapped memory  |||  FUN_005246a0
            mappingSuccess = create_or_open_file_mapping(0, 4, 0x1000, localBuffer);

            if (mappingSuccess) {
                // Save mapped pointer value (DAT_03402618 = *(DAT_0340260c + 4))
                DAT_03402618 = *(uint32_t *)(DAT_0340260c + 4);

                // Validate the mapped memory (FUN_0045f5b0)
                mappingSuccess = map_data_block();
            }
        }
    } else {
        mappingSuccess = false;
    }

    // Always set random tick seed (GetTickCount and modulo) after validation attempt
    tickCount = GetTickCount();
    DAT_03402608 = tickCount % 958; // 0x3be = 958

    // Return overall success/failure
    return mappingSuccess;
}



int steam_check_environment(void) {
    char check1;
    int check2;
    uint environmentHash;
    
    // FUN_004f1fc0 flattened into this part
    steam_heap_handle = HeapCreate(0x40000, 0x100000, 0x1000000);
    if (steam_heap_handle == NULL) {
        return 0;
    }
    // end FUN_004f1fc0
    
    check1 = steam_environment_validate(); //FUN_006ce670
    if (check1 == 0) {
        patch_random_callback(0, 0); //FUN_0040d540
    }

    // ---------- this is where i am currently ---------- //
    // ---------- YA CANT MISS ME ----------//

    // General Steam environment setup
    initialize_exception_handling(); //FUN_009ae4f0

    // Callback validation
    check2 = FUN_00542620(FUN_004abe60);
    DAT_03401f54 = FUN_00601f30();

    if (check2 != 0) {
        patch_random_callback(0, 0); //FUN_0040d540
    }

    // Environment Hash Validation
    if (DAT_03401f54 != 0) {
        environmentHash = FUN_00599950();
        if (((environmentHash ^ 0x0b940d0) | 0x410) != 0 && check2 == 0) {
            return 1;
        }
    }

    return 0;
}


int pre_steam_checks(void) {
    DWORD fileAttributes;
    char result;
    // not finished
    fileAttributes = GetFileAttributesA("steam_appid.txt");
    if (fileAttributes != INVALID_FILE_ATTRIBUTES) {
        if (fileAttributes & FILE_ATTRIBUTE_READONLY) {
            SetFileAttributesA("steam_appid.txt", FILE_ATTRIBUTE_NORMAL);
        }
        DeleteFileA("steam_appid.txt");
    }
    result = steam_check_environment(); // FUN_00421e60
    if (result != 0) {
        FUN_00436600();
        result = SteamAPI_RestartAppIfNecessary(0x33fae);
        
        if (result == 0) {
            return 1;
        }
        FUN_00622540();
        FUN_00605e90();
    }
    return 0;
}