//FUN_005075e0 -> launch_steam_drm_process                  |   (this_file)

HANDLE launch_steam_drm_process(undefined4 *ipcHandles, DWORD controlFlag, undefined4 *outEventHandle) {
    HANDLE steamProcess = NULL;
    HANDLE fileHandle;
    DWORD lastError = 0;
    char fullModulePath[1024];
    DWORD processId, filenameLen;
    HMODULE currentModule;

    *outEventHandle = 0;

    DWORD *sharedMemory = (DWORD *)ipcHandles[3];

    // Get module handle of caller
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)_ReturnAddress(), &currentModule)) {
        goto fail;
    }

    // Write control data to shared memory
    processId = GetCurrentProcessId();
    sharedMemory[0] = processId;
    sharedMemory[1] = controlFlag;
    DWORD *extraData = &sharedMemory[2];

    // Get module file path
    filenameLen = GetModuleFileNameA(currentModule, (LPSTR)extraData, 4025);
    if (filenameLen == 0 || filenameLen >= 4025) goto fail;
    ((char *)extraData)[filenameLen] = '\0';

    // Resolve full path to the module
    DWORD fullPathLen = GetFullPathNameA((LPCSTR)extraData, sizeof(fullModulePath), fullModulePath, NULL);
    if (fullPathLen == 0 || fullPathLen >= sizeof(fullModulePath)) goto fail;
    fullModulePath[fullPathLen] = '\0';

    // Prepare event names
    char ackEvent[256], termEvent[256];
    snprintf(ackEvent, sizeof(ackEvent), "STEAM_START_ACK_EVENT_%u_%p", processId, _ReturnAddress());
    snprintf(termEvent, sizeof(termEvent), "STEAM_TERM_EVENT_%u_%p", processId, _ReturnAddress());

    // Store event handle in out param
    *outEventHandle = (undefined4)FUN_00435940(termEvent);

    // If ACK event isn't found, return error
    HANDLE ackHandle = (HANDLE)FUN_00435940(ackEvent);
    if (ackHandle == NULL) {
        lastError = GetLastError();
        goto fail_cleanup;
    }

    // Launch the module (possibly as a process to handle DRM handshake)
    fileHandle = CreateFileA((LPCSTR)extraData, GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        lastError = GetLastError();
        goto fail_cleanup;
    }

    // Load and verify launch binary
    if (!FUN_004c5300(currentModule, fileHandle, fullModulePath, fullPathLen, NULL, NULL)) {
        lastError = GetLastError();
        CloseHandle(fileHandle);
        goto fail_cleanup;
    }

    if (!FUN_0057aa10(fileHandle)) {
        lastError = GetLastError();
        CloseHandle(fileHandle);
        goto fail_cleanup;
    }

    // Release semaphore to signal ready state
    DWORD prevCount = 0;
    if (ReleaseSemaphore((HANDLE)*ipcHandles, 1, (LPLONG)&prevCount)) {
        CloseHandle(fileHandle);
        return ackHandle; // Success
    }

    lastError = GetLastError();
    CloseHandle(fileHandle);

fail_cleanup:
    if (ackHandle != NULL) CloseHandle(ackHandle);
fail:
    sharedMemory[0] = 0;         // Clear process ID
    sharedMemory[1] = lastError; // Store error
    if (lastError != 0) SetLastError(lastError);
    return NULL;
}
