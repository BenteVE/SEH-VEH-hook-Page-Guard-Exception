/*
    SOURCES:
        - https://guidedhacking.com/threads/veh-hooking-hooking-via-forced-exception.11928/
        - https://github.com/hoangprod/LeoSpecial-VEH-Hook/blob/master/Main.cpp
        - https://docs.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-pvectored_exception_handler
    PROJECT SETTINGS:

    INFO:
        - USAGE:
            This code creates a DLL. When the DLL is injected in an application it will install an VEH hook on the
            MessageBoxW function to change the text in the textbox.

        - Different ways to create SEH/VEH hooks
            There are several ways to trigger an exception that will be caught by our Exception handler:
                - STATUS_GUARD_PAGE_VIOLATION
                - STATUS_ACCESS_VIOLATION (with NO_ACCESS flag)
                - EXCEPTION BREAKPOINT (INT3 opcode)
                - setting Dr registers in PCONTEXT

            When we return to the place of the exception after executing our hook, we have to make sure the exception is not triggered again.
            There are 2 ways to accomplish this:
                - SINGLE STEP EXCEPTION
                - creating a trampoline with assembly

            There are also different ways to install an exception handler
                - by using SetUnhandledExceptionFilter/SetVectoredExceptionHandler
                - by changing pointers in Thead Information Block (TIB) with assembly 

            In this program we will use the STATUS_GUARD_PAGE_VIOLATION in combination with the SINGLE STEP EXCEPTION to trigger and recover from the exception,
            and we will use SetVectoredExceptionHandler to install the handler

        - VEH:
            In Windows, users are allowed to register their own vectored exception handler with the WINAPI AddVectoredExceptionHandler.
            The PVECTORED_EXCEPTION_HANDLER structure contains _EXCEPTION_POINTERS that contains a PCONTEXT ContextRecord.
            This will give us access to the debug registers, floating point registers, segments registers, general purpose registers as well as control registers. 
            It also allows us to directly modify control registers such as EIP/RIP to achieve execution flow modification.

        - STATUS_SINGLE_STEP: 
            Thus is not a violation but instead a mechanism to detect a trace trap or when another single instruction mechanism signals that one instruction is executed. 
            This can be achieve by settings the ContextRecord's EFlags with |= 0x100.
            When we use VirtualProtect to set protection flags on a page, it is applied to the entire page. 
            This means that other functions on that page will also trigger the exception. By setting the Eflags with the bitwise OR operator and 0x100,
            we can step 1 instruction at a time through the page until we get to the exact address we want to hook, 
            then we will perform our EIP/RIP modification and achieve the hook we need.
            If the function we are on isn't the one we want to hook but is on the same page, 
            STATUS_SINGLE_STEP will keep going until the function's return is called, which then we will no longer be in the page. This way we avoid hooking the wrong function.
            
        - SUMMARY VEH HOOK:
            Find the address of the function you want to hook (GetProcAddress)
            Register a vectored exception handle, changing the EIP/RIP to your own function (AddVectoredExceptionHandler)
            Use VirtualProtect to add a PAGE_GUARD modifier to your target function's address page
            When the target function is called, the PAGE_GUARD_VIOLATION exception will trigger, the VEH will catch the exception, and redirect the flow to your function.

        - BUILDING
            Because of the register names, this can only be compiled for x86
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

typedef int(WINAPI* TrueMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

// remember memory address of the original MessageBoxW routine
TrueMessageBox trueMessageBox = MessageBoxW;

int WINAPI hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    printf("Executing hooked function\n");
    //LPCTSTR lpTextChanged = L"This messagebox is also changed";
    LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
    int retval = trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);

    //reapply page guard before return
    printf("Reinstalling page guard from end of hook function\n");
    DWORD dwOld;
    VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld); //Reapply the PAGE_GUARD flag because everytime it is triggered, it get removes

    return retval;
}

PVOID VEH_Handle = nullptr;
DWORD oldProtection = 0;

// This function checks if two functions in the same page. 
// We cannot hook 2 functions on the same page because this will cause an infinite callback.
// maakt het nu eigenlijk uit of ze in dezelfde pagina liggen
bool AreInSamePage(const PDWORD Addr1, const PDWORD Addr2)
{
    MEMORY_BASIC_INFORMATION mbi1;
    if (!VirtualQuery(Addr1, &mbi1, sizeof(mbi1))) //Get Page information for Addr1
        return true;

    MEMORY_BASIC_INFORMATION mbi2;
    if (!VirtualQuery(Addr2, &mbi2, sizeof(mbi2))) //Get Page information for Addr2
        return true;

    if (mbi1.BaseAddress == mbi2.BaseAddress) //See if the two pages start at the same Base Address
        return true; //Both addresses are in the same page, abort hooking!

    printf("Not on same page!\n");
    return false;
}

// When an exception is raised, ExceptionFilter checks to see whether the exception occurred at the desired address.
// If so, the exception is handled and now the context record 
// (containing, among other things, the values of all registers and flags when the breakpoint was hit).
// Since the function sets up a standard BP - based frame, the parameters can all be retrieved through 
// ESP(since the stack frame was not set up yet when the breakpoint was hit). 
// All registers and parameters can then be inspected and/or modified as shown in print_parameters and modify_text.
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {

    //We will catch PAGE_GUARD Violation and check the address
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION && (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == (DWORD)trueMessageBox)
    {
        printf("Breakpoint hit!\n");

        printf("Setting ContextRecord to hook\n");
        ExceptionInfo->ContextRecord->Eip = (UINT_PTR)hookedMessageBox; //Modify EIP/RIP to where we want to jump to instead of the original function

        return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
    }
        
    //to avoid hook getting deleted from access on same page: set context flags
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        //Will trigger an STATUS_SINGLE_STEP exception right after the next instruction get executed. In short, we come right back into this exception handler 1 instruction later
        printf("Hit same page!\n");
        ExceptionInfo->ContextRecord->EFlags |= 0x100;

        return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
    }

    // catch exception to reinstall page guard
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) { //We will also catch STATUS_SINGLE_STEP, meaning we just had a PAGE_GUARD violation

        //Reapply the PAGE_GUARD flag because everytime it is triggered, it get removes (only if we don't call true function in hooked function)
        DWORD dwOld;
        printf("Caught single step, reinstalling page guard\n");
        VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);

        return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
    }

    // Exception is not caused by our hook
    else{ 
        return EXCEPTION_CONTINUE_SEARCH; //Keep going down the exception handling list to find the right handler IF it is not PAGE_GUARD nor SINGLE_STEP
    }
        
}

DWORD WINAPI installVEHHook(PVOID base) {

    //HMODULE modUser32 = GetModuleHandle(TEXT("user32.dll"));
    //DWORD trueMessageBoxaddr = (DWORD)GetProcAddress(modUser32, "MessageBoxW");

    // check if both are not in same page
    if (AreInSamePage((PDWORD)trueMessageBox, (PDWORD)hookedMessageBox))
        return FALSE;

    // NOTE: no need to use SetThreadContext because we don't change the Dr registers to set a breakpoint
    //Register the Custom Exception Handler
    VEH_Handle = AddVectoredExceptionHandler(1, ExceptionFilter);//returned handle can be used to later remove the hook with RemoveVectoredExceptionHandler
    printf("AddVectoredExceptionHandler executed.\n");

    //Toggle PAGE_GUARD flag on the page
    if (VEH_Handle && VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection)) {
        //As test: call function
        //printf("Executing Test MessageBox.\n");
        //MessageBoxW(NULL, L"Finished", L"MyMessageBox", MB_OK);
        printf("installed page guard\n");
        return TRUE;
    }
    
    return FALSE;
}

DWORD WINAPI uninstallVEHHook(PVOID base) {
    DWORD old;
    if (VEH_Handle && //Make sure we have a valid Handle to the registered VEH
        VirtualProtect((LPVOID)trueMessageBox, 1, oldProtection, &old) && //Restore old Flags
        RemoveVectoredExceptionHandler(VEH_Handle)) //Remove the VEH
        return true;

    return false;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    FILE* stream; //An out parameter that will point to the reopened stream when the function returns.
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
        // This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads, 
        // and whose DLLs do not need these thread - level notifications of attachment/detachment.
        DisableThreadLibraryCalls(hModule);

        // Open console for debugging
        if (AllocConsole()) {
            freopen_s(&stream, "CONOUT$", "w", stdout);
            SetConsoleTitle(L"Console");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("DLL loaded.\n");
        }

        // install SEH hook
        CreateThread(nullptr, NULL, installVEHHook, hModule, NULL, nullptr); break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

