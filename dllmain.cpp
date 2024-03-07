#include <Windows.h>
#include "Console.h"

// Access the Instruction Pointer Register in 32 and 64 bit architectures
#if _WIN64
#define instr_ptr Rip
#else
#define instr_ptr Eip
#endif

Console console;

// Signature of MessageBoxW
typedef int(WINAPI* TrueMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

TrueMessageBox trueMessageBox = MessageBoxW;

int WINAPI hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	fprintf(console.stream, "Executing hooked function\n");
	//LPCTSTR lpTextChanged = L"This messagebox is also changed";
	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	int retval = trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);

	//reapply page guard before return
	fprintf(console.stream, "Reinstalling page guard from end of hook function\n");
	DWORD dwOld;
	VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld); //Reapply the PAGE_GUARD flag because everytime it is triggered, it get removes

	return retval;
}

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

	fprintf(console.stream, "Not on same page!\n");
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
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION && (UINT_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress == (UINT_PTR)trueMessageBox)
	{
		fprintf(console.stream, "Breakpoint hit!\n");

		fprintf(console.stream, "Setting ContextRecord to hook\n");

		// Modify EIP/RIP (Instruction pointer register) to 
		// execute the hook after the exception handling is complete
		ExceptionInfo->ContextRecord->instr_ptr = (UINT_PTR)hookedMessageBox;

		return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
	}

	//to avoid hook getting deleted from access on same page: set context flags
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		//Will trigger an STATUS_SINGLE_STEP exception right after the next instruction get executed. In short, we come right back into this exception handler 1 instruction later
		fprintf(console.stream, "Hit same page!\n");
		ExceptionInfo->ContextRecord->EFlags |= 0x100;

		return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
	}

	// catch exception to reinstall page guard
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) { //We will also catch STATUS_SINGLE_STEP, meaning we just had a PAGE_GUARD violation

		//Reapply the PAGE_GUARD flag because everytime it is triggered, it get removes (only if we don't call true function in hooked function)
		DWORD dwOld;
		fprintf(console.stream, "Caught single step, reinstalling page guard\n");
		VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);

		return EXCEPTION_CONTINUE_EXECUTION; //Continue to next instruction
	}

	// Exception is not caused by our hook
	else {
		return EXCEPTION_CONTINUE_SEARCH; //Keep going down the exception handling list to find the right handler IF it is not PAGE_GUARD nor SINGLE_STEP
	}

}

// When using the Vectored Exception Handler, this is used to remove the VEH
// (unused when using SEH instead) 
PVOID VEH_Handle = nullptr;

// Store the old page protection before adding the Page guard
DWORD oldProtection = 0;

// Note: When installing this directly from the DllMain function (without CreateThread),
// the SEH hook does not work, but the VEH hook does
DWORD WINAPI installHook(PVOID base) {

	// We can't make this hook if both the hook and the true function are in the same page?
	// TODO: draw the interactions to check if this is true
	if (AreInSamePage((PDWORD)trueMessageBox, (PDWORD)hookedMessageBox))
		return FALSE;

	// Register the ExceptionFilter with SEH or VEH
	//SetUnhandledExceptionFilter(ExceptionFilter);
	VEH_Handle = AddVectoredExceptionHandler(1, ExceptionFilter);

	// Add a page guard to the page that contains the MessageBoxW function
	VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection);

	// Test
	fprintf(console.stream, "Testing the hook ...\n");
	MessageBoxW(NULL, L"Testing the hook", L"Testing", MB_OK);

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH:
	{
		// The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		// This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads, 
		// and whose DLLs do not need these thread - level notifications of attachment/detachment.
		DisableThreadLibraryCalls(hModule);

		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}

		// install hook
		CreateThread(nullptr, NULL, installHook, hModule, NULL, nullptr);

		return TRUE;
	}
	case DLL_THREAD_ATTACH: break;
	case DLL_THREAD_DETACH: break;
	case DLL_PROCESS_DETACH: {
		// Note: moving the uninstall to a function with CreateThread doens't work (Race condition?)
		fprintf(console.stream, "Uninstalling the hook ...\n");

		// Restore the old protection
		VirtualProtect((LPVOID)trueMessageBox, 1, oldProtection, &oldProtection);

		// Remove the ExceptionFilter with SEH or VEH
		//SetUnhandledExceptionFilter(NULL);
		RemoveVectoredExceptionHandler(VEH_Handle);

		// Open a MessageBox to allow reading the output
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);

		return TRUE;
	}
	}
	return TRUE;
}

