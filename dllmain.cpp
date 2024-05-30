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
typedef int(WINAPI *TrueMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

TrueMessageBox trueMessageBox = MessageBoxW;

int WINAPI hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	fprintf(console.stream, "Executing hooked function\n");

	// Execute the true function from the hook with changed arguments
	// => this call will not trigger an exception because we didn't reinstall the page guard yet
	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	int retval = trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);

	// Reapply page guard before returning the result of the true function
	fprintf(console.stream, "Reinstalling page guard from end of hook function\n");
	DWORD dwOld;
	VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld); // Reapply the PAGE_GUARD flag because everytime it is triggered, it get removes

	return retval;
}

// When an exception is raised, the ExceptionFilter will be executed
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{

	// If the exception is a PAGE_GUARD Violation and the address is the address of the hooked function,
	// => deviate the program execution to our hook function
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION && (UINT_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress == (UINT_PTR)trueMessageBox)
	{
		fprintf(console.stream, "Breakpoint hit!\n");

		// Modify EIP/RIP (Instruction pointer register) to
		// execute the hook after the exception handling is complete
		ExceptionInfo->ContextRecord->instr_ptr = (UINT_PTR)hookedMessageBox;

		// Allow the program to continue execution at the address in the Instruction pointer register
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// If the exception is a PAGE_GUARD Violation but the address is not correct:
	// - if we let the program continue, the PAGE_GUARD will be gone,
	//   and the ExceptionFilter will not be called again when the function is called
	// => we need some way to reinstall the PAGE_GUARD after this other function is completed
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		fprintf(console.stream, "Hit same page!\n");

		// This will trigger a STATUS_SINGLE_STEP exception right after the next instruction gets executed
		// => the ExceptionFilter will be called again so we can reinstall the page guard
		ExceptionInfo->ContextRecord->EFlags |= 0x100;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// catch the STATUS_SINGLE_STEP exception (that we caused) to reinstall page guard
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		fprintf(console.stream, "Caught single step, reinstalling page guard\n");

		// Reapply the PAGE_GUARD flag
		DWORD dwOld;
		VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// Any other exception is not caused by our hook
	// Keep going down the exception handling list to find a correct handler
	else
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

// When using the Vectored Exception Handler, this is used to remove the VEH
// (unused when using SEH instead)
PVOID VEH_Handle = nullptr;

// Store the old page protection before adding the Page guard
// so we can restore it when unhooking
DWORD oldProtection = 0;

// Note: When installing this directly from the DllMain function (without CreateThread),
// the SEH hook does not work, but the VEH hook does
DWORD WINAPI installHook(PVOID base)
{

	// Register the ExceptionFilter with SEH or VEH
	// SetUnhandledExceptionFilter(ExceptionFilter);
	VEH_Handle = AddVectoredExceptionHandler(1, ExceptionFilter);

	// Add a page guard to the page that contains the MessageBoxW function
	VirtualProtect((LPVOID)trueMessageBox, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection);

	// Test
	fprintf(console.stream, "Testing the hook ...\n");
	MessageBoxW(NULL, L"Testing the hook", L"Testing", MB_OK);

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{

	case DLL_PROCESS_ATTACH:
	{
		// The DisableThreadLibraryCalls function lets a DLL disable the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notification calls.
		// This can be a useful optimization for multithreaded applications that have many DLLs, frequently createand delete threads,
		// and whose DLLs do not need these thread - level notifications of attachment/detachment.
		DisableThreadLibraryCalls(hModule);

		if (!console.open())
		{
			// Indicate DLL loading failed
			return FALSE;
		}

		// install hook
		CreateThread(nullptr, NULL, installHook, hModule, NULL, nullptr);

		return TRUE;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		// Note: moving the uninstall to a function with CreateThread doens't work (Race condition?)
		fprintf(console.stream, "Uninstalling the hook ...\n");

		// Restore the old protection
		VirtualProtect((LPVOID)trueMessageBox, 1, oldProtection, &oldProtection);

		// Remove the ExceptionFilter with SEH or VEH
		// SetUnhandledExceptionFilter(NULL);
		RemoveVectoredExceptionHandler(VEH_Handle);

		// Open a MessageBox to allow reading the output
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);

		return TRUE;
	}
	}
	return TRUE;
}
