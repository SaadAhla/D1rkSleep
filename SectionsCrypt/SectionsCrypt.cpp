#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

typedef struct {
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;


VOID D1rkCrypt(DWORD SleepTime) {

	DWORD   OldProtect = 0;

	PVOID ImageBase = GetModuleHandle(NULL);
	DWORD ImageSize = ((PIMAGE_NT_HEADERS)((DWORD64)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)ImageBase;
	IMAGE_NT_HEADERS* NT_HEADER = (IMAGE_NT_HEADERS*)((DWORD64)ImageBase + DOS_HEADER->e_lfanew);
	IMAGE_SECTION_HEADER* SECTION_HEADER = IMAGE_FIRST_SECTION(NT_HEADER);

	LPVOID txtSectionBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)SECTION_HEADER->PointerToRawData);
	DWORD txtSectionSize = SECTION_HEADER->SizeOfRawData;


    LPVOID relocBase = NULL;
    DWORD relocSize = 0;
	//printf("[+] %s\t%p\t%d bytes\n", SECTION_HEADER->Name, txtSectionBase, txtSectionSize);

    for (int i = 0; i < NT_HEADER->FileHeader.NumberOfSections; i++) {
        printf("[+] %s\t%p\t%d bytes\n", SECTION_HEADER->Name, 
                                        (LPVOID)((DWORD64)ImageBase + (DWORD64)SECTION_HEADER->PointerToRawData), 
                                        SECTION_HEADER->SizeOfRawData
        );
        
        if (!strcmp(".reloc", (const char*)SECTION_HEADER->Name)) {
            relocBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)SECTION_HEADER->PointerToRawData);
            relocSize = SECTION_HEADER->SizeOfRawData;
        }
        SECTION_HEADER++;
    }

    DWORD CryptSize = ImageSize - (DWORD)((DWORD)txtSectionBase - (DWORD)ImageBase) 
        - (ImageSize - ((DWORD)relocBase - (DWORD)ImageBase)) + relocSize;
	
	CONTEXT CtxThread = { 0 };

	CONTEXT RopProtRW = { 0 };
	CONTEXT RopMemEnc = { 0 };
	CONTEXT RopDelay = { 0 };
	CONTEXT RopMemDec = { 0 };
	CONTEXT RopProtRX = { 0 };
	CONTEXT RopSetEvt = { 0 };

	HANDLE  hTimerQueue = NULL;
	HANDLE  hNewTimer = NULL;
	HANDLE  hEvent = NULL;


	CHAR KeyBuf[16];
	unsigned int r = 0;
	for (int i = 0; i < 16; i++) {
		rand_s(&r); // r between UINT_MIN & UINT_MAX
		KeyBuf[i] = (CHAR)r;

	}

	USTRING Key = { 0 };
	USTRING Img = { 0 };

	PVOID   NtContinue = NULL;
	PVOID   SysFunc032 = NULL;

	hEvent = CreateEventW(0, 0, 0, 0);

	hTimerQueue = CreateTimerQueue();

	NtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");
	SysFunc032 = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	
	Key.Buffer = KeyBuf;
	Key.Length = Key.MaximumLength = 16;

	Img.Buffer = txtSectionBase;
	Img.Length = Img.MaximumLength = CryptSize;

    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        // sleeping , waiting  0x32 mili seconds for RtlCaptureContext function to finish
        WaitForSingleObject(hEvent, 0x32);

        // we gonna populate the info from CtxThread into 6 different CONTEXT structs we ll be utilizing during the obfuscation
        // each CONTEXT struct will hold info for the worker thread to execute specific function with specific params 
        memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopDelay, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
        memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

        // VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
        RopProtRW.Rsp -= 8;
        RopProtRW.Rip = (DWORD64)VirtualProtect;
        RopProtRW.Rcx = (DWORD64)ImageBase;
        RopProtRW.Rdx = ImageSize;
        RopProtRW.R8 = PAGE_READWRITE;
        RopProtRW.R9 = (DWORD64)&OldProtect;

        // SystemFunction032( &Key, &Img );
        RopMemEnc.Rsp -= 8;
        RopMemEnc.Rip = (DWORD64)SysFunc032;
        RopMemEnc.Rcx = (DWORD64)&Img;
        RopMemEnc.Rdx = (DWORD64)&Key;

        
        // WaitForSingleObject( hTargetHdl, SleepTime );
        RopDelay.Rsp -= 8;
        RopDelay.Rip = (DWORD64)WaitForSingleObject;
        RopDelay.Rcx = (DWORD64)NtCurrentProcess();
        RopDelay.Rdx = SleepTime;

        // SystemFunction032( &Key, &Img );
        RopMemDec.Rsp -= 8;
        RopMemDec.Rip = (DWORD64)SysFunc032;
        RopMemDec.Rcx = (DWORD64)&Img;
        RopMemDec.Rdx = (DWORD64)&Key;

        
        // VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
        RopProtRX.Rsp -= 8;
        RopProtRX.Rip = (DWORD64)VirtualProtect;
        RopProtRX.Rcx = (DWORD64)ImageBase;
        RopProtRX.Rdx = ImageSize;
        RopProtRX.R8 = PAGE_EXECUTE_READWRITE;
        RopProtRX.R9 = (DWORD64)&OldProtect;


        RopSetEvt.Rsp -= 8;
        RopSetEvt.Rip = (DWORD64)SetEvent;
        RopSetEvt.Rcx = (DWORD64)hEvent;

        puts("\n[INFO] Queue timers\n");


        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay, 300, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, 500, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);

        puts("\n[INFO] Wait for hEvent\n");
        // once setup we go to sleep and wait SentEvent() function to inform us that everything has been completed
        WaitForSingleObject(hEvent, INFINITE);

        puts("\n[INFO] Finished waiting for event\n");
    }
    // delete the timerQueue
    DeleteTimerQueue(hTimerQueue);
}


int main() {
	
    do {
        printf("\n\n================\t\tStart\t\t================\n\n");
        D1rkCrypt(20000);
        printf("\n[+] Only Section are Encrypted (.text, .rdata, .data, .pdata, .rsrc, .reloc)\n");
        printf("\n\n================\t\tRepeate\t\t================\n\n");
    } while (TRUE);

	return 0;
}

