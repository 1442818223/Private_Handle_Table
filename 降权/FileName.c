#include <ntifs.h>
#include <intrin.h>

#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt


BOOLEAN isThreadWork = TRUE;



//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};
//0x40 bytes (sizeof)
struct _HANDLE_TABLE_FREE_LIST
{
	struct _EX_PUSH_LOCK FreeListLock;                                      //0x0
	union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                        //0x8
	union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                         //0x10
	LONG HandleCount;                                                       //0x18
	ULONG HighWaterMark;                                                    //0x1c
};
//0x80 bytes (sizeof)
struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;                                            //0x0
	LONG ExtraInfoPages;                                                    //0x4
	volatile ULONGLONG TableCode;                                           //0x8
	struct _EPROCESS* QuotaProcess;                                         //0x10
	struct _LIST_ENTRY HandleTableList;                                     //0x18
	ULONG UniqueProcessId;                                                  //0x28
	union
	{
		ULONG Flags;                                                        //0x2c
		struct
		{
			UCHAR StrictFIFO : 1;                                             //0x2c
			UCHAR EnableHandleExceptions : 1;                                 //0x2c
			UCHAR Rundown : 1;                                                //0x2c
			UCHAR Duplicated : 1;                                             //0x2c
			UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;                   //0x2c
		};
	};
	struct _EX_PUSH_LOCK HandleContentionEvent;                             //0x30
	struct _EX_PUSH_LOCK HandleTableLock;                                   //0x38
	union
	{
		struct _HANDLE_TABLE_FREE_LIST FreeLists[1];                        //0x40
		struct
		{
			UCHAR ActualEntry[32];                                          //0x40
			struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
		};
	};
};
///////////////////////////////////////////////////////////////////////////////////////////////////
//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
	LONGLONG PointerCount;                                                  //0x0
	union
	{
		LONGLONG HandleCount;                                               //0x8
		VOID* NextToFree;                                                   //0x8
	};
	struct _EX_PUSH_LOCK Lock;                                              //0x10
	UCHAR TypeIndex;                                                        //0x18**************************************
	union
	{
		UCHAR TraceFlags;                                                   //0x19
		struct
		{
			UCHAR DbgRefTrace : 1;                                            //0x19
			UCHAR DbgTracePermanent : 1;                                      //0x19
		};
	};
	UCHAR InfoMask;                                                         //0x1a
	union
	{
		UCHAR Flags;                                                        //0x1b
		struct
		{
			UCHAR NewObject : 1;                                              //0x1b
			UCHAR KernelObject : 1;                                           //0x1b
			UCHAR KernelOnlyAccess : 1;                                       //0x1b
			UCHAR ExclusiveObject : 1;                                        //0x1b
			UCHAR PermanentObject : 1;                                        //0x1b
			UCHAR DefaultSecurityQuota : 1;                                   //0x1b
			UCHAR SingleHandleEntry : 1;                                      //0x1b
			UCHAR DeletedInline : 1;                                          //0x1b
		};
	};
	ULONG Reserved;                                                         //0x1c
	union
	{
		struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
		VOID* QuotaBlockCharged;                                            //0x20
	};
	VOID* SecurityDescriptor;                                               //0x28
	struct _QUAD Body;                                                      //0x30
};
///////////////////////////////////////////////////////////////////////////////////////////////////
//0x8 bytes (sizeof)
struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;                                                        //0x0
	ULONG MaxRelativeAccessMask;                                            //0x4
};

struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG TagBits : 2;                                                //0x0
			ULONG Index : 30;                                                 //0x0
		};
		VOID* GenericHandleOverlay;                                         //0x0
		ULONGLONG Value;                                                    //0x0
	};
};
//0x10 bytes (sizeof)
typedef union _HANDLE_TABLE_ENTRY
{
	volatile LONGLONG VolatileLowValue;                                     // 0x0: �ɱ䳤���ͣ���ʾ��λֵ��ԭ�ӷ��ʣ���Ҫ����ͬ����
	LONGLONG LowValue;                                                      // 0x0: ��λֵ�����ܴ�������ʵ��ֵ��

	struct
	{
		struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                // 0x0: ָ���������Ϣ�ı�������ٷ��ʾ����Ԫ���ݡ�
		LONGLONG HighValue;                                                 // 0x8: ��λֵ��ͨ�����λֵ����γ������ľ����
		union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                    // 0x8: ָ����һ�����о����Ŀ��ָ�룬���ڹ�������
		struct _EXHANDLE LeafHandleValue;                                   // 0x8: Ҷ���ֵ��ͨ����ʾʵ�ʵĶ�������
	};

	LONGLONG RefCountField;                                                 // 0x0: ���ü����ֶΣ����ڸ��پ�������ô�����
	ULONGLONG Unlocked : 1;                                                  // 0x0: ������־��ָʾ�þ���Ƿ�δ��������
	ULONGLONG RefCnt : 16;                                                   // 0x0: ���ü�����ʵ��ֵ��ָʾ��ǰ���õ�������
	ULONGLONG Attributes : 3;                                                // 0x0: ������ԣ�ָʾ��������ԣ���ɼ̳��ԣ���
	struct
	{
		ULONGLONG ObjectPointerBits : 44;                                    // 0x0: ����ָ��λ����ʾ�����ָ�������
		ULONG GrantedAccessBits : 25;                                        // 0x8: ����ķ���Ȩ��λ����ʾ�þ������Ĳ�����
		ULONG NoRightsUpgrade : 1;                                           // 0x8: ������Ȩ�������ı�־��ָʾ����Ƿ��������Ȩ�ޡ�
		ULONG Spare1 : 6;                                                   // 0x8: ����λ��δʹ�õ�λ��
	};

	ULONG Spare2;                                                           // 0xc: ����ı����ֶΣ����ڶ����δ����չ��
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

///////////////////////////////////////////////////////////////////////////////////////////////////

typedef BOOLEAN(NTAPI* EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PVOID HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);

BOOLEAN ExEnumHandleTable(
	__in PVOID HandleTable,
	__in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	__in PVOID EnumParameter,
	__out_opt PHANDLE Handle
);


EXTERN_C VOID ExfUnblockPushLock(
	_In_ PEX_PUSH_LOCK PushLock
);

///////////////////////////////////////////////////////////////////////////////////////////////////

BOOLEAN NTAPI enumRoutine(
	IN PVOID HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,//HandleTableEntry ��Ӧ�ý���ÿ��ö�ٵ��ľ�����
	IN HANDLE Handle, //��Ӧ��ǰ�ľ��ֵ��
	IN PVOID EnumParameter  //TargetProcess
)
{
	BOOLEAN result = FALSE;
	if (HandleTableEntry)
	{
		ULONG_PTR object_header = (*(PLONG_PTR)(HandleTableEntry) >> 0x10) & 0xFFFFFFFFFFFFFFF0;

		ULONG_PTR object = object_header + 0x30;


	
		// ���ö�������Ϊ���̣���ö���Ϊ�ý��̵�EPROCESS
			if (object == (ULONG_PTR)EnumParameter)
			{
				HandleTableEntry->GrantedAccessBits &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
				result = TRUE;
			}
		
	}

	_InterlockedExchangeAdd64(HandleTableEntry, 1); // ע�� ��������ͷţ��ο�ObpEnumFindHandleProcedure��ʵ��
	if (*(PULONG_PTR)((ULONG_PTR)HandleTable + 0x30)) {
		ExfUnblockPushLock((ULONG_PTR)HandleTable + 0x30, 0); // ͬ��
	}
	return result;
}

VOID ProcessHandleResetPrivilege(PEPROCESS ep)
{
	while (isThreadWork)
	{
		PEPROCESS Process = NULL;
		for (int i = 8; i < 0x1000000; i += 4)
		{
			NTSTATUS status = PsLookupProcessByProcessId((HANDLE)i, &Process);
			if (!NT_SUCCESS(status))
			{
				continue;
			}


			if (PsGetProcessExitStatus(Process) == 0x103)
			{
				if (PsGetProcessId(Process) == 7368)/////
				{

					PVOID handle_table = *(PVOID*)((LONG_PTR)Process + 0x570);
					PVOID Handle = NULL;
					ExEnumHandleTable(handle_table, enumRoutine, ep, NULL);
				}


				if (PsGetProcessExitStatus(Process) == 0x103) ObDereferenceObject(Process);

			}

		}

		LARGE_INTEGER tin = { 0 };
		tin.QuadPart = -10000 * 10000;
		KeDelayExecutionThread(KernelMode, FALSE, &tin);
	}


}

PEPROCESS FindProcessByName(PWCH name)
{

	PEPROCESS Process = NULL;
	PEPROCESS findProcess = NULL;
	for (int i = 8; i < 0x1000000; i += 4)
	{
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)i, &Process);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		PUNICODE_STRING ProcessName = NULL;
		status = SeLocateProcessImageName(Process, &ProcessName);

		if (!NT_SUCCESS(status))
		{
			ObDereferenceObject(Process);
			continue;
		}

		//DbgPrintEx(77, 0, "Checking process ID: %d\n", i); // ��ӡ��ǰ���Ľ���ID

		if (ProcessName->Length) {
			_wcsupr(ProcessName->Buffer);
			// ���Ƚ��ļ�������������·��
			PWCH fileName = wcsrchr(ProcessName->Buffer, L'\\');
			if (fileName) {
				fileName++;// ����'\'�ַ�
			}
			else {
				fileName = ProcessName->Buffer;// û��'\'��ֱ��ʹ����������
			}

			//DbgPrintEx(77, 0, "Comparing with: %ws\n", fileName);

			// ʹ�ò����ִ�Сд�ıȽ�
			if (_wcsicmp(fileName, name) == 0) {
				findProcess = Process;
				//DbgPrintEx(77, 0, "Matched process: %ws\n", ProcessName->Buffer);
				ExFreePoolWithTag(ProcessName, 0);
				break;
			}
		}

		ExFreePoolWithTag(ProcessName, 0);
		ObDereferenceObject(Process);
	}
	if (findProcess == NULL) {
		DbgPrintEx(77, 0, "No process found with name: %ws\n", name); // δ�ҵ�Ŀ�����
	}
	return findProcess;
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	isThreadWork = FALSE;
	LARGE_INTEGER tin = { 0 };
	tin.QuadPart = -10000 * 15000;
	KeDelayExecutionThread(KernelMode, FALSE, &tin);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	PEPROCESS Process = FindProcessByName(L"dbgview64.exe");
	HANDLE hThread = NULL;
	PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ProcessHandleResetPrivilege, Process);
	if (hThread) NtClose(hThread);

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}