#include <ntifs.h>
#include <intrin.h>


#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt

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
PVOID gObject = NULL;

BOOLEAN NTAPI enumRoutine(
	IN PVOID HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,//HandleTableEntry ��Ӧ�ý���ÿ��ö�ٵ��ľ�����
	IN HANDLE Handle, //��Ӧ��ǰ�ľ��ֵ��
	IN PVOID EnumParameter  //TargetProcess
)
{
	//DbgPrintEx(77, 0, "Enumerating handle: %p\n", Handle);
	//DbgPrintEx(77, 0, "HandleTableEntry: %p\n", HandleTableEntry);
	BOOLEAN result = FALSE;
	if (HandleTableEntry)
	{

		ULONG_PTR object_header = (*(PLONG_PTR)(HandleTableEntry) >> 0x10) & 0xFFFFFFFFFFFFFFF0;

		ULONG_PTR object = object_header + 0x30;
		if (object == (ULONG_PTR)EnumParameter)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "[db]:HandleTableEntry= %llx \r\n", HandleTableEntry);


			HandleTableEntry->LowValue = (ULONG_PTR)gObject | 1;//����1λ����


			HandleTableEntry->GrantedAccessBits |= PROCESS_ALL_ACCESS;
			result = TRUE;
		}
	}
	_InterlockedExchangeAdd64(HandleTableEntry, 1); // ע�� ��������ͷţ��ο�ObpEnumFindHandleProcedure��ʵ��
	if (*(PULONG_PTR)((ULONG_PTR)HandleTable + 0x30)) {
		ExfUnblockPushLock((ULONG_PTR)HandleTable + 0x30, 0); // ͬ��
	}
	return result;
}
BOOLEAN IsValidCR3(ULONG cr3) {
	// ���CR3�Ƿ�����Ч��Χ��
	// ����ϵͳ�ܹ��Ͱ汾������Ч��Χ
	return (cr3 != 0 && (cr3 & 0xFFF) == 0); // ʾ����������4KB����
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
ULONG GetProcessIdOffset()
{

	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, L"PsGetProcessId");
	PUCHAR startFunc = MmGetSystemRoutineAddress(&unName);

	return *(PULONG)(startFunc + 3);
}
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{

	DbgPrintEx(77, 0, "Driver loaded successfully\n");

	gObject = ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!gObject) {
		DbgPrintEx(77, 0, "Failed to allocate memory for gObject\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//PEPROCESS srcProcess = (PUCHAR)gObject + 0x18;   //32λ
	PEPROCESS srcProcess = (PUCHAR)gObject + 0x30;    //64λ
	memset(gObject, 0, PAGE_SIZE);
	DbgPrintEx(77, 0, "gObject allocated at: %p\n", gObject);

	//���ƽ���
	PEPROCESS TargetProcess = FindProcessByName(L"dbgview64.exe");
	if (!TargetProcess) {
		DbgPrintEx(77, 0, "Failed to find target process\n");
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(77, 0, "Target process found: %p\n", TargetProcess);

	// ���ӵ�Ŀ�����
	KAPC_STATE kapcState = { 0 };
	KeStackAttachProcess(TargetProcess, &kapcState);
	memcpy(gObject, (PUCHAR)TargetProcess - 0x30, 0x300);
	DbgPrintEx(77, 0, "Copied process data to gObject\n");
	// ж�ظ���
	KeUnstackDetachProcess(&kapcState);



	//���������� �ɵ�PID
	*(PHANDLE)((PUCHAR)srcProcess + GetProcessIdOffset()) = 0;
	DbgPrintEx(77, 0, "Cleared PID in srcProcess\n");


	KeStackAttachProcess(TargetProcess, &kapcState);
	//ULONG cr3 = *(PULONG)((PUCHAR)TargetProcess + 0x18);
	//win11��0x28
	ULONG cr3 = *(PULONG)((PUCHAR)TargetProcess + 0x28);
	DbgPrintEx(77, 0, "CR3 value: 0x%lx\n", cr3);
	if (!IsValidCR3(cr3)) { // ȷ�����������������֤CR3
		DbgPrintEx(77, 0, "Invalid CR3 value, exiting\n");
		return STATUS_INVALID_PARAMETER;
	}
	KeUnstackDetachProcess(&kapcState);


	//PHYSICAL_ADDRESS cr3Phy = {0};
	//cr3Phy.QuadPart = cr3;
	ULONG msize = 0x20;  // 2 4   8
	if ((cr3 % 0x1000) == 0)  //�൱��ӳ���PML4ҳ�� 512 ����4K�����
	{
		//101012
		msize = PAGE_SIZE;
		//	DbgPrintEx(77, 0, "Adjusted msize to PAGE_SIZE\n");
	}

	// WIN10 1803���ϣ�����ӳ��ҳ��
	//�б׶�  �����Сҳ����һ��ӳ���ҳʱ�� ��һ���ɹ�������Ǵ�ҳһ��ӳ��2M ����4M ������ҳ��ͷ����ҳ��������
	//�����ַӳ������Ե�ַ
	//PVOID mem = MmMapIoSpace(cr3Phy, msize, MmNonCached);
	// �������ڴ��豸��Unicode�ַ���
	HANDLE hMemory = NULL;
	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, L"\\Device\\PhysicalMemory");
	// ��ʼ����������
	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(&obj, &unName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = ZwOpenSection(&hMemory, SECTION_ALL_ACCESS, &obj);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "Failed to open physical memory section: 0x%lx\n", status);
		return status;
	}

	DbgPrintEx(77, 0, "Opened physical memory section\n");


	PVOID mem = NULL;// ���ڱ���ӳ����ͼ�Ļ���ַ
	SIZE_T sizeView = PAGE_SIZE; // Ҫӳ�����ͼ��С��
	LARGE_INTEGER lage = { 0 };
	lage.QuadPart = cr3;// Ҫӳ��������ַ

	PVOID sectionObj = NULL;
	status = ObReferenceObjectByHandle(hMemory, SECTION_ALL_ACCESS, NULL, KernelMode, &sectionObj, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "Failed to reference section object: 0x%lx\n", status);
		ZwClose(hMemory);
		return status;
	}
	DbgPrintEx(77, 0, "Referenced section object\n");
	// ӳ����ͼ����ǰ���̵ĵ�ַ�ռ�
	status = ZwMapViewOfSection(hMemory,
		NtCurrentProcess(), &mem,
		0, msize, &lage, &sizeView, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "Failed to map view of section: 0x%lx\n", status);
		ObDereferenceObject(sectionObj);
		ZwClose(hMemory);
		return status;
	}
	DbgPrintEx(77, 0, "Mapped view of section at: %p\n", mem);
	// ж�ظ���



	//����CR3	
	PVOID srcCr3 = (PVOID)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!srcCr3) {
		DbgPrintEx(77, 0, "Failed to allocate memory for srcCr3\n");
		ZwClose(hMemory);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(srcCr3, 0, PAGE_SIZE);
	memcpy(srcCr3, mem, msize);
	DbgPrintEx(77, 0, "Copied CR3 data to srcCr3\n");


	//������滻CR3 �����˳���������ĳЩAPI������Ῠ��������
	PHYSICAL_ADDRESS srcphyCr3 = MmGetPhysicalAddress(srcCr3);

	//����һ���µ�CR3
	//*(PULONG)((PUCHAR)srcProcess + 0x18) = srcphyCr3.LowPart;
	*(PULONG)((PUCHAR)srcProcess + 0x28) = srcphyCr3.LowPart;
	DbgPrintEx(77, 0, "Set new CR3 value: 0x%lx\n", srcphyCr3.LowPart);


	PEPROCESS ceProcess = NULL;
	status = PsLookupProcessByProcessId(8408, &ceProcess);
	if (NT_SUCCESS(status))
	{
		DbgPrintEx(77, 0, "Found process by ID: 6632\n");
		PVOID handle_table = *(PVOID*)((LONG_PTR)ceProcess + 0x570);
		ExEnumHandleTable(handle_table, enumRoutine, TargetProcess, NULL);
	}      // ExEnumHandleTable����ʹ�����ֵ*(PULONG)((PUCHAR)ceProcess + 0x570)�������ý��̵ľ����
	else {
		DbgPrintEx(77, 0, "Failed to find process by ID: 6632, status: 0x%lx\n", status);
	}
	//ZwClose(hMemory);
	DbgPrintEx(77, 0, "Closed physical memory handle\n");

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}