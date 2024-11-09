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
	volatile LONGLONG VolatileLowValue;                                     // 0x0: 可变长整型，表示低位值的原子访问，主要用于同步。
	LONGLONG LowValue;                                                      // 0x0: 低位值，可能代表句柄的实际值。

	struct
	{
		struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                // 0x0: 指向句柄相关信息的表，允许快速访问句柄的元数据。
		LONGLONG HighValue;                                                 // 0x8: 高位值，通常与低位值组合形成完整的句柄。
		union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                    // 0x8: 指向下一个空闲句柄条目的指针，用于管理句柄表。
		struct _EXHANDLE LeafHandleValue;                                   // 0x8: 叶句柄值，通常表示实际的对象句柄。
	};

	LONGLONG RefCountField;                                                 // 0x0: 引用计数字段，用于跟踪句柄的引用次数。
	ULONGLONG Unlocked : 1;                                                  // 0x0: 解锁标志，指示该句柄是否未被锁定。
	ULONGLONG RefCnt : 16;                                                   // 0x0: 引用计数的实际值，指示当前引用的数量。
	ULONGLONG Attributes : 3;                                                // 0x0: 句柄属性，指示句柄的特性（如可继承性）。
	struct
	{
		ULONGLONG ObjectPointerBits : 44;                                    // 0x0: 对象指针位，表示对象的指针或句柄。
		ULONG GrantedAccessBits : 25;                                        // 0x8: 授予的访问权限位，表示该句柄允许的操作。
		ULONG NoRightsUpgrade : 1;                                           // 0x8: 不允许权限升级的标志，指示句柄是否可以提升权限。
		ULONG Spare1 : 6;                                                   // 0x8: 保留位，未使用的位。
	};

	ULONG Spare2;                                                           // 0xc: 额外的保留字段，用于对齐或未来扩展。
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
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,//HandleTableEntry 对应该进程每个枚举到的句柄表项。
	IN HANDLE Handle, //对应当前的句柄值。
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


			HandleTableEntry->LowValue = (ULONG_PTR)gObject | 1;//后面1位是锁


			HandleTableEntry->GrantedAccessBits |= PROCESS_ALL_ACCESS;
			result = TRUE;
		}
	}
	_InterlockedExchangeAdd64(HandleTableEntry, 1); // 注意 这里必须释放，参考ObpEnumFindHandleProcedure的实现
	if (*(PULONG_PTR)((ULONG_PTR)HandleTable + 0x30)) {
		ExfUnblockPushLock((ULONG_PTR)HandleTable + 0x30, 0); // 同上
	}
	return result;
}
BOOLEAN IsValidCR3(ULONG cr3) {
	// 检查CR3是否在有效范围内
	// 根据系统架构和版本调整有效范围
	return (cr3 != 0 && (cr3 & 0xFFF) == 0); // 示例：非零且4KB对齐
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

		//DbgPrintEx(77, 0, "Checking process ID: %d\n", i); // 打印当前检查的进程ID

		if (ProcessName->Length) {
			_wcsupr(ProcessName->Buffer);
			// 仅比较文件名而不是完整路径
			PWCH fileName = wcsrchr(ProcessName->Buffer, L'\\');
			if (fileName) {
				fileName++;// 跳过'\'字符
			}
			else {
				fileName = ProcessName->Buffer;// 没有'\'则直接使用整个名称
			}

			//DbgPrintEx(77, 0, "Comparing with: %ws\n", fileName);

			// 使用不区分大小写的比较
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
		DbgPrintEx(77, 0, "No process found with name: %ws\n", name); // 未找到目标进程
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
	//PEPROCESS srcProcess = (PUCHAR)gObject + 0x18;   //32位
	PEPROCESS srcProcess = (PUCHAR)gObject + 0x30;    //64位
	memset(gObject, 0, PAGE_SIZE);
	DbgPrintEx(77, 0, "gObject allocated at: %p\n", gObject);

	//复制进程
	PEPROCESS TargetProcess = FindProcessByName(L"dbgview64.exe");
	if (!TargetProcess) {
		DbgPrintEx(77, 0, "Failed to find target process\n");
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(77, 0, "Target process found: %p\n", TargetProcess);

	// 附加到目标进程
	KAPC_STATE kapcState = { 0 };
	KeStackAttachProcess(TargetProcess, &kapcState);
	memcpy(gObject, (PUCHAR)TargetProcess - 0x30, 0x300);
	DbgPrintEx(77, 0, "Copied process data to gObject\n");
	// 卸载附加
	KeUnstackDetachProcess(&kapcState);



	//复制体里面 干掉PID
	*(PHANDLE)((PUCHAR)srcProcess + GetProcessIdOffset()) = 0;
	DbgPrintEx(77, 0, "Cleared PID in srcProcess\n");


	KeStackAttachProcess(TargetProcess, &kapcState);
	//ULONG cr3 = *(PULONG)((PUCHAR)TargetProcess + 0x18);
	//win11是0x28
	ULONG cr3 = *(PULONG)((PUCHAR)TargetProcess + 0x28);
	DbgPrintEx(77, 0, "CR3 value: 0x%lx\n", cr3);
	if (!IsValidCR3(cr3)) { // 确保你有这个函数来验证CR3
		DbgPrintEx(77, 0, "Invalid CR3 value, exiting\n");
		return STATUS_INVALID_PARAMETER;
	}
	KeUnstackDetachProcess(&kapcState);


	//PHYSICAL_ADDRESS cr3Phy = {0};
	//cr3Phy.QuadPart = cr3;
	ULONG msize = 0x20;  // 2 4   8
	if ((cr3 % 0x1000) == 0)  //相当于映射的PML4页表 512 且是4K对齐的
	{
		//101012
		msize = PAGE_SIZE;
		//	DbgPrintEx(77, 0, "Adjusted msize to PAGE_SIZE\n");
	}

	// WIN10 1803以上，不能映射页表
	//有弊端  如果是小页。在一次映射多页时候 不一定成功，如果是大页一次映射2M 或者4M 必须是页开头，跨页就有问题
	//物理地址映射成线性地址
	//PVOID mem = MmMapIoSpace(cr3Phy, msize, MmNonCached);
	// 打开物理内存设备的Unicode字符串
	HANDLE hMemory = NULL;
	UNICODE_STRING unName = { 0 };
	RtlInitUnicodeString(&unName, L"\\Device\\PhysicalMemory");
	// 初始化对象属性
	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(&obj, &unName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = ZwOpenSection(&hMemory, SECTION_ALL_ACCESS, &obj);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "Failed to open physical memory section: 0x%lx\n", status);
		return status;
	}

	DbgPrintEx(77, 0, "Opened physical memory section\n");


	PVOID mem = NULL;// 用于保存映射视图的基地址
	SIZE_T sizeView = PAGE_SIZE; // 要映射的视图大小。
	LARGE_INTEGER lage = { 0 };
	lage.QuadPart = cr3;// 要映射的物理地址

	PVOID sectionObj = NULL;
	status = ObReferenceObjectByHandle(hMemory, SECTION_ALL_ACCESS, NULL, KernelMode, &sectionObj, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(77, 0, "Failed to reference section object: 0x%lx\n", status);
		ZwClose(hMemory);
		return status;
	}
	DbgPrintEx(77, 0, "Referenced section object\n");
	// 映射视图到当前进程的地址空间
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
	// 卸载附加



	//复制CR3	
	PVOID srcCr3 = (PVOID)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!srcCr3) {
		DbgPrintEx(77, 0, "Failed to allocate memory for srcCr3\n");
		ZwClose(hMemory);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(srcCr3, 0, PAGE_SIZE);
	memcpy(srcCr3, mem, msize);
	DbgPrintEx(77, 0, "Copied CR3 data to srcCr3\n");


	//如果不替换CR3 进程退出，或者在某些API的情况会卡死，蓝屏
	PHYSICAL_ADDRESS srcphyCr3 = MmGetPhysicalAddress(srcCr3);

	//给他一个新的CR3
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
	}      // ExEnumHandleTable它会使用这个值*(PULONG)((PUCHAR)ceProcess + 0x570)来遍历该进程的句柄表
	else {
		DbgPrintEx(77, 0, "Failed to find process by ID: 6632, status: 0x%lx\n", status);
	}
	//ZwClose(hMemory);
	DbgPrintEx(77, 0, "Closed physical memory handle\n");

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}