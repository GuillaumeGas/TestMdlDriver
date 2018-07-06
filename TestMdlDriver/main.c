#include <ntddk.h>

/*
Creates and returns an MDL from a given virtual address, the newAddress parameter is filled with the new virtual address.
This new virtual address with point to the same physical area that the sourceAddress is pointed to.
GetNewMdlFor() also check if the needed pages are accessible with the given access right and processor mode.

@param sourceAddress : the source virtual address
@param newAddress    : a pointer that will be filled with the new virtual address
@param size          : size in bytes
@param processorMode : can be KernelMode or UserMode
@param neededAccess  : can be IoReadAccess, IoWriteAccess or IoModifyAccess

@returns : a valid MDL pointer or NULL
*/
static PMDL GetNewMdlFor(_In_ PVOID sourceAddress, _Inout_  PVOID* newAddress, _In_ ULONG size, _In_ KPROCESSOR_MODE processorMode, _In_ LOCK_OPERATION neededAccess)
{
	PMDL pMdl = NULL;

	// Wdk macro that gives a address aligned on a page size
	PVOID alignedVa = PAGE_ALIGN(sourceAddress);
	// We determine a new size based on a page size
	ULONG pagedSize = ADDRESS_AND_SIZE_TO_SPAN_PAGES(sourceAddress, size) * PAGE_SIZE;
	PCHAR alignedNewAddress = NULL;

	if (sourceAddress == NULL)
		return NULL;
	if (newAddress == NULL)
		return NULL;
	if (size == 0)
		return NULL;
	if (processorMode != KernelMode && processorMode != UserMode)
		return NULL;

	// allocate a mdl from the given address
	pMdl = IoAllocateMdl(alignedVa, pagedSize, FALSE, FALSE, NULL);
	if (pMdl == NULL)
		return NULL;

	__try
	{
		// Probes the specified virtual memory pages, makes them resident and locks them in memory
		MmProbeAndLockPages(pMdl, processorMode, neededAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return NULL;
	}

	// retrieve the new virtual address
	alignedNewAddress = (PCHAR)MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (alignedNewAddress == NULL)
	{
		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);
		return NULL;
	}

	*newAddress = (PVOID)(alignedNewAddress + ((PCHAR)sourceAddress - (PCHAR)alignedVa));
	return pMdl;
}

/*
Restores opcodes at the destination address.

@param destinationAddress   : start address of the opcodes that must be restored
@param repairOpcodesAddress : start address of the opcodes to copy
@param size                 : number of bytes that will be restored
*/
static VOID RestoreOpcodes(_In_ PVOID destinationAddress, _In_ PUCHAR repairOpcodesAddress, _In_ ULONG size)
{
	PMDL pMdl = NULL;
	PUCHAR newAddr = NULL;
	ULONG index = 0;

	// We get an MDL and a new virtual address on the area that must be restored
	pMdl = GetNewMdlFor(destinationAddress, (PVOID*)&newAddr, size, KernelMode, IoWriteAccess);
	if (pMdl == NULL)
		return;

	// We restore our opcodes
	__try
	{
		for (index = 0; index < size; index++)
			newAddr[index] = repairOpcodesAddress[index];
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		;
	}

	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	// We will replace the DriverEntry prolog by these bytes
	CHAR testOpcodes[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	// We override our DriverEntry prolog with some test bytes
	RestoreOpcodes((PVOID)(DriverEntry), (PVOID)testOpcodes, 16);

	return STATUS_SUCCESS;
}

