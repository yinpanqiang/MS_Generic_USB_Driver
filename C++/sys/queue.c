/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
PURPOSE.

Module Name:

Queue.c

Abstract:

This file contains dispatch routines for create,
close, device-control, read & write.

Environment:

Kernel mode

--*/

#include "private.h"


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, UsbSamp_EvtDeviceFileCreate)
#pragma alloc_text(PAGE, UsbSamp_EvtIoDeviceControl)
#pragma alloc_text(PAGE, UsbSamp_EvtIoRead)
#pragma alloc_text(PAGE, UsbSamp_EvtIoWrite)
#pragma alloc_text(PAGE, GetPipeFromName)
#pragma alloc_text(PAGE, ResetPipe)
#pragma alloc_text(PAGE, ResetDevice)
#endif

#ifndef IOCTL_REGISTER_ACCESS
#define IOCTL_REGISTER_ACCESS
//#define IOCTL_USBSAMP_RESET_PIPE            CTL_CODE(FILE_DEVICE_UNKNOWN,     \
//                                                     IOCTL_INDEX + 2, \
//                                                     METHOD_BUFFERED,         \
//                                                     FILE_ANY_ACCESS)

//++ added by devin_li
#define IOCTL_READ_REGISTERS		CTL_CODE(FILE_DEVICE_UNKNOWN,IOCTL_INDEX+3, METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_WRITE_REGISTERS		CTL_CODE(FILE_DEVICE_UNKNOWN,IOCTL_INDEX+4, METHOD_BUFFERED,FILE_ANY_ACCESS)

//--
#endif

VOID
UsbSamp_EvtDeviceFileCreate(
_In_ WDFDEVICE            Device,
_In_ WDFREQUEST           Request,
_In_ WDFFILEOBJECT        FileObject
)
/*++

Routine Description:

The framework calls a driver's EvtDeviceFileCreate callback
when the framework receives an IRP_MJ_CREATE request.
The system sends this request when a user application opens the
device to perform an I/O operation, such as reading or writing a file.
This callback is called synchronously, in the context of the thread
that created the IRP_MJ_CREATE request.

Arguments:

Device - Handle to a framework device object.
FileObject - Pointer to fileobject that represents the open handle.
CreateParams - copy of the create IO_STACK_LOCATION

Return Value:

NT status code

--*/
{
	NTSTATUS                    status = STATUS_UNSUCCESSFUL;
	PUNICODE_STRING             fileName;
	PFILE_CONTEXT               pFileContext;
	PDEVICE_CONTEXT             pDevContext;
	WDFUSBPIPE                  pipe;

	UsbSamp_DbgPrint(3, ("EvtDeviceFileCreate - begins"));

	PAGED_CODE();

	//
	// initialize variables
	//
	pDevContext = GetDeviceContext(Device);
	pFileContext = GetFileContext(FileObject);


	fileName = WdfFileObjectGetFileName(FileObject);

	if (0 == fileName->Length) {
		//
		// opening a device as opposed to pipe.
		//
		status = STATUS_SUCCESS;
	}
	else {
		pipe = GetPipeFromName(pDevContext, fileName);

		if (pipe != NULL) {
			//
			// found a match
			//
			pFileContext->Pipe = pipe;

			WdfUsbTargetPipeSetNoMaximumPacketSizeCheck(pipe);

			status = STATUS_SUCCESS;
		}
		else {
			status = STATUS_INVALID_DEVICE_REQUEST;
		}
	}

	WdfRequestComplete(Request, status);

	UsbSamp_DbgPrint(3, ("EvtDeviceFileCreate - ends"));

	return;
}

VOID
UsbSamp_EvtIoDeviceControl(
_In_ WDFQUEUE   Queue,
_In_ WDFREQUEST Request,
_In_ size_t     OutputBufferLength,
_In_ size_t     InputBufferLength,
_In_ ULONG      IoControlCode
)
/*++

Routine Description:

This event is called when the framework receives IRP_MJ_DEVICE_CONTROL
requests from the system.

Arguments:

Queue - Handle to the framework queue object that is associated
with the I/O request.
Request - Handle to a framework request object.

OutputBufferLength - length of the request's output buffer,
if an output buffer is available.
InputBufferLength - length of the request's input buffer,
if an input buffer is available.

IoControlCode - the driver-defined or system-defined I/O control code
(IOCTL) that is associated with the request.
Return Value:
 
VOID

--*/
{
	WDFDEVICE          device;
	PVOID              ioBuffer;
	size_t             bufLength;
	NTSTATUS           status;
	PDEVICE_CONTEXT    pDevContext;
	PFILE_CONTEXT      pFileContext;
	ULONG              length = 0;


	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);

	UsbSamp_DbgPrint(3, ("Entered UsbSamp_DispatchDevCtrl\n"));

	PAGED_CODE();

	//
	// initialize variables
	//
	device = WdfIoQueueGetDevice(Queue);
	pDevContext = GetDeviceContext(device);
	
	// to acqurie current Irq level
	KIRQL CurrentIrqLevel;
	CurrentIrqLevel = KeGetCurrentIrql();
	UsbSamp_DbgPrint(3, ("IoCtrl: CurrentIrqlevel is %d\n", CurrentIrqLevel));

	switch (IoControlCode) {

	case IOCTL_USBSAMP_RESET_PIPE:

		pFileContext = GetFileContext(WdfRequestGetFileObject(Request));

		if (pFileContext->Pipe == NULL) {
			status = STATUS_INVALID_PARAMETER;
		}
		else {
			status = ResetPipe(pFileContext->Pipe);
		}

		break;

	case IOCTL_USBSAMP_GET_CONFIG_DESCRIPTOR:


		if (pDevContext->UsbConfigurationDescriptor) {

			length = pDevContext->UsbConfigurationDescriptor->wTotalLength;

			status = WdfRequestRetrieveOutputBuffer(Request, length, &ioBuffer, &bufLength);
			if (!NT_SUCCESS(status)){
				UsbSamp_DbgPrint(1, ("WdfRequestRetrieveInputBuffer failed\n"));
				break;
			}

			RtlCopyMemory(ioBuffer,
				pDevContext->UsbConfigurationDescriptor,
				length);

			status = STATUS_SUCCESS;
		}
		else {
			status = STATUS_INVALID_DEVICE_STATE;
		}

		break;

	case IOCTL_USBSAMP_RESET_DEVICE:

		status = ResetDevice(device);
		break;

	case IOCTL_READ_REGISTERS:
	case IOCTL_WRITE_REGISTERS:

		UsbSamp_DbgPrint(3, ("read register of 8188FU\n\n Just for test"));

		HANDLE IoCtlCurrentHandle;
		//KeGetCurrentProcessId();
		IoCtlCurrentHandle = PsGetCurrentProcessId();
		UsbSamp_DbgPrint(3, ("IoCtlCurrentHandle=%x", IoCtlCurrentHandle));

		if (IoControlCode == IOCTL_READ_REGISTERS)
		{
			status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &ioBuffer, &bufLength);
		}
		else
		{
			status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &ioBuffer, &bufLength);
			/*WDFMEMORY InputMemory;
			status = WdfRequestRetrieveInputMemory(Request, &InputMemory);*/

			// *((unsigned char *)*(ptr + 4)) will result in system crash
			//UINT *ptr;
			//ptr = ioBuffer;
			//UsbSamp_DbgPrint(3, ("IoCtrl  *(ptr + 4)=%x\n", *(ptr + 4)));
			//UsbSamp_DbgPrint(3, ("IoCtrl  *(*(ptr + 4))=%x\n", *((unsigned char *)*(ptr + 4))));
		}
		if (!NT_SUCCESS(status)){
			UsbSamp_DbgPrint(1, ("WdfRequestRetrieveInputBuffer or WdfRequestRetrieveOutputBuffer failed\n"));
			break;
		}
		// use a workitem to send vendor's I/O command at passive level
		/*IoCmdPassiveLevelCallback(
		_In_	WDFDEVICE		Device,
		_In_	WDFUSBDEVICE	UsbTargeDevice,
		_In_	UINT			IoCode,
		_Inout_ PVOID			ioBuffer,
		_In_	size_t			BufLength,
		_Inout_	size_t			*Length_Output
		)*/
		
		UsbSamp_DbgPrint(3, ("IoCtrl: pDeviceContext->WdfUsbTargetDevice = %x\n", pDevContext->WdfUsbTargetDevice));
		UsbSamp_DbgPrint(3, ("IoCtrl: device = %x\n", device));
		UsbSamp_DbgPrint(3, ("length=%d  status=%d Request=%x \n", length, status, Request));

#if 0
		if (IoControlCode == IOCTL_READ_REGISTERS)
		{
			status = IoCmdPassiveLevelCallback(device, pDevContext->WdfUsbTargetDevice, IOCTL_READ_REGISTERS, ioBuffer, bufLength, &length);
		}
		else
		{

			status = IoCmdPassiveLevelCallback(device, pDevContext->WdfUsbTargetDevice, IOCTL_WRITE_REGISTERS, ioBuffer, bufLength, &length);
		}
		// to wait some time.  because that the timeout of user app is only 5ms.
		ULONG ulMicroSecond = 4000;
		LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-10 * ulMicroSecond);

		UsbSamp_DbgPrint(3, ("IoCtrl: before waitforsingleobject IoRegEvent = %x\n", IoRegEvent));
		KeWaitForSingleObject(&IoRegEvent, Executive, KernelMode, FALSE, &timeout);
		UsbSamp_DbgPrint(3, ("IoCtrl: after waitforsingleobject IoRegEvent = %x\n", IoRegEvent));
		KeClearEvent(&IoRegEvent);
		UsbSamp_DbgPrint(3, ("IoCtrl: after clear, IoRegEvent = %x\n", IoRegEvent));
#endif


		WDF_REQUEST_SEND_OPTIONS	options;
		USHORT						wValue, wIndex, Length_Input;
		BYTE						bReq;
		WDF_MEMORY_DESCRIPTOR		memDesc;
		ULONG						bytesTransferred;
		UINT						*ptr;
		WDF_USB_CONTROL_SETUP_PACKET controlSetupPacket;

		//setup control_setup_packet
		ptr = ioBuffer;
		UsbSamp_DbgPrint(3, ("WorkItem  Receive Info: %x %x %x %x", *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3)));
		bReq = (BYTE)*(ptr + 1);
		wValue = (USHORT)*(ptr + 2);
		Length_Input = (USHORT)*(ptr + 3);
		wIndex = 0;


		/*UsbSamp_DbgPrint(3, ("WorkItem  *(ptr + 4)=%x\n", *(ptr + 4)));
		UsbSamp_DbgPrint(3, ("WorkItem  *(*(ptr + 4))=%x\n", *((unsigned char *)*(ptr + 4))));*/

		// fatal system error 0x0000007e(0xC0000005, 0xA370FAA8, 0x801D29E8, 0x801D25B0)
		//unsigned char *UserCharPtr;
		//UserCharPtr = (unsigned char *)*(ptr + 4);
		//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *UserCharPtr));
		//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *(UserCharPtr + 1)));
		//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *(UserCharPtr + 2)));
		//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *(UserCharPtr + 3)));


		if (IoControlCode == IOCTL_READ_REGISTERS)
		{
			WDF_USB_CONTROL_SETUP_PACKET_INIT_VENDOR(
				&controlSetupPacket,
				BmRequestDeviceToHost,
				BmRequestToDevice,
				bReq,
				wValue,
				wIndex);

			WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(
				&memDesc,
				ioBuffer,//(void *)(ptr+4),
				//pItemContext->BufLength);
				Length_Input);
			UsbSamp_DbgPrint(3, ("Read Register Receive Length_Input = %d", Length_Input));
		}
		else
		{
			WDF_USB_CONTROL_SETUP_PACKET_INIT_VENDOR(
				&controlSetupPacket,
				BmRequestHostToDevice,
				BmRequestToDevice,
				bReq,
				wValue,
				wIndex);
			UCHAR WriteData[4] = { 0x17, 0x70, 0x02, 0x00 };
			WriteData[0] = (UCHAR)(*(ptr + 4) & 0x000000FF);
			WriteData[1] = (UCHAR)((*(ptr + 4) & 0x0000FF00) >> 8);
			WriteData[2] = (UCHAR)((*(ptr + 4) & 0x00FF0000) >> 16);
			WriteData[3] = (UCHAR)((*(ptr + 4) & 0xFF000000) >> 24);
			UsbSamp_DbgPrint(3, ("*(ptr+3)=%08x \n", *(ptr + 3)));
			UsbSamp_DbgPrint(3, ("*(ptr+4)=%08x \n", *(ptr + 4)));
			UsbSamp_DbgPrint(3, ("*WriteData[0]=%02x \n", WriteData[0]));
			UsbSamp_DbgPrint(3, ("*WriteData[1]=%02x \n", WriteData[1]));
			UsbSamp_DbgPrint(3, ("*WriteData[2]=%02x \n", WriteData[2]));
			UsbSamp_DbgPrint(3, ("*WriteData[3]=%02x \n", WriteData[3]));

			WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(
				&memDesc,
				WriteData,//(void *)(ptr+4),
				//pItemContext->BufLength);
				(ULONG)*(ptr + 3));
			UsbSamp_DbgPrint(3, ("Write Register Receive Length_Input = %d", Length_Input));
		}

		controlSetupPacket.Packet.wLength = Length_Input;



		//set time-out limit of WdfUsbTargetDeviceSendControlTransferSynchromously
		WDF_REQUEST_SEND_OPTIONS_INIT(&options, 0);
		WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&options, WDF_REL_TIMEOUT_IN_SEC(5));



		UsbSamp_DbgPrint(3, ("WorkItem: pItemContext->UsbTargetDevice = %x\n", pDevContext->WdfUsbTargetDevice));
		UsbSamp_DbgPrint(3, ("WorkItem: pItemContext->Device = %x\n", device));

		status = WdfUsbTargetDeviceSendControlTransferSynchronously(
			pDevContext->WdfUsbTargetDevice,
			WDF_NO_HANDLE, // Specific WDFREQUEST
			&options, // PWDF_REQUEST_SEND_OPTIONS
			&controlSetupPacket,
			&memDesc,
			&bytesTransferred//NULL
			);
		UsbSamp_DbgPrint(3, ("WorkItem: bytesTransferred = %d \n", bytesTransferred));
		if (NT_SUCCESS(status))
		{
			//if (!bWrite)
			//*pBufferLengthRead = bytesTransferred;
			UsbSamp_DbgPrint(3, ("Read/Write register successful \n"));
			//bresult = true;
			length = bytesTransferred;
		}
		else
		{ // Error handling.
			UsbSamp_DbgPrint(3, ("Read/Write register WdfUsbTargetDeviceSendControlTransferSynchronously(),errorcode = %X, =%d \n", status, status));
			length = 0;
		}
		UsbSamp_DbgPrint(3, ("length=%d  status=%d Request=%x \n",length,status,Request));

		if (IoControlCode == IOCTL_READ_REGISTERS)
		{
			UsbSamp_DbgPrint(3, ("Read register offset = %04x, len = %d, value = %08x", wValue, Length_Input, *((UINT *)(ioBuffer))));
		}
		break;
#if 0
	case IOCTL_WRITE_REGISTERS:

		UsbSamp_DbgPrint(3, ("write register of 8188FU\n\n Just for test"));

			status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &ioBuffer, &bufLength);
			/*WDFMEMORY InputMemory;
			status = WdfRequestRetrieveInputMemory(Request, &InputMemory);*/

			// *((unsigned char *)*(ptr + 4)) will result in system crash
			UINT *ptr;
			ptr = ioBuffer;

			__try
			{
				ProbeForWrite((VOID *)*(ptr+4),*(ptr+3),sizeof(UCHAR));
				UsbSamp_DbgPrint(3, ("Leave __try block \n"));
				UsbSamp_DbgPrint(3, ("(UCHAR *)*(ptr+4) \n", (UCHAR *)*(ptr + 4)));
				UsbSamp_DbgPrint(3, (" *((UCHAR *)*(ptr + 4)) \n", *((UCHAR *)*(ptr + 4)) ) );
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				UsbSamp_DbgPrint(1, ("Catch this exception\n This point is not readable \n"));
				status = STATUS_UNSUCCESSFUL;
			}
			//UsbSamp_DbgPrint(3, ("IoCtrl  *(ptr + 4)=%x\n", *(ptr + 4)));
			//UsbSamp_DbgPrint(3, ("IoCtrl  *(*(ptr + 4))=%x\n", *((unsigned char *)*(ptr + 4))));

		if (!NT_SUCCESS(status)){
			UsbSamp_DbgPrint(1, ("WdfRequestRetrieveInputBuffer or WdfRequestRetrieveOutputBuffer failed\n"));
			break;
		}
	
		//PURB urb;
		//urb = ExAllocatePool(NonPagedPool, sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST));
		////PVOID pOutRegisterData = ((PSetupToken_BLOCK)ioBuffer)->pbyData;
		//if (urb)
		//{
		//	UsbSamp_DbgPrint(3, ("begin to create urb vendor request \n"));
		//	UsbBuildVendorRequest(
		//		urb,
		//		URB_FUNCTION_VENDOR_DEVICE,
		//		sizeof(struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST),
		//		0,
		//		0x40,
		//		0x0C,
		//		(USHORT)(*(ptr+2)),//(USHORT)((PSetupToken_BLOCK)ioBuffer)->uOffset,
		//		(USHORT)0x00,//(USHORT)((PSetupToken_BLOCK)ioBuffer)->uIndex,
		//		(PVOID*)(*(ptr+4)),//pOutRegisterData,
		//		NULL,
		//		(USHORT)(*(ptr+3)),//(USHORT)((PSetupToken_BLOCK)ioBuffer)->uLength,
		//		NULL);

		//	(urb)->UrbHeader.Function = URB_FUNCTION_CONTROL_TRANSFER;
		//	(urb)->UrbHeader.Length = sizeof(struct _URB_CONTROL_TRANSFER);
		//	(urb)->UrbControlTransfer.PipeHandle = 0;
		//	(urb)->UrbControlTransfer.TransferFlags = 1 << 3;
		//	(urb)->UrbControlTransfer.TransferBufferLength = (USHORT)(*(ptr + 3));
		//	(urb)->UrbControlTransfer.TransferBuffer = (PVOID*)(*(ptr + 4));
		//	(urb)->UrbControlTransfer.TransferBufferMDL = NULL;
		//	(urb)->UrbControlTransfer.UrbLink = NULL;


		//	(urb)->UrbControlTransfer.SetupPacket[0] = 0x40;// (UCHAR)((PSetupToken_BLOCK)ioBuffer)->bmRequestType;
		//	(urb)->UrbControlTransfer.SetupPacket[1] = 0x0c;// (UCHAR)((PSetupToken_BLOCK)ioBuffer)->bmRequest;
		//	(urb)->UrbControlTransfer.SetupPacket[2] = (*(ptr + 2)) & 0xFF;//((USHORT)((PSetupToken_BLOCK)ioBuffer)->uOffset) & 0xff;
		//	(urb)->UrbControlTransfer.SetupPacket[3] = ((*(ptr + 2)) & 0xFF00)>>8;//(((USHORT)((PSetupToken_BLOCK)ioBuffer)->uOffset) & 0xff00) >> 8;
		//	(urb)->UrbControlTransfer.SetupPacket[4] = 0x00;//((USHORT)((PSetupToken_BLOCK)ioBuffer)->uIndex) & 0xff;
		//	(urb)->UrbControlTransfer.SetupPacket[5] = 0x00;//(((USHORT)((PSetupToken_BLOCK)ioBuffer)->uIndex) & 0xff00) >> 8;
		//	(urb)->UrbControlTransfer.SetupPacket[6] = (*(ptr + 3)) & 0xFF;//((USHORT)((PSetupToken_BLOCK)ioBuffer)->uLength) & 0xff;
		//	(urb)->UrbControlTransfer.SetupPacket[7] = ((*(ptr + 3)) & 0xFF00) >> 8;//(((USHORT)((PSetupToken_BLOCK)ioBuffer)->uLength) & 0xff00) >> 8;

		//	//status = CallUSBD(DeviceObject, urb);
		//	WDF_REQUEST_SEND_OPTIONS SyncReqOptions;
		//	WDF_REQUEST_SEND_OPTIONS_INIT(&SyncReqOptions, 0);
		//	WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&SyncReqOptions, -1000000);//-100ms units:100ns
		//	UsbSamp_DbgPrint(3, ("begin to send urb synchronously \n"));
		//	status = WdfUsbTargetDeviceSendUrbSynchronously(
		//		pDevContext->WdfUsbTargetDevice,
		//		NULL,
		//		&SyncReqOptions,
		//		urb);

		//	ExFreePool(urb);
		//}
		//else
		//{
		//	UsbSamp_DbgPrint(3, ("fail to create urb\n"));
		//}
		break;
#endif
	/*case IOCTL_WRITE_REGISTERS:
		UsbSamp_DbgPrint(3, ("write register of 8188FU\n\n"));
		status = 0;
		break;*/
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	WdfRequestCompleteWithInformation(Request, status, length);

	UsbSamp_DbgPrint(3, ("Exit UsbSamp_DispatchDevCtrl\n"));

	return;
}

//++ added by devin_li
NTSTATUS
IoCmdPassiveLevelCallback(
_In_	WDFDEVICE		Device,
_In_	WDFUSBDEVICE	UsbTargeDevice,
_In_	UINT			IoCode,
_Inout_ PVOID			ioBuffer,
_In_	size_t			BufLength,
_Inout_	ULONG			*Length_Output
)
/*++
Routine Description:
This routine is used to queue workitems so that the callback functions
can be executed at PASSIVE_LEVEL in the context of a system thread.
Arguments:

Return value:
--*/
{
	NTSTATUS                        status = STATUS_SUCCESS;
	PWORKITEM_IOREG_CONTEXT         context;
	WDF_OBJECT_ATTRIBUTES           attributes;
	WDF_WORKITEM_CONFIG             workitemConfig;
	WDFWORKITEM                     IoRegWorkItem;

	UsbSamp_DbgPrint(3, ("IoCmdPassiveLevelCallback function is called\n"));
	KIRQL CurrentIrqLevel;
	CurrentIrqLevel = KeGetCurrentIrql();
	UsbSamp_DbgPrint(3, ("IoCmdPassiveLevelCallback: CurrentIrqlevel is %d\n", CurrentIrqLevel));

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&attributes, WORKITEM_IOREG_CONTEXT);
	attributes.ParentObject = Device;

	//WDF_WORKITEM_CONFIG_INIT(&workitemConfig, UsbSamp_EvtReadWriteWorkItem);
	WDF_WORKITEM_CONFIG_INIT(&workitemConfig, UsbSamp_EvtRegisterReadWriteWorkItem);

	status = WdfWorkItemCreate(&workitemConfig,
		&attributes,
		&IoRegWorkItem);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	context = GetWorkItemIoRegContext(IoRegWorkItem);

	context->Device = Device;
	context->UsbTargetDevice = UsbTargeDevice;
	context->IoCode = IoCode;
	context->BufLength = BufLength;
	context->ioBuffer = ioBuffer;
	context->Length_Output = Length_Output;
	//
	// Execute this work item.
	// add this workitem to system's workitem queue
	WdfWorkItemEnqueue(IoRegWorkItem);

	UsbSamp_DbgPrint(3, ("IoCmdPassiveLevelCallback function end \n"));
	return STATUS_SUCCESS;
}
//-- added by devin_li

//++ added by devin_li
VOID
UsbSamp_EvtRegisterReadWriteWorkItem(
_In_ WDFWORKITEM  IoRegWorkItem
)
{
	PWORKITEM_IOREG_CONTEXT		pItemContext;
	NTSTATUS					status;
	WDF_REQUEST_SEND_OPTIONS	options;
	USHORT						wValue, wIndex, Length_Input;
	BYTE						bReq;
	WDF_MEMORY_DESCRIPTOR		memDesc;
	ULONG						bytesTransferred;
	UINT						*ptr;
	WDF_USB_CONTROL_SETUP_PACKET controlSetupPacket;

	HANDLE WorkItemCurrentHandle;
	//KeGetCurrentProcessId();
	WorkItemCurrentHandle = PsGetCurrentProcessId();
	UsbSamp_DbgPrint(3, ("WorkItemCurrentHandle=%x", WorkItemCurrentHandle));

	UsbSamp_DbgPrint(3, ("Register ReadWriteWorkItem function is called\n"));
	KIRQL CurrentIrqLevel;
	CurrentIrqLevel = KeGetCurrentIrql();
	UsbSamp_DbgPrint(3, ("UsbSamp_EvtRegisterReadWriteWorkItem: CurrentIrqlevel is %d\n", CurrentIrqLevel));

	pItemContext = GetWorkItemIoRegContext(IoRegWorkItem);
	//typedef struct _WORKITEM_IOREG_CONTEXT{
	//	WDFDEVICE		Device;
	//	WDFUSBDEVICE	UsbTargetDevice;
	//	UINT			IoCode;
	//	PVOID			ioBuffer;
	//	size_t			BufLength;
	//  ULONG			*Length_Output;
	//} WORKITEM_IOREG_CONTEXT, *PWORKITEM_IOREG_CONTEXT;




	//setup control_setup_packet
	ptr = pItemContext->ioBuffer;
	UsbSamp_DbgPrint(3, ("WorkItem  Receive Info: %x %x %x %x", *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3)));
	bReq = (BYTE)*(ptr + 1);
	wValue = (USHORT)*(ptr + 2);
	Length_Input = (USHORT)*(ptr + 3);
	wIndex = 0;
	

	/*UsbSamp_DbgPrint(3, ("WorkItem  *(ptr + 4)=%x\n", *(ptr + 4)));
	UsbSamp_DbgPrint(3, ("WorkItem  *(*(ptr + 4))=%x\n", *((unsigned char *)*(ptr + 4))));*/

	// fatal system error 0x0000007e(0xC0000005, 0xA370FAA8, 0x801D29E8, 0x801D25B0)
	//unsigned char *UserCharPtr;
	//UserCharPtr = (unsigned char *)*(ptr + 4);
	//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *UserCharPtr));
	//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *(UserCharPtr + 1)));
	//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *(UserCharPtr + 2)));
	//UsbSamp_DbgPrint(3, ("*UserCharPtr=%x", *(UserCharPtr + 3)));

	
	if (pItemContext->IoCode == IOCTL_READ_REGISTERS)
	{
		WDF_USB_CONTROL_SETUP_PACKET_INIT_VENDOR(
				&controlSetupPacket,
				BmRequestDeviceToHost,
				BmRequestToDevice,
				bReq,
				wValue,
				wIndex);

		WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(
			&memDesc,
			pItemContext->ioBuffer,//(void *)(ptr+4),
			//pItemContext->BufLength);
			Length_Input);
		UsbSamp_DbgPrint(3, ("Receive bufLength: %d Length = %d", pItemContext->BufLength, Length_Input));
	}
	else
	{
		WDF_USB_CONTROL_SETUP_PACKET_INIT_VENDOR(
			&controlSetupPacket,
			BmRequestHostToDevice,
			BmRequestToDevice,
			bReq,
			wValue,
			wIndex);
		UCHAR WriteData[4] = { 0x17, 0x70, 0x02, 0x00 };
		WriteData[0] = (UCHAR)(*(ptr + 4) & 0x000000FF);
		WriteData[1] = (UCHAR)((*(ptr + 4) & 0x0000FF00)>>8);
		WriteData[2] = (UCHAR)((*(ptr + 4) & 0x00FF0000)>>16);
		WriteData[3] = (UCHAR)((*(ptr + 4) & 0xFF000000)>>24);
		UsbSamp_DbgPrint(3, ("*(ptr+3)=%08x \n", *(ptr + 3)));
		UsbSamp_DbgPrint(3, ("*(ptr+4)=%08x \n", *(ptr + 4)));
		UsbSamp_DbgPrint(3, ("*WriteData[0]=%02x \n", WriteData[0]));
		UsbSamp_DbgPrint(3, ("*WriteData[1]=%02x \n", WriteData[1]));
		UsbSamp_DbgPrint(3, ("*WriteData[2]=%02x \n", WriteData[2]));
		UsbSamp_DbgPrint(3, ("*WriteData[3]=%02x \n", WriteData[3]));

		WDF_MEMORY_DESCRIPTOR_INIT_BUFFER(
			&memDesc,
			WriteData,//(void *)(ptr+4),
			//pItemContext->BufLength);
			(ULONG)*(ptr + 3));
		UsbSamp_DbgPrint(3, ("Receive bufLength: %d Length = %d", pItemContext->BufLength, Length_Input));
	}
	
	controlSetupPacket.Packet.wLength = Length_Input;

	

	//set time-out limit of WdfUsbTargetDeviceSendControlTransferSynchromously
	WDF_REQUEST_SEND_OPTIONS_INIT(&options, 0);
	WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&options, WDF_REL_TIMEOUT_IN_SEC(5));
	
	

	UsbSamp_DbgPrint(3, ("WorkItem: pItemContext->UsbTargetDevice = %x\n", pItemContext->UsbTargetDevice));
	UsbSamp_DbgPrint(3, ("WorkItem: pItemContext->Device = %x\n", pItemContext->Device));

	status = WdfUsbTargetDeviceSendControlTransferSynchronously(
		pItemContext->UsbTargetDevice,
		WDF_NO_HANDLE, // Specific WDFREQUEST
		&options, // PWDF_REQUEST_SEND_OPTIONS
		&controlSetupPacket,
		&memDesc,
		&bytesTransferred//NULL
		);
	UsbSamp_DbgPrint(3, ("WorkItem: bytesTransferred = %d\n", bytesTransferred));
	if (NT_SUCCESS(status))
	{
		//if (!bWrite)
		//*pBufferLengthRead = bytesTransferred;
		UsbSamp_DbgPrint(3, ("Read/Write register workitem WdfUsbTargetDeviceSendControlTransferSynchronously(),errorcode = %X, =%d", status, status));
		//bresult = true;
		*(pItemContext->Length_Output) = bytesTransferred;
	}
	else
	{ // Error handling.
		UsbSamp_DbgPrint(3, ("Read/Write register workitem WdfUsbTargetDeviceSendControlTransferSynchronously(),errorcode = %X, =%d", status, status));
		*(pItemContext->Length_Output) = 0;
	}

	WdfObjectDelete(IoRegWorkItem);

	UsbSamp_DbgPrint(3, ("*(pItemContext->Length_Output) = %d\n", *(pItemContext->Length_Output)));
	UsbSamp_DbgPrint(3, ("Register ReadWriteWorkItem function ends \n"));

	//KIRQL OldIrql;
	//KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
	KeSetEvent(&IoRegEvent, IO_NO_INCREMENT,FALSE);
	//KeLowerIrql(DISPATCH_LEVEL);
	return;
}
//-- added by devin_li

VOID
UsbSamp_EvtIoRead(
_In_ WDFQUEUE         Queue,
_In_ WDFREQUEST       Request,
_In_ size_t           Length
)
/*++

Routine Description:

Called by the framework when it receives Read requests.

Arguments:

Queue - Default queue handle
Request - Handle to the read/write request
Lenght - Length of the data buffer associated with the request.
The default property of the queue is to not dispatch
zero lenght read & write requests to the driver and
complete is with status success. So we will never get
a zero length request.

Return Value:


--*/
{
	PFILE_CONTEXT           fileContext = NULL;
	WDFUSBPIPE              pipe;
	WDF_USB_PIPE_INFORMATION   pipeInfo;

	PAGED_CODE();

	//
	// Get the pipe associate with this request.
	//
	fileContext = GetFileContext(WdfRequestGetFileObject(Request));
	pipe = fileContext->Pipe;
	if (pipe == NULL) {
		UsbSamp_DbgPrint(1, ("pipe handle is NULL\n"));
		WdfRequestCompleteWithInformation(Request, STATUS_INVALID_PARAMETER, 0);
		return;
	}
	WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);
	WdfUsbTargetPipeGetInformation(pipe, &pipeInfo);

	if ((WdfUsbPipeTypeBulk == pipeInfo.PipeType) ||
		(WdfUsbPipeTypeInterrupt == pipeInfo.PipeType)) {

		ReadWriteBulkEndPoints(Queue, Request, (ULONG)Length, WdfRequestTypeRead);
		return;

	}
	else if (WdfUsbPipeTypeIsochronous == pipeInfo.PipeType){

#if !defined(BUFFERED_READ_WRITE) // if doing DIRECT_IO
		ReadWriteIsochEndPoints(Queue, Request, (ULONG)Length, WdfRequestTypeRead);
		return;
#endif

	}

	UsbSamp_DbgPrint(1, ("ISO transfer is not supported for buffered I/O transfer\n"));
	WdfRequestCompleteWithInformation(Request, STATUS_INVALID_DEVICE_REQUEST, 0);

	return;
}

VOID
UsbSamp_EvtIoWrite(
_In_ WDFQUEUE         Queue,
_In_ WDFREQUEST       Request,
_In_ size_t           Length
)
/*++

Routine Description:

Called by the framework when it receives Write requests.

Arguments:

Queue - Default queue handle
Request - Handle to the read/write request
Lenght - Length of the data buffer associated with the request.
The default property of the queue is to not dispatch
zero lenght read & write requests to the driver and
complete is with status success. So we will never get
a zero length request.

Return Value:


--*/
{
	PFILE_CONTEXT           fileContext = NULL;
	WDFUSBPIPE              pipe;
	WDF_USB_PIPE_INFORMATION   pipeInfo;

	PAGED_CODE();

	//
	// Get the pipe associate with this request.
	//
	fileContext = GetFileContext(WdfRequestGetFileObject(Request));
	pipe = fileContext->Pipe;
	if (pipe == NULL) {
		UsbSamp_DbgPrint(1, ("pipe handle is NULL\n"));
		WdfRequestCompleteWithInformation(Request, STATUS_INVALID_PARAMETER, 0);
		return;
	}
	WDF_USB_PIPE_INFORMATION_INIT(&pipeInfo);
	WdfUsbTargetPipeGetInformation(pipe, &pipeInfo);

	if ((WdfUsbPipeTypeBulk == pipeInfo.PipeType) ||
		(WdfUsbPipeTypeInterrupt == pipeInfo.PipeType)) {

		ReadWriteBulkEndPoints(Queue, Request, (ULONG)Length, WdfRequestTypeWrite);
		return;

	}
	else if (WdfUsbPipeTypeIsochronous == pipeInfo.PipeType){

#if !defined(BUFFERED_READ_WRITE) // if doing DIRECT_IO
		ReadWriteIsochEndPoints(Queue, Request, (ULONG)Length, WdfRequestTypeWrite);
		return;
#endif

	}

	UsbSamp_DbgPrint(1, ("ISO transfer is not supported for buffered I/O transfer\n"));
	WdfRequestCompleteWithInformation(Request, STATUS_INVALID_DEVICE_REQUEST, 0);

	return;
}

WDFUSBPIPE
GetPipeFromName(
_In_ PDEVICE_CONTEXT DeviceContext,
_In_ PUNICODE_STRING FileName
)
/*++

Routine Description:

This routine will pass the string pipe name and
fetch the pipe handle.

Arguments:

DeviceContext - pointer to Device Context

FileName - string pipe name

Return Value:

The device extension maintains a pipe context for
the pipes on 82930 board.

--*/
{
	LONG                  ix;
	ULONG                 uval;
	ULONG                 nameLength;
	ULONG                 umultiplier;
	WDFUSBPIPE            pipe = NULL;

	PAGED_CODE();

	//
	// typedef WCHAR *PWSTR;
	//
	nameLength = (FileName->Length / sizeof(WCHAR));

	UsbSamp_DbgPrint(3, ("UsbSamp_PipeWithName - begins\n"));

	if (nameLength != 0) {

		UsbSamp_DbgPrint(3, ("Filename = %wZ nameLength = %d\n", FileName, nameLength));

		//
		// Parse the pipe#
		//
		ix = nameLength - 1;

		// if last char isn't digit, decrement it.
		while ((ix > -1) &&
			((FileName->Buffer[ix] < (WCHAR) '0') ||
			(FileName->Buffer[ix] > (WCHAR) '9')))             {

			ix--;
		}

		if (ix > -1) {

			uval = 0;
			umultiplier = 1;

			// traversing least to most significant digits.

			while ((ix > -1) &&
				(FileName->Buffer[ix] >= (WCHAR) '0') &&
				(FileName->Buffer[ix] <= (WCHAR) '9'))          {

				uval += (umultiplier *
					(ULONG)(FileName->Buffer[ix] - (WCHAR) '0'));

				ix--;
				umultiplier *= 10;
			}
			pipe = WdfUsbInterfaceGetConfiguredPipe(
				DeviceContext->UsbInterface,
				(UCHAR)uval, //PipeIndex,
				NULL
				);

		}
	}

	UsbSamp_DbgPrint(3, ("UsbSamp_PipeWithName - ends\n"));

	return pipe;
}

NTSTATUS
ResetPipe(
_In_ WDFUSBPIPE Pipe
)
/*++

Routine Description:

This routine resets the pipe.

Arguments:

Pipe - framework pipe handle

Return Value:

NT status value

--*/
{
	NTSTATUS status;

	PAGED_CODE();

	//
	//  This routine synchronously submits a URB_FUNCTION_RESET_PIPE
	// request down the stack.
	//
	status = WdfUsbTargetPipeResetSynchronously(Pipe,
		WDF_NO_HANDLE, // WDFREQUEST
		NULL  // PWDF_REQUEST_SEND_OPTIONS
		);

	if (NT_SUCCESS(status)) {
		UsbSamp_DbgPrint(3, ("ResetPipe - success\n"));
		status = STATUS_SUCCESS;
	}
	else {
		UsbSamp_DbgPrint(1, ("ResetPipe - failed\n"));
	}

	return status;
}

VOID
StopAllPipes(
_In_ PDEVICE_CONTEXT DeviceContext
)
{
	UCHAR count, i;

	count = DeviceContext->NumberConfiguredPipes;
	for (i = 0; i < count; i++) {
		WDFUSBPIPE pipe;
		pipe = WdfUsbInterfaceGetConfiguredPipe(DeviceContext->UsbInterface,
			i, //PipeIndex,
			NULL
			);
		WdfIoTargetStop(WdfUsbTargetPipeGetIoTarget(pipe),
			WdfIoTargetCancelSentIo);
	}
}


VOID
StartAllPipes(
_In_ PDEVICE_CONTEXT DeviceContext
)
{
	NTSTATUS status;
	UCHAR count, i;

	count = DeviceContext->NumberConfiguredPipes;
	for (i = 0; i < count; i++) {
		WDFUSBPIPE pipe;
		pipe = WdfUsbInterfaceGetConfiguredPipe(DeviceContext->UsbInterface,
			i, //PipeIndex,
			NULL
			);
		status = WdfIoTargetStart(WdfUsbTargetPipeGetIoTarget(pipe));
		if (!NT_SUCCESS(status)) {
			UsbSamp_DbgPrint(1, ("StartAllPipes - failed pipe #%d\n", i));
		}
	}
}

NTSTATUS
ResetDevice(
_In_ WDFDEVICE Device
)
/*++

Routine Description:

This routine calls WdfUsbTargetDeviceResetPortSynchronously to reset the device if it's still
connected.

Arguments:

Device - Handle to a framework device

Return Value:

NT status value

--*/
{
	PDEVICE_CONTEXT pDeviceContext;
	NTSTATUS status;

	UsbSamp_DbgPrint(3, ("ResetDevice - begins\n"));

	PAGED_CODE();

	pDeviceContext = GetDeviceContext(Device);

	//
	// A reset-device
	// request will be stuck in the USB until the pending transactions
	// have been canceled. Similarly, if there are pending tranasfers on the BULK
	// _In_/OUT pipe cancel them.
	// To work around this issue, the driver should stop the continuous reader
	// (by calling WdfIoTargetStop) before resetting the device, and restart the
	// continuous reader (by calling WdfIoTargetStart) after the request completes.
	//
	StopAllPipes(pDeviceContext);

	//
	// It may not be necessary to check whether device is connected before
	// resetting the port.
	//
	status = WdfUsbTargetDeviceIsConnectedSynchronous(pDeviceContext->WdfUsbTargetDevice);

	if (NT_SUCCESS(status)) {
		status = WdfUsbTargetDeviceResetPortSynchronously(pDeviceContext->WdfUsbTargetDevice);
	}

	StartAllPipes(pDeviceContext);

	UsbSamp_DbgPrint(3, ("ResetDevice - ends\n"));

	return status;
}
