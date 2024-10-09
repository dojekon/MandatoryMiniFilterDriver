#include <fltKernel.h>
#include <ntddk.h>

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

// Структура для хранения правил доступа
struct AccessRule {
    WCHAR FileName[256];
    WCHAR ProcessName[100];
    int AccessMask;
};

#define MAX_RULES 50
AccessRule AccessRules[MAX_RULES];
int RuleCount = 0;

// Глобальные переменные
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\MandatAccessControl");
UNICODE_STRING SymLinkName = RTL_CONSTANT_STRING(L"\\??\\MandatAccessLink");
PDEVICE_OBJECT DeviceObject = NULL;

// Определение структур для работы с файловыми операциями
PFLT_FILTER FilterHandle = NULL;

NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreFileCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

// Фильтр операций

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE,0,MiniPreCreate,MiniPostCreate},
    {IRP_MJ_READ,0,MiniPreRead,NULL},
    {IRP_MJ_WRITE,0,MiniPreWrite,NULL},
    {IRP_MJ_OPERATION_END}
};

// Регистрация фильтра
const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    MiniUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

// IOCTL обработчики
NTSTATUS DispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = ioStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioStack->Parameters.DeviceIoControl.IoControlCode) {
    case DEVICE_SEND: {
        // Обработка запроса на добавление правила
        if (inputLength < sizeof(AccessRule)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        AccessRule* newRule = (AccessRule*)Irp->AssociatedIrp.SystemBuffer;
        if (RuleCount < MAX_RULES) {
            AccessRules[RuleCount++] = *newRule;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    }
    case DEVICE_REC: {
        // Возврат списка правил
        if (outputLength < sizeof(AccessRule) * RuleCount) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        memcpy(Irp->AssociatedIrp.SystemBuffer, AccessRules, sizeof(AccessRule) * RuleCount);
        Irp->IoStatus.Information = sizeof(AccessRule) * RuleCount;
        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Перехват операции создания файлов
FLT_PREOP_CALLBACK_STATUS PreFileCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(FileNameInfo);
        if (NT_SUCCESS(status)) {
            for (int i = 0; i < RuleCount; ++i) {
                if (wcsstr(FileNameInfo->Name.Buffer, AccessRules[i].FileName)) {
                    // Проверка на права доступа (например, 0x1 - запись, 0x2 - чтение)
                    if ((Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & AccessRules[i].AccessMask) == 0) {
                        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Data->IoStatus.Information = 0;
                        FltReleaseFileNameInformation(FileNameInfo);
                        return FLT_PREOP_COMPLETE;
                    }
                }
            }
        }
        FltReleaseFileNameInformation(FileNameInfo);
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MiniPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    WCHAR NameBuf[512];
    RtlZeroMemory(NameBuf, sizeof(NameBuf));

    // Получаем информацию о файле, который собираются создать или открыть
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(FileNameInfo);
        if (NT_SUCCESS(status)) {
            // Проверяем длину имени файла, чтобы избежать переполнения буфера
            if (FileNameInfo->Name.MaximumLength < sizeof(NameBuf)) {
                RtlCopyMemory(NameBuf, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);

                // Цикл по списку файлов и процессов
                for (int i = 0; i < RuleCount; i++) {
                    if (wcsstr(FileNameInfo->Name.Buffer, AccessRules[i].FileName)) {  // Сравнение имени файла
                        WCHAR* User = GetUser();
                        if (wcsstr(User, List[i].proccess_name)) {  // Сравнение имени процесса
                            if ((List[i].Mask & 4) == 0) {  // Проверка на разрешение создания/открытия файла (битовая маска 4)
                                KdPrint(("access denied (CREATE/OPEN)\n\n"));
                                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                                Data->IoStatus.Information = 0;
                                FltReleaseFileNameInformation(FileNameInfo);
                                return FLT_PREOP_COMPLETE;
                            }
                        }
                    }
                }
            }
        }

        // Освобождаем ресурсы, выделенные для информации о файле
        FltReleaseFileNameInformation(FileNameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


// Перехват операции записи в файл
FLT_PREOP_CALLBACK_STATUS MiniPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    WCHAR NameBuf[512];
    RtlZeroMemory(NameBuf, sizeof(NameBuf));

    // Получаем информацию о файле, к которому производится запись
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(FileNameInfo);
        if (NT_SUCCESS(status)) {
            // Проверяем длину имени файла, чтобы избежать переполнения буфера
            if (FileNameInfo->Name.MaximumLength < sizeof(NameBuf)) {
                RtlCopyMemory(NameBuf, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);

                // Цикл по списку разрешенных файлов и процессов
                for (int i = 0; i < RuleCount; i++) {
                    if (wcsstr(FileNameInfo->Name.Buffer, AccessRules[i].FileName)) {  // Сравнение имени файла
                        WCHAR* User = GetUser();
                        if (wcsstr(User, List[i].proccess_name)) {  // Сравнение имени процесса
                            if ((List[i].Mask & 1) == 0) {  // Проверка на разрешение записи (битовая маска 1)
                                KdPrint(("access denied (WRITE)\n\n"));
                                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                                Data->IoStatus.Information = 0;
                                FltReleaseFileNameInformation(FileNameInfo);
                                return FLT_PREOP_COMPLETE;
                            }
                        }
                    }
                }
            }
        }

        // Освобождаем ресурсы, выделенные для информации о файле
        FltReleaseFileNameInformation(FileNameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Перехват операции чтения файла
FLT_PREOP_CALLBACK_STATUS MiniPreRead(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION FileNameInfo;
    WCHAR NameBuf[512];
    RtlZeroMemory(NameBuf, sizeof(NameBuf));

    // Получаем информацию о файле, который открывается для чтения
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);
    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(FileNameInfo);
        if (NT_SUCCESS(status)) {
            // Проверяем длину имени файла
            if (FileNameInfo->Name.MaximumLength < sizeof(NameBuf)) {
                RtlCopyMemory(NameBuf, FileNameInfo->Name.Buffer, FileNameInfo->Name.Length);

                // Цикл по списку разрешенных файлов и процессов
                for (int i = 0; i < RuleCount; i++) {
                    if (wcsstr(FileNameInfo->Name.Buffer, AccessRules[i].FileName)) {  // Сравнение имени файла
                        WCHAR* User = GetUser();
                        if (wcsstr(User, List[i].proccess_name)) {  // Сравнение имени процесса
                            if ((List[i].Mask & 2) == 0) {  // Проверка на разрешение чтения (битовая маска 2)
                                KdPrint(("access denied (READ)\n\n"));
                                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                                Data->IoStatus.Information = 0;
                                FltReleaseFileNameInformation(FileNameInfo);
                                return FLT_PREOP_COMPLETE;
                            }
                        }
                    }
                }
            }
        }

        // Освобождаем ресурсы
        FltReleaseFileNameInformation(FileNameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Обработка события создания файла после того, как операция завершена
FLT_POSTOP_CALLBACK_STATUS MiniPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    return FLT_POSTOP_FINISHED_PROCESSING;
}


// Функция выгрузки драйвера
NTSTATUS MiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    FltUnregisterFilter(FilterHandle);
    IoDeleteSymbolicLink(&SymLinkName);
    IoDeleteDevice(DeviceObject);
    return STATUS_SUCCESS;
}

// Функция инициализации драйвера
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;

    // Создание устройства
    status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    // Символическая ссылка
    status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    // Установка обработчиков IRP
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;

    // Регистрация фильтра
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &FilterHandle);
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(FilterHandle);
    }

    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&SymLinkName);
        IoDeleteDevice(DeviceObject);
    }

    return status;
}
