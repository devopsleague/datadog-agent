#include "etw.h"
#include <windows.h>
#include <Evntcons.h>

typedef struct _SubscriptionInfo
{
    HANDLE      hProcessTraceThread;
    TRACEHANDLE hTraceSession;
    TRACEHANDLE hTraceOpen;
    char        subscriptionName[SUBSCIPTION_NAME_MAX_LEN + 1];
    int64_t     providers;
    int64_t     flags;
    ETW_EVENT_CALLBACK callback;
}SubscriptionInfo;

typedef struct EventTracePropertyData
{
    EVENT_TRACE_PROPERTIES props;
    WCHAR loggerName[SUBSCIPTION_NAME_MAX_LEN + 1];
} EventTracePropertyData;

// In future to have simulteneousl subscription we need advance tracking to keep context and allocate
// this structure dynamically and also make sure that it is freed AFTER tracing is guarantee ti be stopped.
// Another word complexity which are not needed at this time.
static SubscriptionInfo g_subscriptionInfo = { 0 };


// It is from C:\Program Files (x86)\Windows Kits\10\Include\xxxx\shared\evntrace.h
// but one need to use INITGUID BEFORE including the header which is inconvinient for CGO
const GUID EventTraceGuid = { /* 68fdd900-4a3e-11d1-84f4-0000f80464e3 */
    0x68fdd900, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };

const GUID HttpServiceGuid = { /* dd5ef90a-6398-47a4-ad34-4dcecdef795f */
    0xdd5ef90a, 0x6398, 0x47a4, { 0xad, 0x34, 0x4d, 0xce, 0xcd, 0xef, 0x79, 0x5f } };


static void SaveStartedSubscriptionInfo(TRACEHANDLE hTraceSession, const char* subscriptionName, int64_t providers, int64_t flags, ETW_EVENT_CALLBACK callback)
{
    g_subscriptionInfo.hTraceSession = hTraceSession;
    strcpy_s(g_subscriptionInfo.subscriptionName, _countof(g_subscriptionInfo.subscriptionName), subscriptionName);
    g_subscriptionInfo.providers = providers;
    g_subscriptionInfo.flags     = flags;
    g_subscriptionInfo.callback  = callback;
}

static BOOL InitializeEventTraceProperties(const char* subscriptionName, EventTracePropertyData* evtTraceProps)
{
    // Validate name length
    int subscriptionNameLen = (int)strlen(subscriptionName);
    if (subscriptionNameLen > SUBSCIPTION_NAME_MAX_LEN)
    {
        return FALSE;
    }

    // Intialize
    memset(evtTraceProps, 0, sizeof(EventTracePropertyData));
    evtTraceProps->props.Wnode.BufferSize = sizeof(EventTracePropertyData);
    evtTraceProps->props.Wnode.Flags      = WNODE_FLAG_TRACED_GUID;
    evtTraceProps->props.LoggerNameOffset = offsetof(EventTracePropertyData, loggerName);

    // Convert ASCII to Wide Char
    if (MultiByteToWideChar(CP_OEMCP, 0, subscriptionName, subscriptionNameLen, evtTraceProps->loggerName, subscriptionNameLen) != subscriptionNameLen)
    {
        return FALSE;
    }

    return TRUE;
}

static WCHAR* GetSubscriptionNameFromEventTaceProps(EVENT_TRACE_PROPERTIES* evtTraceProps)
{
    return (WCHAR*)(((char*)evtTraceProps) + evtTraceProps->LoggerNameOffset);
}

static BOOL StopSubscription(TRACEHANDLE hTraceSession, const char* subscriptionName)
{
    EventTracePropertyData evtTraceProps;
    if (!InitializeEventTraceProperties(subscriptionName, &evtTraceProps))
    {
        return FALSE;
    }

    ULONG rc = ControlTraceW(hTraceSession, GetSubscriptionNameFromEventTaceProps(&evtTraceProps.props), &evtTraceProps.props, EVENT_TRACE_CONTROL_STOP);

    return TRUE;
}


static void WINAPI RecordEventCallback(PEVENT_RECORD event)
{
    int16_t provider =
        IsEqualGUID(&event->EventHeader.ProviderId, &HttpServiceGuid) ? DD_ETW_TRACE_PROVIDER_HttpService : 0;

    // Is event for the matching provider? Do we have callback?
    if (provider == 0 || ((provider & g_subscriptionInfo.providers) == 0) || g_subscriptionInfo.callback == NULL)
    {
        return;
    }

    ETW_EVENT_CALLBACK callback = g_subscriptionInfo.callback;

    // Initialize helper structure
    DD_ETW_EVENT_INFO ddEventInfo = { 0 };
    ddEventInfo.event     = (DD_ETW_EVENT*)event;
    ddEventInfo.provider  = provider;
    if (event->ExtendedDataCount > 0 && event->ExtendedData)
    {
        for (USHORT idx = 0; idx < event->ExtendedDataCount; ++idx)
        {
            EVENT_HEADER_EXTENDED_DATA_ITEM* exData = event->ExtendedData + idx;
            if (exData->ExtType == EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID && exData->DataSize == sizeof(GUID))
            {
                ddEventInfo.relatedActivityId = (DDGUID*)exData->DataPtr;
            }
        }
    }

    callback(&ddEventInfo);
}

// * StartTrace
// * EnableTraceEx2
static int PrepareTracing(const char* subscriptionName, int64_t providers, int64_t flags, ETW_EVENT_CALLBACK callback)
{
    EventTracePropertyData evtTraceProps;
    if (!InitializeEventTraceProperties(subscriptionName, &evtTraceProps))
    {
        return -1;
    }

    // Start trace
    TRACEHANDLE hTraceSession = 0;
    evtTraceProps.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    evtTraceProps.props.Wnode.ClientContext = 1;
    ULONG rc = StartTraceW(&hTraceSession, GetSubscriptionNameFromEventTaceProps(&evtTraceProps.props), &evtTraceProps.props);
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }

    // Enable trace for Microsoft-Windows-HttpService if requested
    if (providers & DD_ETW_TRACE_PROVIDER_HttpService)
    {
        // We are interested only in the following events and filter using keyword mask and log level for such events
        //   #define EVENT_ID_HttpService_HTTPRequestTraceTaskRecvReq  1
        //   #define EVENT_ID_HTTPRequestTraceTaskDeliver  3
        //   #define EVENT_ID_HttpService_HTTPRequestTraceTaskFastResp  8
        //   #define EVENT_ID_HttpService_HTTPConnectionTraceTaskConnConn  21
        //   #define EVENT_ID_HttpService_HTTPConnectionTraceTaskConnClose  23
        //
        const ULONGLONG keywordFlags = 0x8000000000000136;
        ULONG rc = EnableTraceEx2(hTraceSession, &HttpServiceGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, keywordFlags, 0, 0, NULL);
        if (rc != ERROR_SUCCESS)
        {
            StopSubscription(hTraceSession, subscriptionName);
            return rc;
        }
    }

    // Save properties in globals to be found by StopEtwSubscription
    // Presume Start and Stop is called in order (otherwise small memory leak may happen)
    SaveStartedSubscriptionInfo(hTraceSession, subscriptionName, providers, flags, callback);

    return 0;
}

static int StartTracing(const char* loggerName)
{
    WCHAR loggerNameW[SUBSCIPTION_NAME_MAX_LEN + 1] = { 0 };
    int subscriptionNameLen = (int)strlen(loggerName);

    // Convert ASCII to Wide Char
    if (MultiByteToWideChar(CP_OEMCP, 0, loggerName, subscriptionNameLen, loggerNameW, subscriptionNameLen) != subscriptionNameLen)
    {
        StopEtwSubscription();
        return -1;
    }

    EVENT_TRACE_LOGFILEW evtTraceLogFile = { 0 };
    evtTraceLogFile.LoggerName          = loggerNameW;
    evtTraceLogFile.LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    evtTraceLogFile.ProcessTraceMode    = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    evtTraceLogFile.EventRecordCallback = RecordEventCallback;
    evtTraceLogFile.IsKernelTrace       = 1;

    g_subscriptionInfo.hTraceOpen = OpenTraceW(&evtTraceLogFile);
    if (g_subscriptionInfo.hTraceOpen == (TRACEHANDLE)INVALID_HANDLE_VALUE)
    {
        StopEtwSubscription();
        return GetLastError();
    }

    return 0;
}

DWORD WINAPI ProcessTraceProcessor(LPVOID dummyParam)
{
    ULONG rc = ProcessTrace(&g_subscriptionInfo.hTraceOpen, 1, 0, 0);
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }

    return 0;
}

static int StartProcessing(int64_t flags)
{
    g_subscriptionInfo.hProcessTraceThread = CreateThread(NULL, 0, ProcessTraceProcessor, NULL, 0, NULL);
    if (g_subscriptionInfo.hProcessTraceThread == 0)
    {
        return GetLastError();
    }

    ULONG rc = ProcessTrace(&g_subscriptionInfo.hTraceOpen, 1, 0, 0);
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }

    return 0;
}

int StartEtwSubscription(const char* subscriptionName, int64_t providers, int64_t flags, ETW_EVENT_CALLBACK callback)
{
    // Stop trace if it is running (e.g. after crash)
    StopSubscription(0, subscriptionName);

    // * StartTrace
    // * EnableTraceEx2
    int rc = PrepareTracing(subscriptionName, providers, flags, callback);
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }

    // Start tracing
    rc = StartTracing(subscriptionName);
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }

    // Start peocessing
    rc = StartProcessing(flags);
    if (rc != ERROR_SUCCESS)
    {
        return rc;
    }

    return 0;
}

void StopEtwSubscription()
{
    // shutoff callbacks immedeatly
    g_subscriptionInfo.providers = 0;
    g_subscriptionInfo.callback  = NULL;

    if (g_subscriptionInfo.hTraceOpen != 0)
    {
        CloseTrace(g_subscriptionInfo.hTraceOpen);
        g_subscriptionInfo.hTraceOpen = 0;
    }

    if (!g_subscriptionInfo.hTraceSession != 0)
    {
        StopSubscription(g_subscriptionInfo.hTraceSession, g_subscriptionInfo.subscriptionName);
        g_subscriptionInfo.subscriptionName[0] = '\0';
        g_subscriptionInfo.hTraceSession = 0;
    }

    g_subscriptionInfo.flags = 0;

    // In future we can wait on the thread signaling/exit
    if (g_subscriptionInfo.hProcessTraceThread != NULL)
    {
        CloseHandle(g_subscriptionInfo.hProcessTraceThread);
        g_subscriptionInfo.hProcessTraceThread = NULL;
    }

    // Do we need sleep or wait for a thread to finished.
}
