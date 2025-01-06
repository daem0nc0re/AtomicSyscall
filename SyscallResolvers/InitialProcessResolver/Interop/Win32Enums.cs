using System;

namespace InitialProcessResolver.Interop
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        // For Process
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_TERMINATE = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x000000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,

        // For Thread
        THREAD_ALL_ACCESS = 0x001FFFFF,
        THREAD_TERMINATE = 0x00000001,
        THREAD_SUSPEND_RESUME = 0x00000002,
        THREAD_ALERT = 0x00000004,
        THREAD_GET_CONTEXT = 0x00000008,
        THREAD_SET_CONTEXT = 0x00000010,
        THREAD_SET_INFORMATION = 0x00000020,
        THREAD_SET_LIMITED_INFORMATION = 0x00000400,
        THREAD_QUERY_LIMITED_INFORMATION = 0x00000800,

        // For Files
        FILE_ANY_ACCESS = 0x00000000,
        FILE_READ_ACCESS = 0x00000001,
        FILE_WRITE_ACCESS = 0x00000002,
        FILE_READ_DATA = 0x00000001,
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_ADD_FILE = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_CREATE_PIPE_INSTANCE = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_ALL_ACCESS = 0x001F01FF,
        FILE_GENERIC_READ = 0x00100089,
        FILE_GENERIC_WRITE = 0x00100116,
        FILE_GENERIC_EXECUTE = 0x001000A0,

        // For Transaction
        TRANSACTION_QUERY_INFORMATION = 0x00000001,
        TRANSACTION_SET_INFORMATION = 0x00000002,
        TRANSACTION_ENLIST = 0x00000004,
        TRANSACTION_COMMIT = 0x00000008,
        TRANSACTION_ROLLBACK = 0x00000010,
        TRANSACTION_PROPAGATE = 0x00000020,
        TRANSACTION_RIGHT_RESERVED1 = 0x00000040,
        TRANSACTION_GENERIC_READ = 0x00120001,
        TRANSACTION_GENERIC_WRITE = 0x0012003E,
        TRANSACTION_GENERIC_EXECUTE = 0x00120018,
        TRANSACTION_ALL_ACCESS = 0x001F003F,
        TRANSACTION_RESOURCE_MANAGER_RIGHTS = 0x00120037,

        // Others
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,

        // For section
        SECTION_QUERY = 0x00000001,
        SECTION_MAP_WRITE = 0x00000002,
        SECTION_MAP_READ = 0x00000004,
        SECTION_MAP_EXECUTE = 0x00000008,
        SECTION_EXTEND_SIZE = 0x00000010,
        SECTION_MAP_EXECUTE_EXPLICIT = 0x00000020,
        SECTION_ALL_ACCESS = 0x000F001F
    }

    internal enum IMAGE_FILE_MACHINE : ushort
    {
        UNKNOWN = 0,
        I386 = 0x014C,
        R3000BE = 0x0160,
        R3000LE = 0x0162,
        R4000 = 0x0166,
        R10000 = 0x0168,
        WCEMIPSV2 = 0x0169,
        ALPHA = 0x0184,
        SH3 = 0x01A2,
        SH3DSP = 0x01A3,
        SH3E = 0x01A4,
        SH4 = 0x01A6,
        SH5 = 0x01A8,
        ARM = 0x01C0,
        THUMB = 0x01C2,
        ARM2 = 0x01C4,
        AM33 = 0x01D3,
        POWERPC = 0x01F0,
        POWERPCFP = 0x01F1,
        IA64 = 0x0200,
        MIPS16 = 0x0266,
        ALPHA64 = 0x0284,
        MIPSFPU = 0x0366,
        MIPSFPU16 = 0x0466,
        AXP64 = 0x0284,
        TRICORE = 0x0520,
        CEF = 0x0CEF,
        EBC = 0x0EBC,
        AMD64 = 0x8664,
        M32R = 0x9041,
        ARM64 = 0xAA64,
        CEE = 0xC0EE
    }

    [Flags]
    internal enum PROCESS_CREATION_FLAGS : uint
    {
        NONE = 0,
        BREAKAWAY = 0x00000001,
        NO_DEBUG_INHERIT = 0x00000002,
        INHERIT_HANDLES = 0x00000004,
        OVERRIDE_ADDRESS_SPACE = 0x00000008,
        LARGE_PAGES = 0x00000010,
        LARGE_PAGE_SYSTEM_DLL = 0x00000020,
        PROTECTED_PROCESS = 0x00000040,
        CREATE_SESSION = 0x00000080,
        INHERIT_FROM_PARENT = 0x00000100,
        SUSPENDED = 0x00000200,
        EXTENDED_UNKNOWN = 0x00000400
    }

    internal enum PROCESSINFOCLASS
    {
        ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
        ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
        ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // q: HANDLE // 30
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: IO_PRIORITY_HINT
        ProcessExecuteFlags, // qs: ULONG
        ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
        ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // q: ULONG[] // since WINBLUE
        ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
        ProcessCommandLineInformation, // q: UNICODE_STRING // 60
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
        ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
        ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
        ProcessDisableSystemAllowedCpuSets, // 80
        ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
        ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
        ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
        ProcessImageSection, // q: HANDLE
        ProcessDebugAuthInformation, // since REDSTONE4 // 90
        ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
        ProcessSequenceNumber, // q: ULONGLONG
        ProcessLoaderDetour, // since REDSTONE5
        ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
        ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
        ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
        ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
        ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
        ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
        ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
        ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
        ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
        ProcessCreateStateChange, // since WIN11
        ProcessApplyStateChange,
        ProcessEnableOptionalXStateFeatures,
        ProcessAltPrefetchParam, // since 22H1
        ProcessAssignCpuPartitions,
        ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
        ProcessMembershipInformation,
        ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
        ProcessEffectivePagePriority, // q: ULONG
        MaxProcessInfoClass
    }

    /*
     * Reference:
     * https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
     */
    internal enum PS_ATTRIBUTES : ulong
    {
        PARENT_PROCESS = 0x00060000, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeParentProcess, false, true, true);
        DEBUG_OBJECT = 0x00060001, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeDebugObject, false, true, true);
        TOKEN = 0x00060002, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeToken, false, true, true);
        CLIENT_ID = 0x00010003, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeClientId, true, false, false);
        TEB_ADDRESS = 0x00010004, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeTebAddress, true, false, false);
        IMAGE_NAME = 0x00020005, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeImageName, false, true, false);
        IMAGE_INFO = 0x00000006, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeImageInfo, false, false, false);
        MEMORY_RESERVE = 0x00020007, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMemoryReserve, false, true, false);
        PRIORITY_CLASS = 0x00020008, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributePriorityClass, false, true, false);
        ERROR_MODE = 0x00020009, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeErrorMode, false, true, false);
        STD_HANDLE_INFO = 0x0002000A, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeStdHandleInfo, false, true, false);
        HANDLE_LIST = 0x0002000B, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeHandleList, false, true, false);
        GROUP_AFFINITY = 0x0003000C, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeGroupAffinity, true, true, false);
        PREFERRED_NODE = 0x0002000D, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributePreferredNode, false, true, false);
        IDEAL_PROCESSOR = 0x0003000E, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeIdealProcessor, true, true, false);
        UMS_THREAD = 0x0003000F, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeUmsThread, true, true, false);
        MITIGATION_OPTIONS = 0x00020010, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMitigationOptions, false, true, false);
        PROTECTION_LEVEL = 0x00060011, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeProtectionLevel, false, true, true);
        SECURE_PROCESS = 0x00020012, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeSecureProcess, false, true, false);
        JOB_LIST = 0x00020013, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeJobList, false, true, false);
        CHILD_PROCESS_POLICY = 0x00020014, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeChildProcessPolicy, false, true, false);
        ALL_APPLICATION_PACKAGES_POLICY = 0x00020015, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeAllApplicationPackagesPolicy, false, true, false);
        WIN32K_FILTER = 0x00020016, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeWin32kFilter, false, true, false);
        SAFE_OPEN_PROMPT_ORIGIN_CLAIM = 0x00020017, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeSafeOpenPromptOriginClaim, false, true, false);
        BNO_ISOLATION = 0x00020018, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeBnoIsolation, false, true, false);
        DESKTOP_APP_POLICY = 0x00020019, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeDesktopAppPolicy, false, true, false);
        CHPE = 0x0006001A, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeChpe, false, true, true);
        MITIGATION_AUDIT_OPTIONS = 0x0002001B, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMitigationAuditOptions, false, true, false);
        MACHINE_TYPE = 0x0006001C, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMachineType, false, true, true);
        COMPONENT_FILTER = 0x0002001D, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeComponentFilter, false, true, false);
        ENABLE_OPTIONAL_XSTATE_FEATURES = 0x0003001E, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeEnableOptionalXStateFeatures, true, true, false);
    }

    [Flags]
    internal enum PS_CREATE_INIT_FLAGS : uint
    {
        WriteOutputOnExit = 0x00000001,
        DetectManifest = 0x00000002,
        IFEOSkipDebugger = 0x00000004,
        IFEODoNotPropagateKeyState = 0x00000008,
        ProhibitedImageCharacteristics = 0xFFFF0000
    }

    [Flags]
    internal enum PS_CREATE_OUTPUT_FLAGS : uint
    {
        ProtectedProcess = 0x00000001,
        AddressSpaceOverride = 0x00000002,
        DevOverrideEnabled = 0x00000004,
        ManifestDetected = 0x00000008,
        ProtectedProcessLight = 0x00000010
    }

    internal enum PS_CREATE_STATE
    {
        PsCreateInitialState,
        PsCreateFailOnFileOpen,
        PsCreateFailOnSectionCreate,
        PsCreateFailExeFormat,
        PsCreateFailMachineMismatch,
        PsCreateFailExeName, // Debugger specified
        PsCreateSuccess,
        PsCreateMaximumStates
    }

    [Flags]
    internal enum RTL_USER_PROC_FLAGS : uint
    {
        PARAMS_NORMALIZED = 0x00000001,
        PROFILE_USER = 0x00000002,
        PROFILE_KERNEL = 0x00000004,
        PROFILE_SERVER = 0x00000008,
        RESERVE_1MB = 0x00000020,
        RESERVE_16MB = 0x00000040,
        CASE_SENSITIVE = 0x00000080,
        DISABLE_HEAP_DECOMMIT = 0x00000100,
        DLL_REDIRECTION_LOCAL = 0x00001000,
        APP_MANIFEST_PRESENT = 0x00002000,
        IMAGE_KEY_MISSING = 0x00004000,
        OPTIN_PROCESS = 0x00020000
    }

    [Flags]
    internal enum THREAD_CREATION_FLAGS : uint
    {
        NONE = 0,
        CREATE_SUSPENDED = 0x00000001,
        SKIP_THREAD_ATTACH = 0x00000002,
        HIDE_FROM_DEBUGGER = 0x00000004,
        HAS_SECURITY_DESCRIPTOR = 0x00000010,
        ACCESS_CHECK_IN_TARGET = 0x00000020,
        INITIAL_THREAD = 0x00000080
    }
}
