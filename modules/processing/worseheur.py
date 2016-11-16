# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
class Detailed(object):
    """ Generates a detailed representation of a task's behavior """

    key = "detailed"

    _gendat = [
        {
            "event": "delete",
            "object": "dir",
            "apis": [
                "RemoveDirectoryA",
                "RemoveDirectoryW"
            ],
            "args": [("file", "DirectoryName")]
        },
        {
            "event": "create",
            "object": "dir",
            "apis": [
                "CreateDirectoryW",
                "CreateDirectoryExW"
            ],
            "args": [("file", "DirectoryName")]
        },
        {
            "event": "list",
            "object": "dir",
            "apis": [
                "FindFirstFileExA",
                "FindFirstFileExW"
            ],
            "args": [("file", "FileName")]
        },
        {
            "event": "create",
            "object": "file",
            "apis": [
                "NtCreateFile",
            ],
            "args": [
                ("disposition", "CreateDisposition"),
                ("file", "FileName"),
                ("handle", "FileHandle"),
            ]
        },
        {
            "event": "open",
            "object": "file",
            "apis": [
                "NtOpenFile",
            ],
            "args": [
                ("handle", "FileHandle"),
                ("file", "FileName"),
            ]
        },
        {
            "event": "close",
            "object": "system",
            "apis": [
                "NtClose",
            ],
            "args": [
                ("handle", "Handle"),
            ]
        },
        {
            "event": "read",
            "object": "file",
            "apis": [
                "NtReadFile",
            ],
            "args": [("file", "HandleName")]
        },
        {
            "event": "write",
            "object": "file",
            "apis": [
                "NtWriteFile",
            ],
            "args": [("file", "HandleName")]
        },
        {
            "event": "query",
            "object": "file",
            "apis": [
                "NtQueryAttributesFile",
            ],
            "args": [
                ("file", "FileName"),
            ]
        },
        {
            "event": "query",
            "object": "file",
            "apis": [
                "NtQueryInformationFile",
            ],
            "args": [
                ("file", "HandleName"),
                ("handle", "FileHandle"),
            ]
        },
        {
            "event": "move",
            "object": "file",
            "apis": [
                "MoveFileWithProgressW",
                "MoveFileWithProgressTransactedW",
            ],
            "args": [
                ("from", "ExistingFileName"),
                ("to", "NewFileName")
            ]
        },
        {
            "event": "copy",
            "object": "file",
            "apis": [
                "CopyFileA",
                "CopyFileW",
                "CopyFileExW",
                "CopyFileExA"
            ],
            "args": [
                ("from", "ExistingFileName"),
                ("to", "NewFileName")
            ]
        },
        {
            "event": "download",
            "object": "file",
            "apis": [
                "URLDownloadToFileW",
                "URLDownloadToFileA"
            ],
            "args": [
                ("url", "URL"),
                ("to", "FileName"),
            ]
        },
        {
            "event": "delete",
            "object": "file",
            "apis": [
                "DeleteFileA",
                "DeleteFileW",
                "NtDeleteFile"
            ],
            "args": [("file", "FileName")]
        },
        {
            "event": "execute",
            "object": "command",
            "apis": [
                "ShellExecuteExA",
                "ShellExecuteExW",
            ],
            "args": [("command", "FilePath")]
        },
        {
            "event": "execute",
            "object": "command",
            "apis": [
                "system",
            ],
            "args": [("command", "Command")]
        },
        {
            "event": "create",
            "object": "process",
            "apis": [
                "CreateProcessAsUserA",
                "CreateProcessAsUserW",
                "CreateProcessA",
                "CreateProcessW",
                "NtCreateProcess",
                "NtCreateProcessEx"
            ],
            "args": [
                ("file", "FileName"),
                ("handle", "ProcessHandle"),
            ]
        },
        {
            "event": "create",
            "object": "process",
            "apis": [
                "CreateProcessInternalW",
                "CreateProcessWithLogonW",
                "CreateProcessWithTokenW",
            ],
            "args": [
                ("cmd", "CommandLine"),
                ("file", "ApplicationName"),
                ("handle", "ProcessHandle"),
            ]
        },
        {
            "event": "open",
            "object": "process",
            "apis": [
                "NtOpenProcess"
            ],
            "args": [
                ("id", "ProcessIdentifier"),
                ("handle", "ProcessHandle"),
            ]
        },
        {
            "event": "read",
            "object": "process",
            "apis": [
                "ReadProcessMemory",
            ],
            "args": [
                ("handle", "ProcessHandle"),
                ("addr", "BaseAddress"),
            ]
        },
        {
            "event": "write",
            "object": "process",
            "apis": [
                "WriteProcessMemory",
            ],
            "args": [
                ("handle", "ProcessHandle"),
                ("addr", "BaseAddress"),
                ("length", "BufferLength"),
            ]
        },
        {
            "event": "terminate",
            "object": "process",
            "apis": [
                "NtTerminateProcess",
            ],
            "args": [
                ("code", "ExitCode"),
                ("handle", "ProcessHandle"),
            ]
        },
        {
            "event": "exit",
            "object": "process",
            "apis": [
                "ExitProcess",
            ],
            "args": [
                ("code", "ExitCode"),
            ]
        },
        {
            "event": "allocate",
            "object": "memory",
            "apis": [
                "NtAllocateVirtualMemory",
            ],
            "args": [
                ("handle", "ProcessHandle"),
                ("protection", "Protection"),
                ("addr", "BaseAddress"),
                ("size", "RegionSize"),
            ]
        },
        {
            "event": "protect",
            "object": "memory",
            "apis": [
                "NtProtectVirtualMemory",
            ],
            "args": [
                ("handle", "ProcessHandle"),
                ("protection", "NewAccessProtection"),
                ("addr", "BaseAddress"),
                ("size", "NumberOfBytesProtected"),
            ]
        },
        {
            "event": "create",
            "object": "section",
            "apis": [
                "NtCreateSection",
            ],
            "args": [
                ("section", "SectionHandle"),
                ("access", "DesiredAccess"),
                ("file", "FileHandle"),
            ]
        },
        {
            "event": "open",
            "object": "section",
            "apis": [
                "NtOpenSection",
            ],
            "args": [
                ("section", "SectionHandle"),
                ("access", "DesiredAccess"),
                ("file", "ObjectAttributes"),
            ]
        },
        {
            "event": "map",
            "object": "section",
            "apis": [
                "NtMapViewOfSection",
            ],
            "args": [
                ("process", "ProcessHandle"),
                ("section", "SectionHandle"),
                ("addr", "BaseAddress"),
                ("offset", "SectionOffset"),
                ("size", "ViewSize"),
                ("protect", "Win32Protect"),
            ]
        },
        {
            "event": "unmap",
            "object": "section",
            "apis": [
                "NtUnmapViewOfSection",
            ],
            "args": [
                ("process", "ProcessHandle"),
                ("addr", "BaseAddress"),
                ("size", "RegionSize"),
            ],
        },
        {
            "event": "IsDebuggerPresent",
            "object": "system",
            "apis": [
                "IsDebuggerPresent",
            ],
            "args": []
        },
        {
            "event": "ExitWindowsEx",
            "object": "system",
            "apis": [
                "ExitWindowsEx",
            ],
            "args": []
        },
#TODO: socket functions

        {
            "event": "load",
            "object": "library",
            "apis": [
                "LoadLibraryA",
                "LoadLibraryW",
                "LoadLibraryExA",
                "LoadLibraryExW",
                "LdrGetDllHandle"
            ],
            "args": [
                ("file", "FileName"),
                ("base", "ModuleHandle")
            ]
        },
        {
            "event": "load",
            "object": "library",
            "apis": [
                "LdrLoadDll",
            ],
            "args": [
                ("file", "FileName"),
                ("base", "BaseAddress")
            ]
        },
        {
            "event": "create",
            "object": "thread",
            "apis": [
                "CreateThread",
            ],
            "args": [("id", "ThreadId")]
        },
        {
            "event": "create",
            "object": "thread",
            "apis": [
                "NtCreateThreadEx",
                "NtCreateThread",
            ],
            "args": []
        },
        {
            "event": "resume",
            "object": "thread",
            "apis": [
                "NtResumeThread",
            ],
            "args": [("handle", "ThreadHandle")]
        },
        {
            "event": "exit",
            "object": "thread",
            "apis": [
                "ExitThread",
            ],
            "args": []
        },
        {
            "event": "terminate",
            "object": "thread",
            "apis": [
                "NtTerminateThread",
            ],
            "args": [("handle", "ThreadHandle")]
        },
        {
            "event": "open",
            "object": "mutant",
            "apis": [
                "NtOpenMutant",
            ],
            "args": [
                ("name", "MutexName"),
            ]
        },
        {
            "event": "create",
            "object": "mutant",
            "apis": [
                "NtCreateMutant",
            ],
            "args": [
                ("name", "MutexName"),
            ]
        },
        {
            "event": "findwindow",
            "object": "windowname",
            "apis": [
                "FindWindowA",
                "FindWindowW",
                "FindWindowExA",
                "FindWindowExW"
            ],
            "args": [
                ("classname", "ClassName"),
                ("windowname", "WindowName")
            ]
        },
        {
            "event": "IoControl",
            "object": "device",
            "apis": [
                "NtDeviceIoControlFile",
            ],
            "args": [
                ("code", "IoControlCode"),
                ("handle", "FileHandle")
            ]
        },
        {
            "event": "IoControl",
            "object": "device",
            "apis": [
                "DeviceIoControl",
            ],
            "args": [
                ("code", "IoControlCode"),
                ("handle", "DeviceHandle")
            ]
        },
        {
            "event": "open",
            "object": "registry",
            "apis": [
                "RegOpenKeyExA",
                "RegOpenKeyExW",
            ],
            "args": [
                ("regkey", "FullName"),
            ]
        },
        {
            "event": "write",
            "object": "registry",
            "apis": [
                "RegSetValueExA",
                "RegSetValueExW"
            ],
            "args": [
                ("regkey", "FullName"),
                ("content", "Buffer")
            ]
        },
        {
            "event": "write",
            "object": "registry",
            "apis": [
                "RegCreateKeyExA",
                "RegCreateKeyExW"
            ],
            "args": [
                ("regkey", "FullName")
            ]
        },
        {
            "event": "read",
            "object": "registry",
            "apis": [
                "RegQueryValueExA",
                "RegQueryValueExW",
            ],
            "args": [
                ("regkey", "FullName"),
                ("content", "Data")
            ]
        },
        {
            "event": "read",
            "object": "registry",
            "apis": [
                "NtQueryValueKey"
            ],
            "args": [
                ("regkey", "FullName"),
                ("content", "Information")
            ]
        },
        {
            "event": "delete",
            "object": "registry",
            "apis": [
                "RegDeleteKeyA",
                "RegDeleteKeyW",
                "RegDeleteValueA",
                "RegDeleteValueW",
                "NtDeleteValueKey",
                "NtDeleteKey",
            ],
            "args": [
                ("regkey", "FullName")
            ]
        },
        #TODO NtCreateKey and alike
        {
            "event": "create",
            "object": "windowshook",
            "apis": [
                "SetWindowsHookExA",
                "SetWindowsHookExW"
            ],
            "args": [
                ("id", "HookIdentifier"),
                ("moduleaddress", "ModuleAddress"),
                ("procedureaddress", "ProcedureAddress")
            ]
        },
        {
            "event": "start",
            "object": "service",
            "apis": [
                "StartServiceA",
                "StartServiceW"
            ],
            "args": [("name", "ServiceName")]
        },
        {
            "event": "modify",
            "object": "service",
            "apis": ["ControlService"],
            "args": [
                ("name", "ServiceName"),
                ("controlcode", "ControlCode")
            ]
        },
        {
            "event": "delete",
            "object": "service",
            "apis": ["DeleteService"],
            "args": [("name", "ServiceName")]
        },
        {
            "event": "open",
            "object": "service",
            "apis": [
                "OpenServiceA",
                "OpenServiceW",
            ],
            "args": [
                ("name", "ServiceName"),
                ("access", "DesiredAccess"),
            ]
        },
        {
            "event": "create",
            "object": "service",
            "apis": [
                "CreateServiceA",
                "CreateServiceW",
            ],
            "args": [
                ("name", "ServiceName"),
                ("path", "BinaryPathName"),
            ]
        },
        {
            "event": "query",
            "object": "dns",
            "apis": [
                "DnsQuery_A",
                "DnsQuery_UTF8",
                "DnsQuery_W",
            ],
            "args": [("name", "Name")]
        },
        {
            "event": "query",
            "object": "dns",
            "apis": [
                "getaddrinfo",
                "GetAddrInfoW",
            ],
            "args": [("name", "NodeName")]
        },
        {
            "event": "openurl",
            "object": "net",
            "apis": [
                "InternetOpenUrlA",
                "InternetOpenUrlW",
            ],
            "args": [("name", "URL")]
        },
        {
            "event": "crackurl",
            "object": "net",
            "apis": [
                "InternetCrackUrlA",
                "InternetCrackUrlW",
            ],
            "args": [("name", "Url")]
        },
        {
            "event": "connect",
            "object": "net",
            "apis": [
                "InternetConnectA",
                "InternetConnectW",
            ],
            "args": [("name", "ServerName")]
        },
        {
            "event": "open",
            "object": "net",
            "apis": [
                "HttpOpenRequestA",
                "HttpOpenRequestW",
            ],
            "args": [
                ("name", "Path"),
                ("handle", "InternetHandle"),
            ]
        },
        {
            "event": "send",
            "object": "net",
            "apis": [
                "HttpSendRequestA",
                "HttpSendRequestW",
            ],
            "args": [("name", "RequestHandle")]
        },
        {
            "event": "close",
            "object": "net",
            "apis": [
                "InternetCloseHandle",
            ],
            "args": [("name", "InternetHandle")]
        },
        {
            "event": "create",
            "object": "event",
            "apis": [
                "NtCreateEvent",
            ],
            "args": [("name", "EventName")]
        },
        {
            "event": "open",
            "object": "event",
            "apis": [
                "NtOpenEvent",
            ],
            "args": [("name", "EventName")]
        },
#TODO Zw counterparts
    ]

    def __init__(self, details=False):
        self.details = details
        self.modules = {}
        self.events = []
        self.events_idx = {}

        self.gendat_idx = {}
        for item in self._gendat:
            for api in item["apis"]:
                self.gendat_idx[api] = item


    def process_call(self, call):
        """ Translates a call coming from the behavior module into the
            equivalent detailed trace. Calls deemed irrelevant are discarded.
            @return: a trace that contains enough information to characterize a
            process's behavior but is still succint enough to be handled by
            malheur
        """
        def _load_args(call):
            """
            Loads arguments from call
            """
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res

        def _generic_handle_details(self, call, item):
            """
            Generic handling of api calls
            @call: the call dict
            @item: Generic item to process
            """
            event = None
            if call["api"] in item["apis"]:
                args = _load_args(call)

                event = {
                    "event": item["event"],
                    "object": item["object"],
                    "timestamp": call["timestamp"],
                    "tid": call["thread_id"],
                    "status": call["status"],
                    "return": call["return"],
                    "data": {}
                }

                for logname, dataname in item["args"]:
                    event["data"][logname] = args.get(dataname)
                return event

        def _generic_handle(self, idx, call):
            """Generic handling of api calls."""
            if call["api"] in idx:
                event = _generic_handle_details(self, call, idx[call["api"]])
                if event:
                    return event

            return None

        event = _generic_handle(self, self.gendat_idx, call)
        args = _load_args(call)

        return event

    def event_apicall(self, call, process):
        """ Processes a call and adds it to the collection
            @return: None.
        """
        event = self.process_call(call)
        if event:
            #worse-dev
            event["pid"] = process["process_id"]
            if not event["tid"] in self.events_idx:
                self.events_idx[event["tid"]] = len(self.events)
                lst = []
                lst.append(event)
                self.events.append(lst)
            else:
                idx = self.events_idx[event["tid"]]
                self.events[idx].append(event)

            #self.events.append(event)

    def run(self):
        """ Gets a tailored collection of calls extracted from the task's
            behavior
            @return: a sequence of events, with a more detailed level of info
        """
        ret = []
        for tevents in self.events:
            ret += tevents
        return ret


