// Copyright (C) 2016 Moriyoshi Koizumi <mozo@mozo.jp>
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Security;
using System.Runtime.InteropServices;
using System.Collections;
using System.Collections.Generic;

namespace Win32API
{

public sealed class Win32APIException: Exception
{
    int code;
    string message;
    string[] arguments;

    public int Code
    {
        get { return code; }
        set { code = value; }
    }

    public override string Message
    {
        get {
            if (message == null) {
                IntPtr messageText = IntPtr.Zero;
                IntPtr[] _arguments = null;
                if (arguments != null)
                {
                    _arguments = new IntPtr[arguments.Length];
                    for (var i = 0; i < arguments.Length; i++)
                    {
                        _arguments[i] = Marshal.StringToHGlobalUni(arguments[i]);
                    }
                }
                try
                {
                    uint messageTextLen = Kernel32.FormatMessage(
                        Kernel32.FormatMessageFlags.ALLOCATE_BUFFER | Kernel32.FormatMessageFlags.FROM_SYSTEM | Kernel32.FormatMessageFlags.ARGUMENT_ARRAY,
                        IntPtr.Zero,
                        (uint)Code,
                        0,
                        ref messageText,
                        0,
                        _arguments
                    );
                    if (messageTextLen != 0)
                    {
                        message = Marshal.PtrToStringUni(messageText, (int)messageTextLen).Trim();
                    }
                }
                finally
                {
                    if (messageText != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(messageText);
                    }
                    if (_arguments != null)
                    {
                        foreach (IntPtr a in _arguments)
                        {
                            Marshal.FreeHGlobal(a);
                        }
                    }
                }
            }
            return message;
        }
    }

    public Win32APIException(int code, params string[] arguments)
    {
        this.code = code;
        this.arguments = arguments;
    }
}

public sealed class UserEnv
{
    [DllImport("userenv.dll", EntryPoint="CreateEnvironmentBlock", SetLastError=true)]
    public static extern bool _CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    public static IntPtr CreateEnvironmentBlock(IntPtr hToken, bool bInherit)
    {
        IntPtr retval;
        if (!_CreateEnvironmentBlock(out retval, hToken, bInherit))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    [DllImport("userenv.dll", EntryPoint="DestroyEnvironmentBlock", SetLastError=true)]
    public static extern bool _DestroyEnvironmentBlock(IntPtr lpEnvironment);

    public static void DestroyEnvironmentBlock(IntPtr lpEnvironment)
    {
        if (!_DestroyEnvironmentBlock(lpEnvironment))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROFILEINFO {
        public int dwSize; 
        public int dwFlags;
        public string lpUserName; 
        public string lpProfilePath; 
        public string lpDefaultPath; 
        public string lpServerName; 
        public string lpPolicyPath; 
        public IntPtr hProfile; 
    }

    [DllImport("userenv.dll", EntryPoint="LoadUserProfile", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

    public static PROFILEINFO LoadUserProfile(IntPtr hToken, string userName)
    {
        PROFILEINFO retval = new PROFILEINFO();
        retval.dwSize = Marshal.SizeOf(typeof(PROFILEINFO));
        retval.lpUserName = userName;
        if (!_LoadUserProfile(hToken, ref retval))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    [DllImport("userenv.dll", EntryPoint="UnloadUserProfile", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

    public static void UnloadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo)
    {
        if (!_UnloadUserProfile(hToken, lpProfileInfo.hProfile))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }
}

public sealed class Kernel32
{
    [Flags]
    public enum FormatMessageFlags: uint
    {
        ALLOCATE_BUFFER = 0x00000100,
        IGNORE_INSERTS  = 0x00000200,
        FROM_SYSTEM     = 0x00001000,
        ARGUMENT_ARRAY  = 0x00002000,
        FROM_HMODULE    = 0x00000800,
        FROM_STRING     = 0x00000400
    }

    [DllImport("Kernel32.dll", EntryPoint="FormatMessageW", SetLastError=true)]
    public static extern uint FormatMessage(
        FormatMessageFlags dwFlags,
        IntPtr lpSource, 
        uint dwMessageId,
        uint dwLanguageId,
        ref IntPtr lpBuffer, 
        uint nSize,
        IntPtr[] Arguments
    );

    [Flags]
    public enum CreateProcessFlags: uint
    {
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }

    [Flags]
    public enum StartUpInfoFlags: uint
    {
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_USESTDHANDLES = 0x00000100,
    } 

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public StartUpInfoFlags dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;

        public STARTUPINFO(
            StartUpInfoFlags dwFlags = 0,
            string lpDesktop = null,
            string lpTitle = null,
            int dwX = CW_USEDEFAULT,
            int dwY = CW_USEDEFAULT,
            int dwXSize = CW_USEDEFAULT,
            int dwYSize = CW_USEDEFAULT,
            int dwXCountChars = 0,
            int dwYCountChars = 0,
            int dwFillAttribute = 0,
            short wShowWindow = 0,
            IntPtr hStdInput = default(IntPtr),
            IntPtr hStdOutput = default(IntPtr),
            IntPtr hStdError = default(IntPtr)
        )
        {
            this.lpReserved = IntPtr.Zero;
            this.lpDesktop = lpDesktop;
            this.lpTitle = lpTitle;
            this.dwX = dwX;
            this.dwY = dwY;
            this.dwXSize = dwXSize;
            this.dwYSize = dwYSize;
            this.dwXCountChars = dwXCountChars;
            this.dwYCountChars = dwYCountChars;
            this.dwFillAttribute = dwFillAttribute;
            this.dwFlags = dwFlags;
            this.wShowWindow = wShowWindow;
            this.cbReserved2 = 0;
            this.lpReserved2 = IntPtr.Zero;
            this.hStdInput = hStdInput;
            this.hStdOutput = hStdOutput;
            this.hStdError = hStdError;
            this.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION 
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public const int CW_USEDEFAULT = -1;  

    [DllImport("kernel32.dll", EntryPoint="CreateProcessW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes, 
        IntPtr lpThreadAttributes,
        bool bInheritHandles, 
        CreateProcessFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo, 
        out PROCESS_INFORMATION lpProcessInformation
    );

    public static PROCESS_INFORMATION CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        CreateProcessFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo
    )
    {
        PROCESS_INFORMATION retval;
        if (!_CreateProcess(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            ref lpStartupInfo,
            out retval
        ))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error(), lpApplicationName);
        }
        return retval;
    }

    [DllImport("kernel32.dll", EntryPoint="CloseHandle", SetLastError=true)]
    public static extern bool _CloseHandle(IntPtr hObject);

    public static void CloseHandle(IntPtr hObject)
    {
        if (!_CloseHandle(hObject))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }

    [DllImport("Kernel32.dll", EntryPoint="RtlMoveMemory", SetLastError=false)]
    public static extern void MoveMemory(IntPtr dest, IntPtr src, uint size);


    public enum WaitCode: uint
    {
        OBJECT_0 = 0x00000000,
        ABANDONED = 0x00000080,
        TIMEOUT = 0x00000102,
        FAILED = 0xFFFFFFFF
    }

    [DllImport("kernel32.dll", EntryPoint="WaitForSingleObject", SetLastError=true)]
    public static extern WaitCode _WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public static WaitCode WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds)
    {
        WaitCode retval = _WaitForSingleObject(hHandle, dwMilliseconds);
        if (retval == WaitCode.FAILED)
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    [DllImport("kernel32.dll", EntryPoint="WaitForInputIdle", SetLastError=true)]
    public static extern WaitCode _WaitForInputIdle(IntPtr hHandle, uint dwMilliseconds);

    public static WaitCode WaitForInputIdle(IntPtr hHandle, uint dwMilliseconds)
    {
        WaitCode retval = _WaitForInputIdle(hHandle, dwMilliseconds);
        if (retval == WaitCode.FAILED)
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    [DllImport("kernel32.dll", EntryPoint="GetExitCodeProcess", SetLastError=true)]
    public static extern bool _GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    public static uint GetExitCodeProcess(IntPtr hProcess)
    {
        uint retval;
        if (!_GetExitCodeProcess(hProcess, out retval))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }


    [DllImport("kernel32.dll", EntryPoint="GetCurrentProcess", SetLastError=false)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", EntryPoint="GetProcessId", SetLastError=false)]
    public static extern uint GetProcessId(IntPtr hProcess);

}

public sealed class User32
{
    public enum ShowWindowCommand
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_MAX = 10
    }

    [DllImport("user32.dll", EntryPoint="GetProcessWindowStation", SetLastError=true)]
    public static extern IntPtr GetProcessWindowStation();

    public enum UserObjectInformationIndex: int
    {
        UOI_FLAGS = 1,
        UOI_NAME,
        UOI_TYPE,
        UOI_USER_SID,
        UOI_HEAPSIZE,
        UOI_IO
    }

    public struct USEROBJECTFLAGS
    {
        public bool fInherit;
        public bool fReserved;
        public uint dwFlags;
    };

    [DllImport("user32.dll", EntryPoint="GetUserObjectInformation", SetLastError=true)]
    public static extern bool _GetUserObjectInformation(
        IntPtr hObj,
        UserObjectInformationIndex nIndex,
        IntPtr pvInfo,
        uint nLength,
        out uint lpnLengthNeeded
    );

    public static object GetUserObjectInformation(IntPtr hObj, UserObjectInformationIndex nIndex)
    {
        uint len;
        _GetUserObjectInformation(hObj, nIndex, IntPtr.Zero, (uint)0, out len);
        IntPtr buf = Marshal.AllocHGlobal((int)len);
        try
        {
            if (!_GetUserObjectInformation(hObj, nIndex, buf, len, out len))
            {
                throw new Win32APIException(Marshal.GetLastWin32Error());
            }
            if (nIndex == UserObjectInformationIndex.UOI_FLAGS)
            {
                return Marshal.PtrToStructure<USEROBJECTFLAGS>(buf);
            }
            else
            {
                byte[] retval = new byte[len];
                Marshal.Copy(buf, retval, 0, (int)len);
                return retval;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    public delegate bool EnumDesktopProc(
        [MarshalAs(UnmanagedType.LPWStr)] string lpszDesktop,
        uint lParam
    );

    [DllImport("user32.dll", EntryPoint="EnumDesktopsW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _EnumDesktops(
        IntPtr hwinsta,
        [MarshalAs(UnmanagedType.FunctionPtr)] EnumDesktopProc lpEnumFunc,
        uint lParam
    );

    public static IList<string> EnumDesktops(IntPtr hwinsta)
    {
        List<string> retval = new List<string>();
        if (!_EnumDesktops(
            hwinsta,
            delegate (string lpszDesktop, uint lParam)
            {
                retval.Add(lpszDesktop);
                return true;
            },
            0))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    [DllImport("user32.dll", EntryPoint="OpenDesktopW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr _OpenDesktop(
        string lpszDesktop,
        uint dwFlags,
        bool fInherit,
        AdvApi32.ACCESS_MASK dwDesiredAccess
    );

    public static IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, AdvApi32.ACCESS_MASK dwDesiredAccess)
    {
        IntPtr retval = _OpenDesktop(lpszDesktop, dwFlags, fInherit, dwDesiredAccess);
        if (retval == IntPtr.Zero)
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    [DllImport("user32.dll", EntryPoint="CloseDesktop", SetLastError=true)]
    public static extern bool _CloseDesktop(IntPtr hDesktop);

    public static void CloseDesktop(IntPtr hDesktop)
    {
        if (!_CloseDesktop(hDesktop))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }

    [Flags] 
    public enum DESKTOP_ACCESS_MASK: uint
    {
        DESKTOP_READOBJECTS = 0x0001,
        DESKTOP_CREATEWINDOW = 0x0002,
        DESKTOP_CREATEMENU = 0x0004,
        DESKTOP_HOOKCONTROL = 0x0008,
        DESKTOP_JOURNALRECORD = 0x0010,
        DESKTOP_JOURNALPLAYBACK = 0x0020,
        DESKTOP_ENUMERATE = 0x0040,
        DESKTOP_WRITEOBJECTS = 0x0080,
        DESKTOP_SWITCHDESKTOP = 0x0100
    }
}

public sealed class AdvApi32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    public enum LogonType: int
    {
        INTERACTIVE = 2,
        NETWORK,
        BATCH,
        SERVICE,
        UNLOCK = 7,
        NETWORK_CLEARTEXT,
        NEW_CREDENTIALS
    }

    public enum LogonProvider: int
    {
        DEFAULT = 0,
        WINNT35 = 1,
        WINNT40 = 2,
        WINNT50 = 3
    }


    [DllImport("advapi32.dll", EntryPoint="LogonUserW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _LogonUser(
        string pszUserName,
        string pszDomain,
        string pszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("advapi32.dll", EntryPoint="LogonUserW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _LogonUser(
        string pszUserName,
        string pszDomain,
        IntPtr pszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    );

    public static bool _LogonUser(
        string pszUserName,
        string pszDomain,
        SecureString pszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    )
    {
        IntPtr password = Marshal.SecureStringToCoTaskMemUnicode(pszPassword);
        try
        {
            return _LogonUser(
                pszUserName,
                pszDomain,
                password,
                dwLogonType,
                dwLogonProvider,
                out phToken
            );
        }
        finally
        {
            Marshal.ZeroFreeCoTaskMemUnicode(password);
        }
    }

    public static IntPtr LogonUser(
        string pszUserName,
        string pszDomain,
        string pszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider
    )
    {
        IntPtr token = IntPtr.Zero;
        if (!_LogonUser(pszUserName, pszDomain, pszPassword, dwLogonType, dwLogonProvider, out token))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return token;
    }

    public static IntPtr LogonUser(
        string pszUserName,
        string pszDomain,
        SecureString pszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider
    )
    {
        IntPtr token = IntPtr.Zero;
        if (!_LogonUser(pszUserName, pszDomain, pszPassword, dwLogonType, dwLogonProvider, out token))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return token;
    }

    [DllImport("advapi32.dll", EntryPoint="CreateProcessAsUserW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        Kernel32.CreateProcessFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref Kernel32.STARTUPINFO lpStartupInfo,
        out Kernel32.PROCESS_INFORMATION lpProcessInformation
    );

    public static Kernel32.PROCESS_INFORMATION CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        Kernel32.CreateProcessFlags dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref Kernel32.STARTUPINFO lpStartupInfo
    )
    {
        Kernel32.PROCESS_INFORMATION retval;
        if (!_CreateProcessAsUser(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            ref lpStartupInfo,
            out retval
        ))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error(), lpApplicationName);
        }
        return retval;
    }

    [DllImport("advapi32.dll", EntryPoint="ImpersonateLoggedOnUser", SetLastError=true)]
    public static extern bool _ImpersonateLoggedOnUser(IntPtr hToken);

    public static void ImpersonateLoggedOnUser(IntPtr hToken)
    {
        if (!_ImpersonateLoggedOnUser(hToken))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }


    [DllImport("advapi32.dll", EntryPoint="ConvertSidToStringSidW", SetLastError=true)]
    public static extern bool _ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    public static string ConvertSidToStringSid(IntPtr sid)
    {
        IntPtr str;
        if (!_ConvertSidToStringSid(sid, out str))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        try
        {
            return Marshal.PtrToStringUni(str);
        }
        finally
        {
            Marshal.FreeHGlobal(str);
        }
    }

    [Flags]
    public enum SECURITY_INFORMATION: uint
    {
        OWNER            = 0x00000001,
        GROUP            = 0x00000002,
        DACL             = 0x00000004,
        SACL             = 0x00000008,
        UNPROTECTED_SACL = 0x10000000,
        UNPROTECTED_DACL = 0x20000000,
        PROTECTED_SACL   = 0x40000000,
        PROTECTED_DACL   = 0x80000000
    }

    public enum SE_OBJECT_TYPE
    {
        UNKNOWN_OBJECT_TYPE = 0,
        FILE_OBJECT,
        SERVICE,
        PRINTER,
        REGISTRY_KEY,
        LMSHARE,
        KERNEL_OBJECT,
        WINDOW_OBJECT,
        DS_OBJECT,
        DS_OBJECT_ALL,
        PROVIDER_DEFINED_OBJECT,
        WMIGUID_OBJECT,
        REGISTRY_WOW64_32KEY
    }

    [DllImport("advapi32.dll", EntryPoint="FreeSid", SetLastError=true)]
    public static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", EntryPoint="GetLengthSid", SetLastError=true)]
    public static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", EntryPoint="ConvertStringSidToSidW", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool _ConvertStringSidToSid(string stringSid, out IntPtr sid);

    public static IntPtr ConvertStringSidToSid(string stringSid)
    {
        IntPtr retval;
        if (!_ConvertStringSidToSid(stringSid, out retval))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    public static int ConvertStringSidToSid(string stringSid, IntPtr buf)
    {
        string[] components = stringSid.Split('-');
        if (components.Length < 3 || components.Length > 10 || components[0] != "S")
        {
            throw new ArgumentException(string.Format("Specified string ({}) is not a valid string SID", stringSid));
        }
        int nSubauthorities = components.Length - 3;
        int size = 8 + nSubauthorities * 4;
        if (buf != IntPtr.Zero)
        {
            int revision = int.Parse(components[1]);
            long identifierAuthority = long.Parse(components[2]);
            Marshal.WriteByte(buf + 0, (byte)revision);
            Marshal.WriteByte(buf + 1, (byte)nSubauthorities);
            Marshal.WriteByte(buf + 2, (byte)((identifierAuthority >> 40) & 255));
            Marshal.WriteByte(buf + 3, (byte)((identifierAuthority >> 32) & 255));
            Marshal.WriteByte(buf + 4, (byte)((identifierAuthority >> 24) & 255));
            Marshal.WriteByte(buf + 5, (byte)((identifierAuthority >> 16) & 255));
            Marshal.WriteByte(buf + 6, (byte)((identifierAuthority >> 8) & 255));
            Marshal.WriteByte(buf + 7, (byte)((identifierAuthority >> 0) & 255));
            for (int i = 0; i < nSubauthorities; i++) {
                Marshal.WriteInt32(buf + 8 + i * 4, (int)uint.Parse(components[i + 3]));
            }
        }
        return size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _ACL
    {
        byte AclRevision;
        byte Sbz1;
        ushort AclSize;
        ushort AceCount;
        ushort Sbz2;
    }

    public enum AceType: byte
    {
        ACCESS_ALLOWED_ACE_TYPE = 0x0,
        ACCESS_MIN_MS_ACE_TYPE = 0x0,
        ACCESS_DENIED_ACE_TYPE = 0x1,
        SYSTEM_AUDIT_ACE_TYPE = 0x2,
        SYSTEM_ALARM_ACE_TYPE = 0x3,
        ACCESS_MAX_MS_V2_ACE_TYPE = 0x3,

        ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x4,
        ACCESS_MAX_MS_V3_ACE_TYPE = 0x4,

        ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x5,
        ACCESS_MIN_MS_OBJECT_ACE_TYPE = 0x5,
        ACCESS_DENIED_OBJECT_ACE_TYPE = 0x6,
        SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x7,
        SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x8,
        ACCESS_MAX_MS_OBJECT_ACE_TYPE = 0x8,

        ACCESS_MAX_MS_V4_ACE_TYPE = 0x8,
        ACCESS_MAX_MS_ACE_TYPE = 0x8,

        ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9,
        ACCESS_DENIED_CALLBACK_ACE_TYPE = 0xA,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xB,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0xC,
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0xD,
        SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0xE,
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0xF,
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,

        SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12,
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13,
        ACCESS_MAX_MS_V5_ACE_TYPE = 0x13
    }

    [Flags]
    public enum AceFlags: byte
    {
        OBJECT_INHERIT_ACE = 0x1,
        CONTAINER_INHERIT_ACE = 0x2,
        NO_PROPAGATE_INHERIT_ACE = 0x4,
        INHERIT_ONLY_ACE = 0x8,
        INHERITED_ACE = 0x10,
        VALID_INHERIT_FLAGS = 0x1F,

        SUCCESSFUL_ACCESS_ACE_FLAG = 0x40,
        FAILED_ACCESS_ACE_FLAG = 0x80
    }

    [Flags]
    public enum ACCESS_MASK: uint
    {
        DELETE                   = 0x00010000,
        READ_CONTROL             = 0x00020000,
        WRITE_DAC                = 0x00040000,
        WRITE_OWNER              = 0x00080000,
        SYNCHRONIZE              = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ     = READ_CONTROL,
        STANDARD_RIGHTS_WRITE    = READ_CONTROL,
        STANDARD_RIGHTS_EXECUTE  = READ_CONTROL,

        STANDARD_RIGHTS_ALL      = 0x001F0000,

        SPECIFIC_RIGHTS_ALL      = 0x0000FFFF,

        ACCESS_SYSTEM_SECURITY   = 0x01000000,
        MAXIMUM_ALLOWED          = 0x02000000,

        GENERIC_READ             = 0x80000000,
        GENERIC_WRITE            = 0x40000000,
        GENERIC_EXECUTE          = 0x20000000,
        GENERIC_ALL              = 0x10000000
    }


    [StructLayout(LayoutKind.Sequential)]
    struct _ACE_HEADER
    {
        AceType  AceType;
        AceFlags AceFlags;
        ushort   AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _ACCESS_ALLOWED_ACE
    {
        _ACE_HEADER  Header;
        ACCESS_MASK Mask;
        uint        SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _ACCESS_ALLOWED_CALLBACK_ACE
    {
        _ACE_HEADER  Header;
        ACCESS_MASK Mask;
        uint        SidStart;
    }

    public interface IACE
    {
        AceType AceType { get; }
        AceFlags AceFlags { get; }
        int Length { get; }
 
        int Render(IntPtr p);
    }

    public abstract class ACE: IACE
    {
        AceFlags aceFlags;

        public abstract AceType AceType { get; }

        public AceFlags AceFlags
        {
            get { return aceFlags; }
            set { aceFlags = value; }
        }
        
        public abstract int Length { get; }

        public abstract int Render(IntPtr p);

        protected ACE(AceFlags aceFlags)
        {
            this.aceFlags = aceFlags;
        }
    }

    public class OpaqueACE: IACE
    {
        IntPtr ptr;

        public AceType AceType
        {
            get
            {
                return (AceType)Marshal.ReadByte(ptr, 0);
            }
        }

        public AceFlags AceFlags
        {
            get
            {
                return (AceFlags)Marshal.ReadByte(ptr, 1);
            }
        }

        public int Length
        {
            get
            {
                return (int)(ushort)Marshal.ReadInt16(ptr, 2);
            }
        }

        public int Render(IntPtr buf)
        {
            int length = Length;
            Kernel32.MoveMemory(buf, ptr, (uint)length);
            return length;
        }

        public OpaqueACE(IntPtr ptr)
        {
            this.ptr = ptr;
        }
    }

    public class AccessAllowed: ACE
    {
        public override AceType AceType
        {
            get { return AceType.ACCESS_ALLOWED_ACE_TYPE; }
        }

        public ACCESS_MASK AccessMask;
        public string SID;

        public override int Length
        {
            get
            {
                return 4 + 4 + ConvertStringSidToSid(SID, IntPtr.Zero);
            }
        }

        public override int Render(IntPtr buf)
        {
            Marshal.WriteByte(buf + 0, (byte)AceType);
            Marshal.WriteByte(buf + 1, (byte)AceFlags);
            Marshal.WriteInt32(buf + 4, (int)AccessMask);
            int aceSize = 8 + ConvertStringSidToSid(SID, buf + 8);
            Marshal.WriteInt16(buf + 2, (short)(ushort)aceSize);
            return aceSize;
        }

        public AccessAllowed(AceFlags aceFlags, ACCESS_MASK accessMask, string sid): base(aceFlags)
        {
            this.AccessMask = accessMask;
            this.SID = sid;
        }
    }

    public const int MIN_ACL_REVISION = 2;
    public const int MAX_ACL_REVISION = 4;

    public interface IACL: IEnumerable<IACE>
    {
        IntPtr Render();

        int Count { get; }

        int Length { get; }
    }

    public class ACEEnumerator: IEnumerator<IACE>
    {
        IACE current;
        IntPtr pAcl;
        IntPtr pEnd;
        IntPtr p;
        int i;
        int count;

        public IACE Current
        {
            get
            {
                return current;
            }
        }

        object IEnumerator.Current
        {
            get { return Current; }
        }

        public bool MoveNext()
        {
            if (i >= count || (long)p >= (long)pEnd)
            {
                return false;
            }

            AceType aceType = (AceType)Marshal.ReadByte(p, 0);
            AceFlags aceFlags = (AceFlags)Marshal.ReadByte(p, 1);
            int aceSize = (int)(ushort)Marshal.ReadInt16(p, 2);
            IACE ace = null;
            switch (aceType)
            {
            case AceType.ACCESS_ALLOWED_ACE_TYPE:
                ACCESS_MASK accessMask = (ACCESS_MASK)Marshal.ReadInt32(p, 4);
                ace = new AccessAllowed(aceFlags, accessMask, ConvertSidToStringSid(p + 8));
                break;
            default:
                ace = new OpaqueACE(p);
                break;
            }
            current = ace;
            p += aceSize;
            i++;
            return true;
        }

        public void Reset()
        {
            this.p = pAcl + 8;
            this.i = 0;
        }

        public void Dispose()
        {
        }

        public ACEEnumerator(IntPtr pAcl, int count)
        {
            int aclRevision = (int)Marshal.ReadByte(pAcl, 0);
            if (aclRevision < MIN_ACL_REVISION || aclRevision > MAX_ACL_REVISION)
            {
                throw new ArgumentException(string.Format("Invalid ACL revision: {}", aclRevision));
            }
            int aclSize = (int)(ushort)Marshal.ReadInt16(pAcl, 2);
            int aclCount = count;
            this.pAcl = pAcl;
            this.pEnd = pAcl + 8 + aclSize;
            this.count = aclCount;
            Reset();
        }
    }

    public class ACLView: IACL
    {
        IntPtr pAcl;

        public IntPtr Ptr
        {
            get { return pAcl; }
        }

        public IEnumerator<IACE> GetEnumerator()
        {
            return new ACEEnumerator(pAcl, Count);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public int Count
        {
            get { return (int)(ushort)Marshal.ReadInt16(pAcl, 4); }
        }

        public int Length
        {
            get { return (ushort)Marshal.ReadInt16(pAcl, 2); }
        }

        public ACLView(IntPtr pAcl)
        {
            this.pAcl = pAcl;
        }

        public IntPtr Render()
        {
            uint aclSize = (uint)Length;
            IntPtr buf = Marshal.AllocHGlobal((int)aclSize);
            Kernel32.MoveMemory(buf, pAcl, aclSize);
            return buf;
        }
    }

    public class ACL: List<IACE>, IACL
    {
        public int Length
        {
            get
            {
                int aclSize = 8;
                foreach (IACE ace in this)
                {
                    aclSize += ace.Length;
                }
                return aclSize;
            }
        }

        public IntPtr Render()
        {
            int aclSize = Length;
            IntPtr buf = Marshal.AllocHGlobal(aclSize);
            Marshal.WriteByte(buf, 2);
            Marshal.WriteInt16(buf + 2, (short)aclSize);
            Marshal.WriteInt16(buf + 4, (short)Count);
            IntPtr p = buf + 8;
            foreach (IACE ace in this)
            {
                p += ace.Render(p);
            }
            return buf; 
        }

        public ACL(): base() {}

        public ACL(IEnumerable<IACE> enumerable): base(enumerable) {}
    }

    [Flags]
    public enum SECURITY_DESCRIPTOR_CONTROL: ushort
    {
        SE_OWNER_DEFAULTED = 0x0001,
        SE_GROUP_DEFAULTED = 0x0002,
        SE_DACL_PRESENT = 0x0004,
        SE_DACL_DEFAULTED = 0x0008,
        SE_SACL_PRESENT = 0x0010,
        SE_SACL_DEFAULTED = 0x0020,
        SE_DACL_AUTO_INHERIT_REQ = 0x0100,
        SE_SACL_AUTO_INHERIT_REQ = 0x0200,

        SE_SACL_AUTO_INHERITED = 0x0800,
        SE_DACL_PROTECTED = 0x1000,
        SE_SACL_PROTECTED = 0x2000,
        SE_RM_CONTROL_VALID = 0x4000,
        SE_SELF_RELATIVE = 0x8000
    }

    public const int SECURITY_DESCRIPTOR_REVISION = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct _SECURITY_DESCRIPTOR {
        byte Revision;
        byte Sbz1;
        SECURITY_DESCRIPTOR_CONTROL Control;
        IntPtr Owner;
        IntPtr Group;
        IntPtr Sacl;
        IntPtr Dacl;
    };

    [DllImport("advapi32.dll", EntryPoint="GetSecurityDescriptorOwner", SetLastError=true)]
    public static extern bool _GetSecurityDescriptorOwner(
        IntPtr pSecurityDescriptor,
        out IntPtr owner,
        out bool lpbOwnerDefaulted
    );

    public static IntPtr GetSecurityDescriptorOwner(IntPtr pSecurityDescriptor, out bool defaulted)
    {
        IntPtr retval;
        if (!_GetSecurityDescriptorOwner(pSecurityDescriptor, out retval, out defaulted))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    public static IntPtr GetSecurityDescriptorOwner(IntPtr pSecurityDescriptor)
    {
        bool _;
        return GetSecurityDescriptorOwner(pSecurityDescriptor, out _);
    }

    [DllImport("advapi32.dll", EntryPoint="GetSecurityDescriptorGroup", SetLastError=true)]
    public static extern bool _GetSecurityDescriptorGroup(
        IntPtr pSecurityDescriptor,
        out IntPtr owner,
        out bool lpbGroupDefaulted
    );

    public static IntPtr GetSecurityDescriptorGroup(IntPtr pSecurityDescriptor, out bool defaulted)
    {
        IntPtr retval;
        if (!_GetSecurityDescriptorGroup(pSecurityDescriptor, out retval, out defaulted))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }
    
    public static IntPtr GetSecurityDescriptorGroup(IntPtr pSecurityDescriptor)
    {
        bool _;
        return GetSecurityDescriptorGroup(pSecurityDescriptor, out _);
    }

    [DllImport("advapi32.dll", EntryPoint="GetSecurityDescriptorDacl", SetLastError=true)]
    public static extern bool _GetSecurityDescriptorDacl(
        IntPtr pSecurityDescriptor,
        out bool lpbDaclPresent,
        out IntPtr pDacl,
        out bool lpbDaclDefaulted
    );

    public static IntPtr GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, out bool defaulted)
    {
        IntPtr retval = IntPtr.Zero;
        bool present;
        if (!_GetSecurityDescriptorDacl(pSecurityDescriptor, out present, out retval, out defaulted))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    public static IntPtr GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor)
    {
        bool _;
        return GetSecurityDescriptorDacl(pSecurityDescriptor, out _);
    }

    [DllImport("advapi32.dll", EntryPoint="GetSecurityDescriptorSacl", SetLastError=true)]
    public static extern bool _GetSecurityDescriptorSacl(
        IntPtr pSecurityDescriptor,
        out bool lpbSaclPresent,
        out IntPtr pSacl,
        out bool lpbSaclDefaulted
    );

    public static IntPtr GetSecurityDescriptorSacl(IntPtr pSecurityDescriptor, out bool defaulted)
    {
        IntPtr retval = IntPtr.Zero;
        bool present;
        if (!_GetSecurityDescriptorSacl(pSecurityDescriptor, out present, out retval, out defaulted))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }

    public static IntPtr GetSecurityDescriptorSacl(IntPtr pSecurityDescriptor)
    {
        bool _;
        return GetSecurityDescriptorSacl(pSecurityDescriptor, out _);
    }

    [DllImport("advapi32.dll", EntryPoint="InitializeSecurityDescriptor", SetLastError=true)]
    public static extern bool _InitializeSecurityDescriptor(IntPtr pSecurityDescriptor, uint dwRevision);

    public static void InitializeSecurityDescriptor(IntPtr pSecurityDescriptor, uint dwRevision)
    {
        if (!_InitializeSecurityDescriptor(pSecurityDescriptor, dwRevision))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }

    public class SecurityDescriptor: IDisposable
    {
        class DummyACL: IACL
        {
            public IEnumerator<IACE> GetEnumerator()
            {
                return null;
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return null;
            }

            public int Count
            {
                get { return -1; }
            }

            public int Length
            {
                get { return 0; }
            }

            internal DummyACL() {}

            public IntPtr Render()
            {
                return IntPtr.Zero;
            }
        }

        public static readonly string DEFAULTED_SID = "DEFAULTED";
        public static readonly IACL DEFAULTED_ACL = new DummyACL();

        bool disposed;
        static readonly int descriptorSize = Marshal.SizeOf(typeof(_SECURITY_DESCRIPTOR));

        IntPtr pSecurityDescriptor;
        bool shouldBeFreed;

        bool ownerDefaulted;
        IntPtr? pSidOwner;
        bool ownerSet;
        string owner;

        bool groupDefaulted;
        IntPtr? pSidGroup;
        bool groupSet;
        string group;

        bool saclDefaulted;
        IntPtr? pSacl;
        bool saclSet;
        IACL sacl;

        bool daclDefaulted;
        IntPtr? pDacl;
        bool daclSet;
        IACL dacl;

        void RenderOwner()
        {
            if (!ownerSet)
            {
                if (pSidOwner == null)
                {
                    pSidOwner = GetSecurityDescriptorOwner(pSecurityDescriptor);
                }
                owner = pSidOwner != IntPtr.Zero ? ConvertSidToStringSid((IntPtr)pSidOwner): null;
                ownerSet = true;
            }
        }

        public string Owner
        {
            get
            {
                RenderOwner();
                return owner;
            }

            set
            {
                if (value == DEFAULTED_SID)
                {
                    OwnerDefaulted = true;
                    return;
                }
                owner = value;
                pSidOwner = null;
                ownerSet = true;
                ownerDefaulted = false;
                ResetSecurityDescriptor();
            }
        }

        public bool OwnerDefaulted
        {
            get { return ownerDefaulted; }
            set
            {
                if (ownerDefaulted != value)
                {
                    ownerDefaulted = value;
                    if (value)
                    {
                        owner = null;
                        pSidOwner = null;
                        ownerSet = false;
                        ResetSecurityDescriptor();
                    }
                }
            }
        }

        public IntPtr? PSidOwner
        {
            get
            {
                PopulateSecurityDescriptor();
                return pSidOwner;
            }
        }

        void RenderGroup()
        {
            if (!groupSet)
            {
                if (pSidGroup == null)
                {
                    pSidGroup = GetSecurityDescriptorGroup(pSecurityDescriptor);
                }
                group = pSidGroup != IntPtr.Zero ? ConvertSidToStringSid((IntPtr)pSidGroup): null;
                groupSet = true;
            }
        }

        public string Group
        {
            get
            {
                RenderGroup();
                return group;
            }

            set
            {
                if (value == DEFAULTED_SID)
                {
                    GroupDefaulted = true;
                    return;
                }
                group = value;
                pSidGroup = null;
                groupSet = true;
                ResetSecurityDescriptor();
            }
        }

        public bool GroupDefaulted
        {
            get { return groupDefaulted; }
            set
            {
                if (groupDefaulted != value)
                {
                    groupDefaulted = value;
                    if (value)
                    {
                        group = null;
                        pSidGroup = null;
                        groupSet = false;
                        ResetSecurityDescriptor();
                    }
                }
            }
        }

        public IntPtr? PSidGroup
        {
            get
            {
                PopulateSecurityDescriptor();
                return pSidGroup;
            }
        }

        void RenderSacl()
        {
            if (!saclSet)
            {
                if (pSacl == null)
                {
                    pSacl = GetSecurityDescriptorSacl(pSecurityDescriptor);
                }
                sacl = pSacl != IntPtr.Zero ? new ACLView((IntPtr)pSacl): null;
                saclSet = true;
            }
        }

        public IACL Sacl
        {
            get
            {
                RenderSacl();
                return sacl;
            }

            set
            {
                if (value == DEFAULTED_ACL)
                {
                    SaclDefaulted = true;
                    return;
                }
                sacl = value;
                pSacl = null;
                saclSet = true;
                ResetSecurityDescriptor();
            }
        }

        public bool SaclDefaulted
        {
            get { return saclDefaulted; }
            set
            {
                if (saclDefaulted != value)
                {
                    saclDefaulted = value;
                    if (value)
                    {
                        sacl = null;
                        pSacl = null;
                        saclSet = false;
                        ResetSecurityDescriptor();
                    }
                }
            }
        }

        public IntPtr? PSacl
        {
            get
            {
                PopulateSecurityDescriptor();
                return pSacl;
            }
        }

        void RenderDacl()
        {
            if (!daclSet)
            {
                if (pDacl == null)
                {
                    pDacl = GetSecurityDescriptorSacl(pSecurityDescriptor);
                }
                dacl = pDacl != IntPtr.Zero ? new ACLView((IntPtr)pDacl): null;
                daclSet = true;
            }
        }

        public IACL Dacl
        {
            get
            {
                RenderDacl();
                return dacl;
            }

            set
            {
                if (value == DEFAULTED_ACL)
                {
                    DaclDefaulted = true;
                    return;
                }
                dacl = value;
                pDacl = null;
                daclSet = true;
                ResetSecurityDescriptor();
            }
        }

        public bool DaclDefaulted
        {
            get { return daclDefaulted; }
            set
            {
                if (daclDefaulted != value)
                {
                    daclDefaulted = value;
                    if (value)
                    {
                        dacl = null;
                        pDacl = null;
                        daclSet = false;
                        ResetSecurityDescriptor();
                    }
                }
            }
        }

        public IntPtr? PDacl
        {
            get
            {
                PopulateSecurityDescriptor();
                return pDacl;
            }
        }

        void PopulateSecurityDescriptor()
        {
            if (pSecurityDescriptor == IntPtr.Zero)
            {
                pSecurityDescriptor = Render(ref pSidOwner, ref pSidGroup, ref pSacl, ref pDacl);
                shouldBeFreed = true;
            }
        }

        public IntPtr Ptr
        {
            get
            {
                PopulateSecurityDescriptor();
                return pSecurityDescriptor;
            }
        }

        private void FreeSecurityDescriptor()
        {
            SECURITY_DESCRIPTOR_CONTROL control = (SECURITY_DESCRIPTOR_CONTROL)(ushort)Marshal.ReadInt16(pSecurityDescriptor, 2);

            if ((control & SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE) == 0)
            {
                if (pSidOwner != null && pSidOwner != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pSidOwner);
                    pSidOwner = null;
                }
                if (pSidGroup != null && pSidGroup != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pSidGroup);
                    pSidGroup = null;
                }
                if (pSacl != null && pSacl != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pSacl);
                    pSacl = null;
                }
                if (pDacl != null && pDacl != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pDacl);
                    pDacl = null;
                }
            }

            if (shouldBeFreed && pSecurityDescriptor != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSecurityDescriptor);
                pSecurityDescriptor = IntPtr.Zero;
            }
        }

        private void ResetSecurityDescriptor()
        {
            RenderOwner();
            RenderGroup();
            RenderSacl();
            RenderDacl();
            FreeSecurityDescriptor();
        }

        public IntPtr Render(ref IntPtr? pSidOwner, ref IntPtr? pSidGroup, ref IntPtr? pSacl, ref IntPtr? pDacl)
        {
            IntPtr ptr = Marshal.AllocHGlobal(descriptorSize);
            InitializeSecurityDescriptor(ptr, SECURITY_DESCRIPTOR_REVISION);
            SECURITY_DESCRIPTOR_CONTROL flags = 0;
            try
            {
                if (Owner != null)
                {
                    pSidOwner = ConvertStringSidToSid(Owner);
                }
                if (ownerDefaulted)
                {
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_OWNER_DEFAULTED;
                }
                Marshal.WriteIntPtr(ptr + 4 + IntPtr.Size * 0, pSidOwner.GetValueOrDefault(IntPtr.Zero));
                if (Group != null)
                {
                    pSidGroup = ConvertStringSidToSid(Group);
                }
                if (groupDefaulted)
                {
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_GROUP_DEFAULTED;
                }
                Marshal.WriteIntPtr(ptr + 4 + IntPtr.Size * 1, pSidGroup.GetValueOrDefault(IntPtr.Zero));
                if (saclDefaulted)
                {
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_SACL_DEFAULTED;
                }
                if (sacl != null)
                {
                    pSacl = sacl.Render();
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_SACL_PRESENT;
                }
                else
                {
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_SACL_PROTECTED;
                }
                Marshal.WriteIntPtr(ptr + 4 + IntPtr.Size * 2, pSacl.GetValueOrDefault(IntPtr.Zero));
                if (dacl != null)
                {
                    pDacl = dacl.Render();
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT;
                }
                else
                {
                    flags |= SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PROTECTED;
                }
                Marshal.WriteIntPtr(ptr + 4 + IntPtr.Size * 3, pDacl.GetValueOrDefault(IntPtr.Zero));
            }
            catch
            {
                if (pSidOwner != null && pSidOwner != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pSidOwner);
                }
                if (pSidGroup != null && pSidGroup != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pSidGroup);
                }
                if (pSacl != null && pSacl != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pSacl);
                }
                if (pDacl != null && pDacl != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal((IntPtr)pDacl);
                }
                throw;
            }
            return ptr;
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            FreeSecurityDescriptor();
        }

        public SecurityDescriptor(
            IntPtr pSecurityDescriptor,
            bool shouldBeFreed = false,
            IntPtr? pSidOwner = null,
            IntPtr? pSidGroup = null,
            IntPtr? pSacl = null,
            IntPtr? pDacl = null
        )
        {
            this.pSecurityDescriptor = pSecurityDescriptor;
            SECURITY_DESCRIPTOR_CONTROL control = (SECURITY_DESCRIPTOR_CONTROL)(ushort)Marshal.ReadInt16(pSecurityDescriptor, 2);
            this.shouldBeFreed = shouldBeFreed;
            this.pSidOwner = pSidOwner;
            this.pSidGroup = pSidGroup;
            this.pSacl = pSacl;
            this.pDacl = pDacl;
            ownerDefaulted = (control & SECURITY_DESCRIPTOR_CONTROL.SE_OWNER_DEFAULTED) != 0;
            groupDefaulted = (control & SECURITY_DESCRIPTOR_CONTROL.SE_GROUP_DEFAULTED) != 0;
            saclDefaulted = (control & SECURITY_DESCRIPTOR_CONTROL.SE_SACL_DEFAULTED) != 0;
            daclDefaulted = (control & SECURITY_DESCRIPTOR_CONTROL.SE_DACL_DEFAULTED) != 0;
        }

        public SecurityDescriptor(
            string owner,
            string group,
            IACL sacl,
            IACL dacl
        )
        {
            Owner = owner;
            Group = group;
            Sacl = sacl;
            Dacl = dacl;
        }
    }

    [DllImport("advapi32.dll", EntryPoint="GetSecurityInfo", SetLastError=true)]
    public static extern uint _GetSecurityInfo(
        IntPtr handle,
        SE_OBJECT_TYPE objectType,
        SECURITY_INFORMATION securityInfo,
        out IntPtr pSidOwner,
        out IntPtr pSidGroup,
        out IntPtr pDacl, // beware the order! this is opposite of SECURITY_DESCRIPTOR
        out IntPtr pSacl, // beware the order! this is opposite of SECURITY_DESCRIPTOR
        out IntPtr pSecurityDescriptor
    );

    public static SecurityDescriptor GetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE objectType, SECURITY_INFORMATION securityInfo)
    {
        IntPtr sidOwner, sidGroup, dacl, sacl, securityDescriptor;
        uint err = _GetSecurityInfo(
            handle,
            objectType,
            securityInfo,
            out sidOwner,
            out sidGroup,
            out dacl,
            out sacl,
            out securityDescriptor
        );
        if (0 != err)
        {
            throw new Win32APIException((int)err);
        }
        return new SecurityDescriptor(
            securityDescriptor,
            true,
            (securityInfo & SECURITY_INFORMATION.OWNER) != 0 ? (IntPtr?)sidOwner: (IntPtr?)null,
            (securityInfo & SECURITY_INFORMATION.GROUP) != 0 ? (IntPtr?)sidGroup: (IntPtr?)null,
            (securityInfo & SECURITY_INFORMATION.SACL) != 0 ? (IntPtr?)sacl: (IntPtr?)null,
            (securityInfo & SECURITY_INFORMATION.DACL) != 0 ? (IntPtr?)dacl: (IntPtr?)null
        );
    }
 
    [DllImport("advapi32.dll", EntryPoint="SetSecurityInfo", SetLastError=true)]
    public static extern uint _SetSecurityInfo(
        IntPtr handle,
        SE_OBJECT_TYPE objectType,
        SECURITY_INFORMATION securityInfo,
        IntPtr pSidOwner,
        IntPtr pSidGroup,
        IntPtr pDacl, // beware the order! this is opposite of SECURITY_DESCRIPTOR
        IntPtr pSacl  // beware the order! this is opposite of SECURITY_DESCRIPTOR
    );

    public static void SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE objectType, SECURITY_INFORMATION securityInfo, SecurityDescriptor desc)
    {
        uint err = _SetSecurityInfo(
            handle,
            objectType,
            securityInfo,
            desc.PSidOwner.GetValueOrDefault(IntPtr.Zero),
            desc.PSidGroup.GetValueOrDefault(IntPtr.Zero),
            desc.PDacl.GetValueOrDefault(IntPtr.Zero),
            desc.PSacl.GetValueOrDefault(IntPtr.Zero)
        );
        if (0 != err)
        {
            throw new Win32APIException((int)err);
        }
    }

    public enum TOKEN_INFORMATION_CLASS {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        MaxTokenInfoClass
    }

    [DllImport("advapi32.dll", EntryPoint="GetTokenInformation", SetLastError=true)]
    public static extern bool _GetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength
    );

    public static void GetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength
    )
    {
        if (!_GetTokenInformation(
            tokenHandle,
            tokenInformationClass,
            tokenInformation,
            tokenInformationLength,
            out returnLength))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
    }

    public static IntPtr GetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass
    )
    {
        uint returnLength = 0;
        _GetTokenInformation(tokenHandle, tokenInformationClass, IntPtr.Zero, 0, out returnLength);
        IntPtr buf = Marshal.AllocHGlobal((int)returnLength);
        try
        {
            GetTokenInformation(tokenHandle, tokenInformationClass, buf, returnLength, out returnLength);
        }
        catch
        {
            Marshal.FreeHGlobal(buf);
            throw;
        }

        return buf;
    }

    public struct _SID_AND_ATTRIBUTES {
        IntPtr Sid;
        uint   Attributes;
    }

    public static string GetTokenUser(IntPtr tokenHandle, out uint attributes)
    {
        IntPtr buf = GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser);
        try
        {
            IntPtr pSid = Marshal.ReadIntPtr(buf, 0);
            attributes = (uint)Marshal.ReadInt32(buf, IntPtr.Size);
            return ConvertSidToStringSid(pSid);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    [DllImport("advapi32.dll", EntryPoint="OpenProcessToken", SetLastError=true)]
    public static extern bool _OpenProcessToken(
        IntPtr processHandle,
        ACCESS_MASK desiredAccess,
        out IntPtr tokenHandle
    );

    public static IntPtr OpenProcessToken(IntPtr processHandle, ACCESS_MASK desiredAccess)
    {
        IntPtr retval;
        if (!_OpenProcessToken(processHandle, desiredAccess, out retval))
        {
            throw new Win32APIException(Marshal.GetLastWin32Error());
        }
        return retval;
    }
}

public sealed class PSAPI
{
    [DllImport("psapi.dll", EntryPoint="GetProcessImageFileNameW", SetLastError=true)]
    public static extern uint _GetProcessImageFileName(IntPtr hProcess, IntPtr lpImageFileName, uint nSize);

    public static string GetProcessImageFileName(IntPtr hProcess)
    {
        IntPtr buf = Marshal.AllocHGlobal(260);
        try
        {
            uint len = _GetProcessImageFileName(hProcess, buf, 260);
            return Marshal.PtrToStringUni(buf, (int)len);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}

}

// vim: sts=4 ts=4 sw=4 et
