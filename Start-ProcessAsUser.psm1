# Copyright (C) 2016 Moriyoshi Koizumi <mozo@mozo.jp>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

$win32apidll = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "Win32API.dll")
Add-Type -LiteralPath $win32apidll

Add-Type -TypeDefinition @'
using System;

namespace StartProcessAsUser {

public class Process: IDisposable
{
    IntPtr handle;

    public int Id
    {
        get
        {
            return (int)Win32API.Kernel32.GetProcessId(handle);
        }
    }

    public IntPtr Handle
    {
        get { return handle; }
    }

    public int ExitCode
    {
        get
        {
            return (int)Win32API.Kernel32.GetExitCodeProcess(handle);
        }
    }

    public string ProcessName
    {
        get
        {
            return Win32API.PSAPI.GetProcessImageFileName(handle);
        }
    }

    public void Dispose()
    {
        if (handle != IntPtr.Zero)
        {
            Win32API.Kernel32.CloseHandle(handle);
        }
        handle = IntPtr.Zero;
    }

    ~Process()
    {
        Dispose();
    }

    public void WaitForExit()
    {
        Win32API.Kernel32.WaitForSingleObject(handle, uint.MaxValue);
    }

    public void WaitForExit(int timeout)
    {
        if (timeout < 0)
        {
            throw new ArgumentException("timeout cannot be negative");
        }
        Win32API.Kernel32.WaitForSingleObject(handle, (uint)timeout);
    }

    public void WaitForInputIdle()
    {
        Win32API.Kernel32.WaitForInputIdle(handle, uint.MaxValue);
    }

    public void WaitForInputIdle(int timeout)
    {
        if (timeout < 0)
        {
            throw new ArgumentException("timeout cannot be negative");
        }
        Win32API.Kernel32.WaitForInputIdle(handle, (uint)timeout);
    }

    public Process(IntPtr handle)
    {
        this.handle = handle;
    }
}

}
'@ -Language CSharp -ReferencedAssemblies $win32apidll

function Start-ProcessAsUser
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [String] $FilePath,
        [string[]] $ArgumentList = @(),
        [System.Management.Automation.PSCredential] $Credential = $null,
        [switch] $NoNewWindow = $false,
        [switch] $LoadUserProfile = $false,
        [switch] $UseNewEnvironment = $true,
        [System.Diagnostics.ProcessWindowStyle] $WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal,
        [string] $WorkingDirectory = $null,
        [switch] $Wait = $false,
        [switch] $PassThru = $false
    )

    PROCESS {
        [object] $_workingDirectory = [nullstring]::Value

        if (![string]::IsNullOrEmpty($WorkingDirectory))
        {
            $_workingDirectory = $WorkingDirectory
        }

        # resolve the path
        $resolvedFilePath = (Get-Command $FilePath).Definition

        # retrieve the window station
        $winStn = [Win32API.User32]::GetProcessWindowStation()

        # check if window station is visible
        if (![Win32API.User32]::GetUserObjectInformation(
                $winStn,
                [Win32API.User32+UserObjectInformationIndex]::UOI_FLAGS
            ).dwFlags)
        {
            throw "Window station is not visible; If you run this Cmdlet in the service context, you may need to set the value of HKLM:\System\CurrentControlSet\Control\Windows::NoInteractiveServices to 0."
        }

        if ($Credential -ne $null)
        {
            $token = [Win32API.AdvApi32]::LogonUser(
                $Credential.UserName,
                $null,
                $Credential.Password,
                [Win32API.AdvApi32+LogonType]::INTERACTIVE,
                [Win32API.AdvApi32+LogonProvider]::DEFAULT
            )
            [Uint32]$attrs = 0
        }
        else
        {
            $token = [Win32API.Advapi32]::OpenProcessToken(
                [Win32API.Kernel32]::GetCurrentProcess(),
                [Win32API.Advapi32+ACCESS_MASK]::READ_CONTROL + [Win32API.Advapi32+ACCESS_MASK]::GENERIC_ALL
            )
        }

        try
        {
            # retrieve the SID of the user
            [Uint32] $attrs = 0
            $userSid = [Win32API.AdvApi32]::GetTokenUser($token, [ref] $attrs)

            # retrieve the DACL of the window station,
            # add a couple of ACE to it and set it back to the window station.
            $info = [Win32API.AdvApi32]::GetSecurityInfo(
                $winStn,
                [Win32API.AdvApi32+SE_OBJECT_TYPE]::WINDOW_OBJECT,
                [Win32API.AdvApi32+SECURITY_INFORMATION]::DACL
            )

            try
            {
                $acl = (New-Object Win32API.AdvApi32+ACL $info.Dacl)
                $ace = (New-Object Win32API.AdvApi32+AccessAllowed @(
                    [Win32API.AdvApi32+AceFlags]::NO_PROPAGATE_INHERIT_ACE,
                    ([Win32API.AdvApi32+ACCESS_MASK]::GENERIC_ALL +
                        [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_EXECUTE +
                        [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_READ +
                        [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_WRITE),
                    $userSid
                ))
                $acl.Insert(0, $ace)
                $ace = (New-Object Win32API.AdvApi32+AccessAllowed @(
                    [Win32API.AdvApi32+AceFlags]([int][Win32API.AdvApi32+AceFlags]::OBJECT_INHERIT_ACE +
                        [int][Win32API.AdvApi32+AceFlags]::CONTAINER_INHERIT_ACE +
                        [int][Win32API.AdvApi32+AceFlags]::INHERIT_ONLY_ACE),

                    ([Win32API.AdvApi32+ACCESS_MASK]::GENERIC_ALL +
                        [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_EXECUTE +
                        [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_READ +
                        [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_WRITE +
                        [Win32API.AdvApi32+ACCESS_MASK]::DELETE +
                        [Win32API.AdvApi32+ACCESS_MASK]::READ_CONTROL +
                        [Win32API.AdvApi32+ACCESS_MASK]::WRITE_DAC +
                        [Win32API.AdvApi32+ACCESS_MASK]::WRITE_OWNER),
                    $userSid
                ))
                $acl.Insert(0, $ace)
                $info.Dacl = $acl
                [Win32API.AdvApi32]::SetSecurityInfo(
                    $winStn,
                    [Win32API.AdvApi32+SE_OBJECT_TYPE]::WINDOW_OBJECT,
                    [Win32API.AdvApi32+SECURITY_INFORMATION]::DACL,
                    $info
                )
            }
            finally
            {
                $info.Dispose()
            }

            # for each desktop,
            @("Default") | % {
                # open the desktop handle
                $desk = [Win32API.User32]::OpenDesktop(
                    $_,
                    0,
                    $false,
                    (
                        [Win32API.AdvApi32+ACCESS_MASK]::READ_CONTROL +
                            [Win32API.AdvApi32+ACCESS_MASK]::WRITE_DAC +
                            [Win32API.AdvApi32+ACCESS_MASK][Win32API.User32+DESKTOP_ACCESS_MASK]::DESKTOP_READOBJECTS +
                            [Win32API.AdvApi32+ACCESS_MASK][Win32API.User32+DESKTOP_ACCESS_MASK]::DESKTOP_WRITEOBJECTS
                    )
                )
                try
                {
                    # retrieve the DACL of the desktop,
                    # add an ACE and set it back to the desktop.
                    $info = [Win32API.AdvApi32]::GetSecurityInfo(
                        $desk,
                        [Win32API.AdvApi32+SE_OBJECT_TYPE]::WINDOW_OBJECT,
                        [Win32API.AdvApi32+SECURITY_INFORMATION]::DACL
                    )
                    try
                    {
                        $acl = (New-Object Win32API.AdvApi32+ACL $info.Dacl)
                        $ace = (New-Object Win32API.AdvApi32+AccessAllowed @(
                            0,
                            ([Win32API.AdvApi32+ACCESS_MASK]::GENERIC_ALL +
                                [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_EXECUTE +
                                [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_READ +
                                [Win32API.AdvApi32+ACCESS_MASK]::GENERIC_WRITE +
                                [Win32API.AdvApi32+ACCESS_MASK]::READ_CONTROL +
                                [Win32API.AdvApi32+ACCESS_MASK]::WRITE_DAC +
                                [Win32API.AdvApi32+ACCESS_MASK]::WRITE_OWNER),
                            $userSid
                        ))
                        $acl.Insert(0, $ace)
                        $info.Dacl = $acl
                        [Win32API.AdvApi32]::SetSecurityInfo(
                            $desk,
                            [Win32API.AdvApi32+SE_OBJECT_TYPE]::WINDOW_OBJECT,
                            [Win32API.AdvApi32+SECURITY_INFORMATION]::DACL,
                            $info
                        )
                    }
                    finally
                    {
                        $info.Dispose()
                    }
                }
                finally
                {
                    [Win32API.User32]::CloseDesktop($desk)
                }
            }

            # launch the process
            $startupInfo = New-Object Win32API.Kernel32+STARTUPINFO
            $startupInfo.dwFlags = $startupInfo.dwFlags + [Win32API.Kernel32+StartUpInfoFlags]::STARTF_USESHOWWINDOW
            $startupInfo.lpDesktop = "winsta0\default"

            if ($windowStyle -eq [System.Diagnostics.ProcessWindowStyle]::Hidden)
            {
                $startupInfo.wShowWindow = [Int16] [Win32API.User32+ShowWindowCommand]::SW_HIDE
            }
            elseif ($windowStyle -eq [System.Diagnostics.ProcessWindowStyle]::Maximized)
            {
                $startupInfo.wShowWindow = [Int16] [Win32API.User32+ShowWindowCommand]::SW_SHOWMAXIMIZED
            }
            elseif ($windowStyle -eq [System.Diagnostics.ProcessWindowStyle]::Minimized)
            {
                $startupInfo.wShowWindow = [Int16] [Win32API.User32+ShowWindowCommand]::SW_SHOWMINIMIZED
            }
            else
            {
                $startupInfo.wShowWindow = [Int16] [Win32API.User32+ShowWindowCommand]::SW_SHOWNORMAL
            }

            [Win32API.UserEnv+PROFILEINFO] $profile = (New-Object Win32API.UserEnv+PROFILEINFO)
            [IntPtr] $env = [IntPtr]::Zero
            [Win32API.Kernel32+PROCESS_INFORMATION] $processInfo = (New-Object Win32API.Kernel32+PROCESS_INFORMATION)
            try
            {
                # load the profile if necessary
                if ($LoadUserProfile)
                {
                    $profile = [Win32API.UserEnv]::LoadUserProfile($token, $Credential.UserName)
                }
                if ($UseNewEnvironment)
                {
                    $env = [Win32API.UserEnv]::CreateEnvironmentBlock($token, $true)
                }

                [Win32API.AdvApi32]::ImpersonateLoggedOnUser($token)


                $flags = [Win32API.Kernel32+CreateProcessFlags]::CREATE_UNICODE_ENVIRONMENT

                if (!$NoNewWindow)
                {
                    $flags += [Win32API.Kernel32+CreateProcessFlags]::CREATE_NEW_CONSOLE
                }

                $commandLine = "`"${resolvedFilePath}`" " + ($ArgumentList -join " ")

                $processInfo = [Win32API.AdvApi32]::CreateProcessAsUser(
                    $token,
                    $resolvedFilePath,
                    $commandLine,
                    [IntPtr]::Zero,
                    [IntPtr]::Zero,
                    $true,
                    $flags,
                    $env,
                    $_workingDirectory,
                    [ref] $startupInfo
                )
                $info = (New-Object StartProcessAsUser.Process $processinfo.hProcess)
                $ok = $false
                try
                {
                    if ($Wait)
                    {
                        $info.WaitForExit()
                    }
                    $ok = $true
                    if ($PassThru)
                    {
                        $info
                    }
                }
                finally
                {
                    if (!$ok)
                    {
                        $info.Dispose()
                    }
                }
            }
            finally
            {
                if ($profile -ne [IntPtr]::Zero)
                {
                    [Win32API.UserEnv]::UnLoadUserProfile($token, [ref] $profile)
                }
                if ($env -ne [IntPtr]::Zero)
                {
                    [Win32API.UserEnv]::DestroyEnvironmentBlock($env)
                }
                if ($processInfo.hThread -ne [IntPtr]::Zero)
                {
                    [Win32API.Kernel32]::CloseHandle($processInfo.hThread)
                }
            }
        }
        finally
        {
            [Win32API.Kernel32]::CloseHandle($token)
        }
    }
}
Export-ModuleMember -Function Start-ProcessAsUser -Cmdlet Start-ProcessAsUser
# vim: sts=4 sw=4 ts=4 et ai
