@{
RootModule = 'Start-ProcessAsUser.psm1'
ModuleVersion = '0.1.3'
GUID = 'ffee40f3-cf73-421f-b0b5-db66ef2cb0bb'
Author = 'Moriyoshi Koizumi'
Copyright = '(c) Moriyoshi Koizumi. All rights reserved.'
Description = 'A Start-Process alternative which uses CreateProcessAsUser() for elevated execution of a child process.'
PowerShellVersion = '3.0'
DotNetFrameworkVersion = '4.0'
CLRVersion = '4.0'
AliasesToExport = @()
FunctionsToExport = @('Start-ProcessAsUser')
CmdletsToExport = @('Start-ProcessAsUser')
HelpInfoURI = 'https://github.com/moriyoshi/PS-Start-ProcessAsUser/'
}
