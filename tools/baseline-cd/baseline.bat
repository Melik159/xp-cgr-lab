@echo off

mkdir C:\CGRLAB
mkdir C:\CGRLAB\baseline

ver > C:\CGRLAB\baseline\ver.txt
hostname > C:\CGRLAB\baseline\hostname.txt
systeminfo > C:\CGRLAB\baseline\systeminfo.txt

wmic os get Caption,Version,BuildNumber,CSDVersion,InstallDate /format:list > C:\CGRLAB\baseline\os.txt
wmic computersystem get Name,Manufacturer,Model,TotalPhysicalMemory /format:list > C:\CGRLAB\baseline\computer.txt

net user > C:\CGRLAB\baseline\users.txt
net localgroup Administrateurs > C:\CGRLAB\baseline\administrators.txt

wmic useraccount get Name,SID,Disabled,LocalAccount /format:table > C:\CGRLAB\baseline\sids.txt

wmic diskdrive get Index,Model,Size,InterfaceType /format:table > C:\CGRLAB\baseline\diskdrives.txt
wmic logicaldisk get DeviceID,FileSystem,Size,FreeSpace,VolumeName /format:table > C:\CGRLAB\baseline\logicaldisks.txt

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" > C:\CGRLAB\baseline\windows_version_registry.txt

dir C:\ /a > C:\CGRLAB\baseline\root_directory.txt

wmic datafile where name="C:\\WINDOWS\\system32\\advapi32.dll" get Name,Version,FileSize /format:list > C:\CGRLAB\baseline\advapi32.txt
wmic datafile where name="C:\\WINDOWS\\system32\\rsaenh.dll" get Name,Version,FileSize /format:list > C:\CGRLAB\baseline\rsaenh.txt
wmic datafile where name="C:\\WINDOWS\\system32\\ntdll.dll" get Name,Version,FileSize /format:list > C:\CGRLAB\baseline\ntdll.txt
wmic datafile where name="C:\\WINDOWS\\system32\\crypt32.dll" get Name,Version,FileSize /format:list > C:\CGRLAB\baseline\crypt32.txt

dir C:\pagefile.sys /a > C:\CGRLAB\baseline\pagefile.txt 2>&1
dir C:\hiberfil.sys /a > C:\CGRLAB\baseline\hiberfil.txt 2>&1

echo BASELINE COMPLETE
pause
