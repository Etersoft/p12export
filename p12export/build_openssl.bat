:call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.Cmd" /x86 /xp /Release
:call "C:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\bin\vcvars32.bat" /x86 /xp /Release
:set NO_WARN=-D_X86_ -D__i386__ -Dinline=__inline -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_CRT_OBSOLETE_NO_WARNINGS
: -Wp64

call "C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.Cmd" /x86 /xp /Release
set NO_WARN=-D__WINESRC__ -D_X86_ -D__i386__ -Dinline=__inline -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -D_CRT_OBSOLETE_NO_WARNINGS

PATH=D:\Strawberry\perl\bin;%PATH%
:cd openssl
cd openssl_1_1_1d
perl configure VC-WIN32
nmake
