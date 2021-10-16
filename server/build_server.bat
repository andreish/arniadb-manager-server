@echo off

REM prepare vc environment

call "%VS90COMNTOOLS%vsvars32.bat"

echo Start build cm_server ...
cd win

set arniadb_libdir=%arniadb_libdir%
set arniadb_includedir=%arniadb_includedir%

cmd /c devenv amserver.sln /project install /rebuild "%mode%|%platform%"
set exitcode=%errorlevel%
cd ..
if not "%exitcode%" == "0" exit /b %exitcode%

cd win/install
cd AMServer_%mode%_%platform%

robocopy . %prefix%\ /e
if errorlevel 1 (
	set exitcode=0
	) else (
	set exitcode=%errorlevel%
	)
cd ..\..\..

