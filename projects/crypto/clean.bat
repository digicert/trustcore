if exist "%~dp0\build" (
  rmdir /s /q "%~dp0\build"
)

if exist "%~dp0\build_bat.out" (
  del /s /q "%~dp0\build_bat.out"
)
