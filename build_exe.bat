@echo off
REM Builds SSH_Command_LLDP_Tool.exe from ssh_lldp_descriptor.py using
REM PyInstaller. Run this on a Windows PC that has Python 3 installed
REM (python.org or Microsoft Store). It only needs to be run once, or again
REM after editing ssh_lldp_descriptor.py.

cd /d "%~dp0"

echo Installing/updating required packages ...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo Building exe ...
python -m PyInstaller --noconfirm --onefile --windowed --name "SSH_Command_LLDP_Tool" ssh_lldp_descriptor.py

echo.
echo Done. The exe is in the "dist" folder: dist\SSH_Command_LLDP_Tool.exe
pause
