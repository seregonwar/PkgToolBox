; Sample script for Anthem Setup
[Setup]
; Name of the application
AppName=PS4 PKG Tool
; Version of the application
AppVersion=1.0
; Default destination directory
DefaultDirName={pf}\PS4 PKG Tool.
; Name of the output file of the installer.
OutputDir=.
OutputBaseFilename=ps4_pkg_tool_setup
; Icon of the installer
SetupIconFile=icons\toolbox-png.ico  
; Setup type
DefaultGroupName=PS4 PKG Tool

[Files]
; Add all necessary files for the application
Source: “dist\*” ; DestDir: “{app}” ; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Create an icon on the desktop
Name: “{commondesktop}\PS4 PKG Tool”; Filename: “{app}\ps4_pkg_tool.exe”
; Creates an icon in the Start menu
Name: “{group}\PS4 PKG Tool”; Filename: “{app}\ps4_pkg_tool.exe”

[Run]
; Run the application after the installation is complete
Filename: “{app}\ps4_pkg_tool.exe”; Description: “{cm:LaunchProgram,PS4 PKG Tool}”; Flags: nowait postinstall skipifsilent