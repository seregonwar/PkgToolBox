; Inno Setup Script per PkgToolBox
; Questo script crea un installer per l'applicazione PkgToolBox

[Setup]
AppName=PkgToolBox
AppVersion=1.0.0
AppPublisher=Seregonwar
AppPublisherURL=https://github.com/Seregonwar
AppSupportURL=https://github.com/Seregonwar/PkgToolBox
AppUpdatesURL=https://github.com/Seregonwar/PkgToolBox
DefaultDirName={autopf}\PkgToolBox
DefaultGroupName=PkgToolBox
AllowNoIcons=yes
LicenseFile=
OutputDir=installer_output
OutputBaseFilename=PkgToolBox_Setup
SetupIconFile=icons\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Immagini per l'installer
WizardImageFile=installer_assets\welcome.bmp
WizardSmallImageFile=installer_assets\logo.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1

[Files]
; File principale eseguibile
Source: "dist\PkgToolBox\PkgToolBox.exe"; DestDir: "{app}"; Flags: ignoreversion

; Directory _internal con tutte le dipendenze
Source: "dist\PkgToolBox\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs

; Directory PS4PKGToolTemp
Source: "dist\PS4PKGToolTemp\*"; DestDir: "{app}\PS4PKGToolTemp"; Flags: ignoreversion recursesubdirs createallsubdirs

; File di configurazione
Source: "settings.json"; DestDir: "{app}"; Flags: ignoreversion

; Documentazione
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "CHANGELOG.md"; DestDir: "{app}"; Flags: ignoreversion

; Icone
Source: "icons\*"; DestDir: "{app}\icons"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\PkgToolBox"; Filename: "{app}\PkgToolBox.exe"; IconFilename: "{app}\icons\icon.ico"
Name: "{group}\{cm:UninstallProgram,PkgToolBox}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\PkgToolBox"; Filename: "{app}\PkgToolBox.exe"; IconFilename: "{app}\icons\icon.ico"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\PkgToolBox"; Filename: "{app}\PkgToolBox.exe"; IconFilename: "{app}\icons\icon.ico"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\PkgToolBox.exe"; Description: "{cm:LaunchProgram,PkgToolBox}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\PS4PKGToolTemp"
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\settings.json"

[Code]
// Funzione per verificare se .NET Framework è installato (se necessario)
function IsDotNetDetected(version: string; service: cardinal): boolean;
// Placeholder per eventuali controlli di prerequisiti
begin
  Result := true;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
end;