#ifndef AppVersion
  #define AppVersion "1.4.0"
#endif

[Setup]
AppId={{9C3A6D4E-2F81-4B5A-A917-48E0D5C72A31}
AppName=DeepLister
AppVersion={#AppVersion}
AppPublisher=yunhyok
AppPublisherURL=https://github.com/yunhyok/deep-lister
AppSupportURL=https://github.com/yunhyok/deep-lister/issues
DefaultDirName={autopf}\DeepLister
DisableDirPage=no
DefaultGroupName=DeepLister
DisableProgramGroupPage=yes
OutputDir=..\installer
OutputBaseFilename=DeepListerSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\deeplister\assets\app.ico
UninstallDisplayIcon={app}\DeepLister.exe
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=..\LICENSE

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Languages]
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\DeepLister\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\DeepLister"; Filename: "{app}\DeepLister.exe"; AppUserModelID: "yunhyok.DeepLister"
Name: "{commondesktop}\DeepLister"; Filename: "{app}\DeepLister.exe"; AppUserModelID: "yunhyok.DeepLister"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Run]
Filename: "{app}\DeepLister.exe"; Description: "{cm:LaunchProgram,DeepLister}"; Flags: nowait postinstall skipifsilent
