#define MyAppName "Finalis Core"
#ifndef MyAppVersion
  #define MyAppVersion "1.0.2"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\windows\payload"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\installer"
#endif

[Setup]
AppId={{EAA24893-1A6A-4E25-A528-33AB32D54C3B}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Finalis Core
AppPublisherURL=https://github.com/finalis-core/finalis-core
DefaultDirName={autopf}\Finalis Core
DefaultGroupName=Finalis Core
OutputDir={#OutputDir}
OutputBaseFilename=finalis-core_installer
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=no
UninstallDisplayIcon={app}\app\finalis-app-icon.ico
SetupIconFile={#SourceDir}\installer-assets\finalis-app.ico
WizardImageFile={#SourceDir}\installer-assets\finalis-wizard.bmp
WizardSmallImageFile={#SourceDir}\installer-assets\finalis-wizard-small.bmp

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcuts"; GroupDescription: "Additional icons:"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Finalis Wallet"; Filename: "{app}\app\bin\finalis-wallet.exe"; IconFilename: "{app}\app\finalis-app-icon.ico"; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-wallet.exe'))
Name: "{group}\Finalis Explorer"; Filename: "{app}\app\bin\finalis-explorer.exe"; Parameters: "--bind 0.0.0.0 --port 18080 --rpc-url http://127.0.0.1:19444/rpc"; IconFilename: "{app}\app\finalis-app-icon.ico"; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-explorer.exe'))
Name: "{group}\Finalis Explorer (Web)"; Filename: "http://127.0.0.1:18080"; IconFilename: "{app}\app\finalis-app-icon.ico"
Name: "{group}\Start Finalis Stack"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"""; WorkingDir: "{app}\app"; IconFilename: "{app}\app\finalis-app-icon.ico"
Name: "{group}\Finalis CLI"; Filename: "{app}\app\bin\finalis-cli.exe"; IconFilename: "{app}\app\finalis-app-icon.ico"; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-cli.exe'))
Name: "{group}\README"; Filename: "{app}\app\WINDOWS-RUN.txt"; IconFilename: "{app}\app\finalis-app-icon.ico"
Name: "{autodesktop}\Finalis Wallet"; Filename: "{app}\app\bin\finalis-wallet.exe"; IconFilename: "{app}\app\finalis-app-icon.ico"; Tasks: desktopicon; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-wallet.exe'))
Name: "{autodesktop}\Start Finalis Stack"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"""; WorkingDir: "{app}\app"; IconFilename: "{app}\app\finalis-app-icon.ico"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"" -ConfigureFirewall -NoStart"; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"""; Flags: postinstall skipifsilent
Filename: "{app}\app\bin\finalis-wallet.exe"; Description: "Launch Finalis Wallet"; Flags: postinstall nowait skipifsilent; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-wallet.exe'))
