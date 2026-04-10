#define MyAppName "Finalis Core"
#ifndef MyAppVersion
  #define MyAppVersion "0.7.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\windows\payload"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\installer"
#endif

[Setup]
AppId={{EAA24893-1A6A-4E25-A528-33AB32D54C3B}
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
UninstallDisplayIcon={app}\app\bin\finalis-wallet.exe
WizardImageFile={#SourceDir}\installer-assets\finalis-wizard.bmp
WizardSmallImageFile={#SourceDir}\installer-assets\finalis-wizard-small.bmp

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcuts"; GroupDescription: "Additional icons:"
Name: "launchstack"; Description: "Start Finalis node, lightserver, and explorer after installation"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Finalis Wallet"; Filename: "{app}\app\bin\finalis-wallet.exe"; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-wallet.exe'))
Name: "{group}\Finalis Explorer"; Filename: "{app}\app\bin\finalis-explorer.exe"; Parameters: "--bind 0.0.0.0 --port 18080 --rpc-url http://127.0.0.1:19444/rpc"; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-explorer.exe'))
Name: "{group}\Start Finalis Stack"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"""; WorkingDir: "{app}\app"
Name: "{group}\Finalis CLI"; Filename: "{app}\app\bin\finalis-cli.exe"; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-cli.exe'))
Name: "{group}\README"; Filename: "{app}\app\WINDOWS-RUN.txt"
Name: "{autodesktop}\Finalis Wallet"; Filename: "{app}\app\bin\finalis-wallet.exe"; Tasks: desktopicon; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-wallet.exe'))
Name: "{autodesktop}\Start Finalis Stack"; Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"""; WorkingDir: "{app}\app"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"" -ConfigureFirewall -NoStart"; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File ""{app}\app\scripts\Start-Finalis.ps1"""; Flags: postinstall nowait skipifsilent; Tasks: launchstack
Filename: "{app}\app\bin\finalis-wallet.exe"; Description: "Launch Finalis Wallet"; Flags: postinstall nowait skipifsilent; Check: FileExists(ExpandConstant('{app}\app\bin\finalis-wallet.exe'))
