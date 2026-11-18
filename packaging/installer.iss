; Inno Setup script for LogLens (https://jrsoftware.org/isinfo.php).
; Built by tools\build.py, which passes /DAppVersion=<version>; it expects dist\LogLens\ (PyInstaller output)
; and build\loglens.ico. Installs per user by default (no admin prompt); the user can choose "for all users".

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "LogLens"
#define AppExe "LogLens.exe"

[Setup]
AppId={{6F4C1B2A-3E57-4C1D-9B8E-6A2D5C7E9F10}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=LogLens-{#AppVersion}-setup
SetupIconFile=..\build\loglens.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesAssociations=yes
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: unchecked
Name: "openwith"; Description: "Add ""Open with LogLens"" to the Explorer right-click menu"
Name: "assoclog"; Description: "Open .log files with LogLens by default"; Flags: unchecked
Name: "assocevtx"; Description: "Open .evtx event log files with LogLens by default"; Flags: unchecked

[Files]
Source: "..\dist\LogLens\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; ProgIDs used by the associations below.
Root: HKA; Subkey: "Software\Classes\LogLens.LogFile"; ValueType: string; ValueData: "Log file"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\LogLens.LogFile\DefaultIcon"; ValueType: string; ValueData: "{app}\{#AppExe},0"
Root: HKA; Subkey: "Software\Classes\LogLens.LogFile\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""
Root: HKA; Subkey: "Software\Classes\LogLens.EventLogFile"; ValueType: string; ValueData: "Windows event log"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\LogLens.EventLogFile\DefaultIcon"; ValueType: string; ValueData: "{app}\{#AppExe},0"
Root: HKA; Subkey: "Software\Classes\LogLens.EventLogFile\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""
; Offer LogLens in "Open with" for common log types.
Root: HKA; Subkey: "Software\Classes\.log\OpenWithProgids"; ValueType: string; ValueName: "LogLens.LogFile"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\.txt\OpenWithProgids"; ValueType: string; ValueName: "LogLens.LogFile"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\.evtx\OpenWithProgids"; ValueType: string; ValueName: "LogLens.EventLogFile"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\Applications\{#AppExe}\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Flags: uninsdeletekey
; Optional defaults.
Root: HKA; Subkey: "Software\Classes\.log"; ValueType: string; ValueData: "LogLens.LogFile"; Flags: uninsdeletevalue; Tasks: assoclog
Root: HKA; Subkey: "Software\Classes\.evtx"; ValueType: string; ValueData: "LogLens.EventLogFile"; Flags: uninsdeletevalue; Tasks: assocevtx
; "Open with LogLens" on any file.
Root: HKA; Subkey: "Software\Classes\*\shell\LogLens"; ValueType: string; ValueData: "Open with LogLens"; Flags: uninsdeletekey; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\*\shell\LogLens"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExe},0"; Tasks: openwith
Root: HKA; Subkey: "Software\Classes\*\shell\LogLens\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: openwith

[Run]
Filename: "{app}\{#AppExe}"; Description: "Start LogLens"; Flags: nowait postinstall skipifsilent

; User data (%APPDATA%\LogLens: settings, knowledge base, exported event logs) is kept on uninstall on purpose.
