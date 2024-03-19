[Setup]
AppName=BetterPasswords
AppVersion=1.0.1
DefaultDirName={pf}\BetterPasswords
OutputDir=Output
DefaultGroupName=BetterPasswords
UninstallDisplayIcon={app}\BetterPasswords.exe
OutputBaseFilename=Setup
Compression=lzma2/ultra64
PrivilegesRequired=admin

[Dirs]
Name: "{app}"

[Files]
Source: "BetterPasswords.exe"; DestDir: "{app}" 
Source: "_internal\*"; DestDir: "{app}\_internal"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\BetterPasswords"; Filename: "{app}\BetterPasswords.exe"; WorkingDir: "{app}"
Name: "{commonprograms}\BetterPasswords"; Filename: "{app}\BetterPasswords.exe"; WorkingDir: "{app}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
Type: filesandordirs; Name: "{userappdata}\BetterPasswords"
Type: filesandordirs; Name: "{commonprograms}\BetterPasswords"

[Run]
Filename: "{app}\BetterPasswords.exe"; Description: "Launch Password Manager"; Flags: postinstall nowait