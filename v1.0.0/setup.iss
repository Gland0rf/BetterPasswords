[Setup]
AppName=BetterPasswords
AppVersion=1.0
DefaultDirName={pf}\BetterPasswords
OutputDir=Output
DefaultGroupName=BetterPasswords
UninstallDisplayIcon={app}\BetterPasswords.exe
OutputBaseFilename=Setup
Compression=lzma2/ultra64
PrivilegesRequired=admin

[Files]
Source: "BetterPasswords.exe"; DestDir: "{app}"
Source: "_internal\*"; DestDir: "{app}\_internal"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\BetterPasswords"; Filename: "{app}\BetterPasswords.exe"; WorkingDir: "{app}"
Name: "{commonprograms}\BetterPasswords"; Filename: "{app}\BetterPasswords.exe"; WorkingDir: "{app}"

[Run]
Filename: "{app}\BetterPasswords.exe"; Description: "Launch Password Manager"; Flags: postinstall nowait

[Code]
function InitializeSetup: Boolean;
begin
    Result := True;
end;