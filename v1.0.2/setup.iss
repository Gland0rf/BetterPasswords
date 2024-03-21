#include "enviroment.iss"

[Setup]
AppName=BetterPasswords
AppVersion=1.1.0
DefaultDirName={pf}\BetterPasswords
DisableDirPage=no
DisableProgramGroupPage=no
DisableFinishedPage=no
DisableWelcomePage=no
UsePreviousAppDir=no
OutputDir=Output
DefaultGroupName=BetterPasswords
UninstallDisplayIcon={app}\BetterPasswords.exe
OutputBaseFilename=Setup
Compression=lzma2/ultra64
PrivilegesRequired=admin
ChangesEnvironment=true

[Tasks]
Name: "Cli_Support"; Description: "Install CLI Support"; Flags: unchecked

[Dirs]
Name: "{app}"
Name: "{app}\bin"
Name: "{userappdata}\BetterPasswords"

[Files]
Source: "BetterPasswords.exe"; DestDir: "{app}" 
Source: "_internal\*"; DestDir: "{app}\_internal"; Flags: recursesubdirs createallsubdirs
Source: "bin\bps.bat"; DestDir: "{app}\bin"; Flags: uninsneveruninstall;
Source: "bin\BetterPasswordsCLI.py"; DestDir: "{userappdata}\BetterPasswords"; Flags: uninsneveruninstall;

[Icons]
Name: "{group}\BetterPasswords"; Filename: "{app}\BetterPasswords.exe"; WorkingDir: "{app}"
Name: "{commonprograms}\BetterPasswords"; Filename: "{app}\BetterPasswords.exe"; WorkingDir: "{app}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
Type: filesandordirs; Name: "{userappdata}\BetterPasswords"
Type: filesandordirs; Name: "{commonprograms}\BetterPasswords"

[Run]
Filename: "{app}\BetterPasswords.exe"; Description: "Launch Password Manager"; Flags: postinstall

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if WizardIsTaskSelected('Cli_Support') then
  begin
    if CurStep = ssPostInstall then
      EnvAddPath(ExpandConstant('{app}') + '\bin');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    EnvRemovePath(ExpandConstant('{app}') + '\bin');
end;