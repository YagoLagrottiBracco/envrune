; Inno Setup script for the EnvRune Windows installer.
; Built by the release workflow:
;   iscc /DAppVersion=<version> /DRepoDir=<repo> /DBinDir=<binaries> /DOutputDir=<out> envrune.iss
; Installs per user (no administrator prompt) and adds EnvRune to the user PATH.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{8C5E2F4A-3B1D-4E7A-9F2C-6D8B1A0E5C3F}
AppName=EnvRune
AppVersion={#AppVersion}
AppVerName=EnvRune {#AppVersion}
AppPublisher=Yago Lagrotti Bracco
AppPublisherURL=https://github.com/YagoLagrottiBracco/vault
DefaultDirName={autopf}\EnvRune
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible or arm64
ArchitecturesInstallIn64BitMode=x64compatible or arm64
ChangesEnvironment=yes
LicenseFile={#RepoDir}\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=envrune_{#AppVersion}_windows_setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=EnvRune

[Files]
Source: "{#BinDir}\envrune_amd64.exe"; DestDir: "{app}\bin"; DestName: "envrune.exe"; Check: not IsArm64; Flags: ignoreversion
Source: "{#BinDir}\envrune_arm64.exe"; DestDir: "{app}\bin"; DestName: "envrune.exe"; Check: IsArm64; Flags: ignoreversion
Source: "{#RepoDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Messages]
FinishedLabel=EnvRune is installed. Open a new terminal and run "envrune" to create your vault.

[Code]
const
  EnvKey = 'Environment';

function PathContains(Paths, Dir: string): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0;
end;

procedure AddToPath(Dir: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Paths) then
    Paths := '';
  if PathContains(Paths, Dir) then
    exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then
    Paths := Paths + ';';
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Paths + Dir);
end;

procedure RemoveFromPath(Dir: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Paths) then
    exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then
    exit;
  Delete(Paths, P, Length(Dir) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddToPath(ExpandConstant('{app}\bin'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}\bin'));
end;
