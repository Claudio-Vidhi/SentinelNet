; SentinelNet Windows installer (Inno Setup 6).
;
; The problem this solves: DATA_DIR falls back to <cwd>/data, so an exe run
; straight out of a folder keeps secret.key, the databases and every config
; backup right next to itself. Updating by replacing that folder destroys the
; lot -- and losing secret.key makes every stored device password permanently
; undecryptable (see core/data_config.py, _migrate_legacy_files).
;
; So: the program goes under Program Files and is replaced on every upgrade,
; while the data lives in {commonappdata}\SentinelNet, which this script never
; writes to and never removes. An upgrade cannot touch it, and neither can an
; uninstall.
;
; Build with scripts/build_installer.ps1 -- it passes AppVersion from
; core/version.py so the installer version cannot drift from the app's.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName      "SentinelNet"
#define AppPublisher "SentinelNet"
#define AppExeName   "SentinelNet.exe"
#define DataDirName  "SentinelNet"

[Setup]
; Fixed AppId: this is what makes Inno recognise a later run as an UPGRADE of
; this product rather than a second installation. Never change it.
AppId={{751121BA-7F99-4EAC-8219-2F3DBF584298}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppSupportURL=https://github.com/Claudio-Vidhi/SentinelNet
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=SentinelNet-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Per-machine install: the data directory is shared, and a service or another
; operator account must be able to read it.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
; We write SENTINELNET_DATA_DIR to the machine environment; this makes Setup
; broadcast WM_SETTINGCHANGE so already-open shells pick it up.
ChangesEnvironment=yes
VersionInfoVersion={#AppVersion}

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Created if missing, left completely alone when it already exists. It is NOT
; listed in [Files] or [UninstallDelete] precisely so that no upgrade path can
; overwrite it. uninsneveruninstall keeps it after an uninstall too.
Name: "{commonappdata}\{#DataDirName}"; Flags: uninsneveruninstall

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{group}\SentinelNet data folder"; Filename: "{commonappdata}\{#DataDirName}"

[Registry]
; Machine-wide so the app finds its data however it is launched -- shortcut,
; command line, or a Windows service running as another account.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "SENTINELNET_DATA_DIR"; ValueData: "{commonappdata}\{#DataDirName}"; Flags: preservestringtype uninsdeletevalue

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
var
  // Two pages, not one. A TInputDirWizardPage validates its box before any of
  // our code runs, so an empty box -- the "no thanks, start fresh" answer --
  // aborts Setup with "a full path must be entered" instead of continuing.
  // The choice therefore lives on a radio page, and the directory page is only
  // reached by someone who has already said they have a folder to import.
  ChoicePage: TInputOptionWizardPage;
  ImportPage: TInputDirWizardPage;

function DataDir: String;
begin
  Result := ExpandConstant('{commonappdata}\{#DataDirName}');
end;

// An install is "fresh" when no key has ever been written. secret.key is the
// right marker: it is created on first run and is the one file whose loss is
// unrecoverable.
function IsFreshInstall: Boolean;
begin
  Result := not FileExists(DataDir + '\secret.key');
end;

function WantsImport: Boolean;
begin
  Result := Assigned(ChoicePage) and ChoicePage.Values[1];
end;

// The exe is a PyInstaller one-file bootloader: it spawns a CHILD process, and
// killing only the parent leaves the child holding a lock on the file we are
// about to replace. Kill the tree. Same lesson as scripts/build.ps1.
procedure StopRunningApp;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM {#AppExeName} /T /F', '',
       SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure InitializeWizard;
begin
  ChoicePage := CreateInputOptionPage(wpSelectDir,
    'Existing SentinelNet data',
    'Is there data from an earlier copy to bring across?',
    'If you have been running SentinelNet.exe straight from a folder, its data sits in the "data" folder next to that exe: inventory, credentials and the encryption key.',
    True, False);
  ChoicePage.Add('Start fresh. This machine has no SentinelNet data yet.');
  ChoicePage.Add('Copy in an existing data folder.');
  ChoicePage.Values[0] := True;

  ImportPage := CreateInputDirPage(ChoicePage.ID,
    'Existing SentinelNet data',
    'Where is the folder?',
    'Pick the "data" folder from the earlier copy. Nothing is moved or deleted: it is only read, and the original is left untouched.',
    False, '');
  ImportPage.Add('Existing data folder:');
  ImportPage.Values[0] := '';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  // Only worth asking on a first install. An upgrade already has its data.
  if (PageID = ChoicePage.ID) or (PageID = ImportPage.ID) then
    Result := not IsFreshInstall;
  // And the folder question only follows from having said yes.
  if (PageID = ImportPage.ID) and (not Result) then
    Result := not WantsImport;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Src: String;
begin
  Result := True;
  if CurPageID <> ImportPage.ID then
    Exit;
  Src := Trim(ImportPage.Values[0]);
  if not DirExists(Src) then
  begin
    MsgBox('That folder does not exist:' + #13#10 + Src, mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if not FileExists(Src + '\secret.key') then
    Result := MsgBox('No secret.key in that folder, so it may not be a SentinelNet data directory:' + #13#10 + Src + #13#10 + #13#10 +
      'Without the original secret.key every saved device password stays encrypted and unreadable.' + #13#10 + #13#10 +
      'Use it anyway?', mbConfirmation, MB_YESNO) = IDYES;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Src: String;
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
    StopRunningApp;

  if CurStep <> ssPostInstall then
    Exit;
  if not WantsImport then
    Exit;
  Src := Trim(ImportPage.Values[0]);
  if (Src = '') or (not DirExists(Src)) then
    Exit;

  // /E recurse (incl. empty dirs), /I assume dir, /Y overwrite, /Q quiet.
  // The destination is brand new on a fresh install, so nothing is at risk;
  // the source is only ever read.
  Exec(ExpandConstant('{cmd}'),
       '/C xcopy "' + Src + '" "' + DataDir + '" /E /I /Y /Q',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if ResultCode <> 0 then
    MsgBox('Could not copy the existing data (xcopy exit code ' + IntToStr(ResultCode) + ').' + #13#10 + #13#10 +
      'Copy it by hand before starting SentinelNet:' + #13#10 +
      '  from: ' + Src + #13#10 +
      '  to:   ' + DataDir, mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    StopRunningApp;
  // Say plainly that the data is still there. An operator who wants it gone
  // has to delete it deliberately: this folder holds the credentials for every
  // device on the network, and a silent wipe is not a thing an uninstaller
  // should do on its own.
  if CurUninstallStep = usPostUninstall then
    MsgBox('SentinelNet has been removed.' + #13#10 + #13#10 +
      'Your data has been KEPT:' + #13#10 +
      '  ' + DataDir + #13#10 + #13#10 +
      'It holds the inventory, the config backups and the encryption key. Delete that folder by hand if you really want it gone.', mbInformation, MB_OK);
end;
