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

[CustomMessages]
en.SvcGroup=Windows service:
en.SvcTask=Run SentinelNet as a Windows service (starts at boot)
en.SvcInstalling=Registering the Windows service...
en.SvcStarting=Starting the SentinelNet service...
it.SvcGroup=Servizio Windows:
it.SvcTask=Esegui SentinelNet come servizio Windows (parte all'avvio)
it.SvcInstalling=Registrazione del servizio Windows...
it.SvcStarting=Avvio del servizio SentinelNet...

en.FwOpening=Opening the firewall for the ingest ports...
it.FwOpening=Apertura del firewall per le porte di ingest...
en.FwFailed=Could not create the firewall rules for these ports:%n%1%nSentinelNet will still listen on them, but Windows drops the incoming datagrams and no logs arrive. Create the inbound UDP rules by hand, or re-run Setup as administrator.
it.FwFailed=Non e' stato possibile creare le regole firewall per queste porte:%n%1%nSentinelNet restera' comunque in ascolto, ma Windows scarta i datagrammi in ingresso e non arriva alcun log. Crea a mano le regole UDP in ingresso, oppure riesegui l'installazione come amministratore.

en.UninstAskData=Do you also want to DELETE SentinelNet's data?%n%n  %1%n%nThat folder holds the device inventory, every configuration backup, the accounts and the encryption key protecting the stored credentials.%n%nChoose No to keep it. Keeping it is what an upgrade needs.
it.UninstAskData=Vuoi ELIMINARE anche i dati di SentinelNet?%n%n  %1%n%nQuella cartella contiene l'inventario degli apparati, tutti i backup di configurazione, gli account e la chiave di cifratura che protegge le credenziali salvate.%n%nScegli No per conservarla. Conservarla e' cio' che serve a un aggiornamento.
en.UninstConfirmData=Last confirmation.%n%nDeleting is IRREVERSIBLE: the configuration backups and the encryption key cannot be recovered, and without that key the saved credentials stay unreadable even from a copy.%n%nDelete %1 for good?
it.UninstConfirmData=Ultima conferma.%n%nL'eliminazione e' IRREVERSIBILE: i backup di configurazione e la chiave di cifratura non sono recuperabili, e senza quella chiave le credenziali salvate restano illeggibili anche da una copia.%n%nEliminare definitivamente %1?
en.UninstDataKept=SentinelNet has been removed.%n%nYour data has been KEPT:%n  %1%n%nIt holds the inventory, the config backups and the encryption key. Delete that folder by hand if you really want it gone.
it.UninstDataKept=SentinelNet e' stato rimosso.%n%nI tuoi dati sono stati CONSERVATI:%n  %1%n%nContengono l'inventario, i backup di configurazione e la chiave di cifratura. Elimina la cartella a mano se vuoi davvero liberartene.
en.UninstDataGone=SentinelNet and its data have been removed.
it.UninstDataGone=SentinelNet e i suoi dati sono stati rimossi.
en.UninstDataPartial=SentinelNet has been removed, but some files could not be deleted (something may still be holding them):%n  %1%n%nDelete the folder by hand once no process is using it.
it.UninstDataPartial=SentinelNet e' stato rimosso, ma alcuni file non sono stati eliminati (qualcosa potrebbe tenerli aperti):%n  %1%n%nElimina la cartella a mano quando nessun processo la sta usando.

[Files]
; onedir: PyInstaller emette dist\SentinelNet\ con l'exe piu' _internal\ e le
; DLL. L'exe resta comunque in {app}, quindi collegamenti, icona di
; disinstallazione e taskkill qui sotto non cambiano.
Source: "..\dist\SentinelNet\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
; WinSW wrapper: a PyInstaller exe is not a service (it never reports to
; the SCM), so something has to stand between it and Windows. Downloaded
; with a pinned hash by scripts/build_installer.ps1, not versioned.
Source: "vendor\WinSW.exe"; DestDir: "{app}"; DestName: "SentinelNet-service.exe"; Flags: ignoreversion; Tasks: service
Source: "{tmp}\SentinelNet-service-resolved.xml"; DestDir: "{app}"; DestName: "SentinelNet-service.xml"; Flags: ignoreversion external; Tasks: service
; The template travels inside Setup and is never installed as-is: it is
; extracted on demand, the paths are substituted, and the RESULT is what
; the line above copies.
Source: "SentinelNet-service.xml"; Flags: dontcopy

[Dirs]
; Created if missing, left completely alone when it already exists. It is NOT
; listed in [Files] or [UninstallDelete] precisely so that no upgrade path can
; overwrite it. uninsneveruninstall keeps it after an uninstall too.
Name: "{commonappdata}\{#DataDirName}"; Flags: uninsneveruninstall

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
; Off by default: registering a service is a machine-wide change, and a
; desktop install does not need one. Ticking it also makes the Restart
; button in the panel work, because supervisor() then finds something
; that would bring the process back.
Name: "service"; Description: "{cm:SvcTask}"; GroupDescription: "{cm:SvcGroup}"; Flags: unchecked

[Icons]
; WorkingDir is the DATA directory, never {app}. Launched from a shortcut the
; process inherits the exe's folder as CWD, which under Program Files is not
; writable by a normal user: anything resolving a relative path there dies with
; WinError 5 before the server is up. Pointing it at the data directory means a
; relative path lands somewhere writable instead of crashing.
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{commonappdata}\{#DataDirName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{group}\SentinelNet data folder"; Filename: "{commonappdata}\{#DataDirName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{commonappdata}\{#DataDirName}"; Tasks: desktopicon

[Registry]
; Machine-wide so the app finds its data however it is launched -- shortcut,
; command line, or a Windows service running as another account.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "SENTINELNET_DATA_DIR"; ValueData: "{commonappdata}\{#DataDirName}"; Flags: preservestringtype uninsdeletevalue

[Run]
; La registrazione del servizio NON sta qui: [Run] ignora il codice di uscita,
; quindi un "install" fallito passerebbe in silenzio e l'utente scoprirebbe da
; solo, piu' tardi, che il servizio non c'e'. La fa InstallService() in [Code],
; che il codice lo guarda.
; Only offered when NOT running as a service: with the service up the
; port is already taken, and a second copy would just open the browser.
Filename: "{app}\{#AppExeName}"; WorkingDir: "{commonappdata}\{#DataDirName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent; Tasks: not service

[UninstallRun]
; Stop and deregister BEFORE the files go: uninstalling the exe out from
; under a registered service leaves a broken entry in services.msc that
; only a reboot clears. RunOnceId keeps each step to a single run.
Filename: "{app}\SentinelNet-service.exe"; Parameters: "stop"; RunOnceId: "SvcStop"; Flags: runhidden waituntilterminated; Check: ServiceInstalled
Filename: "{app}\SentinelNet-service.exe"; Parameters: "uninstall"; RunOnceId: "SvcUninstall"; Flags: runhidden waituntilterminated; Check: ServiceInstalled

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

// WinSW reads its configuration from a file next to itself; the one in the
// repository is a template carrying {app} and {commonappdata}. Writing it here,
// rather than shipping it literally, is what puts the real paths in it -- and
// the file has to exist before [Files] copies it, hence PrepareToInstall.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Xml: AnsiString;
  Text: String;
begin
  Result := '';
  if not WizardIsTaskSelected('service') then
    Exit;
  ExtractTemporaryFile('SentinelNet-service.xml');
  if not LoadStringFromFile(ExpandConstant('{tmp}\SentinelNet-service.xml'), Xml) then
  begin
    Result := 'The service template could not be read.';
    Exit;
  end;
  Text := String(Xml);
  StringChangeEx(Text, '{app}', ExpandConstant('{app}'), True);
  StringChangeEx(Text, '{commonappdata}', DataDir, True);
  if not SaveStringToFile(ExpandConstant('{tmp}\SentinelNet-service-resolved.xml'), Text, False) then
    Result := 'The service configuration could not be written.';
end;

// Only touch the service on uninstall if it is actually registered: calling
// "stop" on a missing service returns an error and would make the uninstaller
// look broken to someone who never ticked the box.
// Registra e avvia il servizio guardando il codice di uscita di WinSW. Un
// fallimento va detto adesso, con Setup ancora a schermo: e' l'unico momento
// in cui l'utente sa ancora cosa ha appena fatto.
// Il servizio risulta gia' registrato? Si guarda il registro dei servizi,
// non la presenza del file: dopo un aggiornamento il file c'e' sempre.
function AlreadyRegistered: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\SentinelNet');
end;

procedure InstallService;
var
  Exe, LogDir: String;
  Code: Integer;
begin
  Exe := ExpandConstant('{app}\SentinelNet-service.exe');
  LogDir := DataDir + '\logs';
  // Su un aggiornamento il servizio c'e' gia' e "install" fallirebbe: si
  // reinstalla solo se manca, e in ogni caso si riparte alla fine.
  if AlreadyRegistered then
  begin
    if not Exec(Exe, 'start', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
      MsgBox('The service did not start again after the update (exit code '
        + IntToStr(Code) + ').' + #13#10 + #13#10
        + 'Start it from services.msc, or look at the log:' + #13#10
        + '  ' + LogDir, mbError, MB_OK);
    Exit;
  end;
  if not Exec(Exe, 'install', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
  begin
    // NON si indovina la causa. La prima versione di questo messaggio diceva
    // "servono privilegi", e il problema era un XML malformato: ha mandato
    // chi lo leggeva a cercare dalla parte sbagliata. Il comando qui sotto
    // stampa l'errore vero.
    MsgBox('The Windows service could not be registered (exit code '
      + IntToStr(Code) + ').' + #13#10 + #13#10
      + 'SentinelNet is installed and works from the shortcut; only the '
      + 'service, and with it the Restart button in the panel, are missing.'
      + #13#10 + #13#10
      + 'Run this to see the actual error, then retry:' + #13#10
      + '  "' + Exe + '" install', mbError, MB_OK);
    Exit;
  end;
  if not Exec(Exe, 'start', '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    MsgBox('The service is registered but did not start (exit code '
      + IntToStr(Code) + ').' + #13#10 + #13#10
      + 'Look at the log, then start it from services.msc:' + #13#10
      + '  ' + LogDir, mbError, MB_OK);
end;

function ServiceInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\SentinelNet-service.exe'));
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
  Svc: String;
begin
  // Se c'e' il servizio va fermato PRIMA, e per bene: un taskkill secco lo
  // farebbe ripartire da solo (onfailure restart nell'XML) proprio mentre si
  // sostituisce l'eseguibile. Questo e' il percorso dell'aggiornamento
  // silenzioso, dove non c'e' nessuno a guardare.
  Svc := ExpandConstant('{app}\SentinelNet-service.exe');
  if FileExists(Svc) then
    Exec(Svc, 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  // E comunque il taskkill, per un'istanza avviata a mano dall'icona: l'exe
  // e' un bootloader PyInstaller che genera un processo FIGLIO, e fermare
  // solo il padre lascia il figlio a tenere il file bloccato.
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

// Le porte di ingest UDP e le rispettive regole firewall. Senza queste,
// l'apparato manda i log, il socket risulta in ascolto e Windows scarta i
// datagrammi in silenzio: dall'interno dell'applicazione e' indistinguibile da
// un apparato che non sta mandando niente, ed e' il motivo per cui "syslog non
// funziona" e' la prima cosa che si rompe dopo un'installazione.
// Le regole valgono per PORTA e non per programma: l'eseguibile e' un
// bootloader PyInstaller e la porta la tiene comunque un processo solo.
procedure FirewallPorts(var Names: TArrayOfString; var Ports: TArrayOfInteger);
begin
  SetArrayLength(Names, 4);
  SetArrayLength(Ports, 4);
  Names[0] := 'syslog';  Ports[0] := 514;
  Names[1] := 'NetFlow'; Ports[1] := 2055;
  Names[2] := 'IPFIX';   Ports[2] := 4739;
  Names[3] := 'sFlow';   Ports[3] := 6343;
end;

function FirewallRuleName(Name: String; Port: Integer): String;
begin
  Result := 'SentinelNet ' + Name + ' (UDP ' + IntToStr(Port) + ')';
end;

procedure AddFirewallRules;
var
  Names: TArrayOfString;
  Ports: TArrayOfInteger;
  I, ResultCode: Integer;
  Failed: String;
begin
  FirewallPorts(Names, Ports);
  for I := 0 to GetArrayLength(Ports) - 1 do
  begin
    // delete prima di add: rieseguire il setup non deve lasciare regole
    // doppie con lo stesso nome.
    Exec(ExpandConstant('{sys}\netsh.exe'),
         'advfirewall firewall delete rule name="' + FirewallRuleName(Names[I], Ports[I]) + '"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if not Exec(ExpandConstant('{sys}\netsh.exe'),
         'advfirewall firewall add rule name="' + FirewallRuleName(Names[I], Ports[I]) + '"' +
         ' dir=in action=allow protocol=UDP localport=' + IntToStr(Ports[I]) +
         ' profile=any', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      ResultCode := -1;
    if ResultCode <> 0 then
      Failed := Failed + '  UDP ' + IntToStr(Ports[I]) + ' (' + Names[I] + ')' + #13#10;
  end;
  if Failed <> '' then
    MsgBox(FmtMessage(CustomMessage('FwFailed'), [Failed]), mbError, MB_OK);
end;

procedure RemoveFirewallRules;
var
  Names: TArrayOfString;
  Ports: TArrayOfInteger;
  I, ResultCode: Integer;
begin
  FirewallPorts(Names, Ports);
  for I := 0 to GetArrayLength(Ports) - 1 do
    Exec(ExpandConstant('{sys}\netsh.exe'),
         'advfirewall firewall delete rule name="' + FirewallRuleName(Names[I], Ports[I]) + '"',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Rompe l'ereditarieta' sulla cartella dati. Sotto ProgramData l'ACL ereditata
// concede BUILTIN\Users lettura, e li' dentro sta secret.key: la chiave con cui
// si decifra ogni password di apparato. L'applicazione irrigidisce i singoli
// file, ma partire da una cartella gia' chiusa significa che un file nuovo non
// nasce mai leggibile, nemmeno per l'istante fra creazione e icacls.
// SID noti e non nomi di gruppo: su Windows localizzato "Users" non si chiama
// "Users".
// SOLO in modalita' servizio: li' la cartella la usa LocalSystem e basta. In
// installazione desktop l'applicazione gira come l'utente interattivo, che con
// un token non elevato NON ha i diritti di Administrators e resterebbe fuori
// dai propri dati.
procedure HardenDataDir;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\icacls.exe'),
       '"' + DataDir + '" /inheritance:r' +
       ' /grant:r *S-1-5-18:(OI)(CI)F' +
       ' /grant:r *S-1-5-32-544:(OI)(CI)F',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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

  WizardForm.StatusLabel.Caption := CustomMessage('FwOpening');
  AddFirewallRules;

  // Anche senza il task selezionato: un aggiornamento silenzioso deve
  // rimettere in moto un servizio che esisteva gia'.
  if WizardIsTaskSelected('service') or AlreadyRegistered then
  begin
    HardenDataDir;
    InstallService;
  end;

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
  begin
    StopRunningApp;
    RemoveFirewallRules;
  end;

  if CurUninstallStep <> usPostUninstall then
    Exit;

  if not DirExists(DataDir) then
    Exit;

  // Si CHIEDE, non si decide. La cartella contiene le credenziali di ogni
  // apparato della rete e i backup di configurazione: cancellarla in silenzio
  // non e' cosa che un disinstallatore possa fare da solo, e conservarla e'
  // anche cio' che serve a un aggiornamento.
  // MB_DEFBUTTON2 mette il fuoco su No, e in disinstallazione /VERYSILENT la
  // MsgBox non compare e vale la risposta predefinita: i dati restano.
  if MsgBox(FmtMessage(CustomMessage('UninstAskData'), [DataDir]),
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then
  begin
    MsgBox(FmtMessage(CustomMessage('UninstDataKept'), [DataDir]), mbInformation, MB_OK);
    Exit;
  end;

  // Seconda conferma, e non e' un eccesso di zelo: l'operazione non ha un
  // annullamento. Persa la chiave, nemmeno una copia dei file serve piu' a
  // niente, perche' le credenziali salvate restano cifrate per sempre.
  if MsgBox(FmtMessage(CustomMessage('UninstConfirmData'), [DataDir]),
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) <> IDYES then
  begin
    MsgBox(FmtMessage(CustomMessage('UninstDataKept'), [DataDir]), mbInformation, MB_OK);
    Exit;
  end;

  DelTree(DataDir, True, True, True);
  if DirExists(DataDir) then
    MsgBox(FmtMessage(CustomMessage('UninstDataPartial'), [DataDir]), mbError, MB_OK)
  else
    MsgBox(CustomMessage('UninstDataGone'), mbInformation, MB_OK);
end;
