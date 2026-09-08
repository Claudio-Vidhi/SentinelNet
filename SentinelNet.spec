# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['app_server.py'],
    pathex=[],
    binaries=[],
    # 'data' NON va impacchettata: conteneva secret.key (la chiave Fernet di
    # ogni credenziale salvata), jwt_secret.key (con cui si forgia un token di
    # amministratore), i database con la rete del cliente e i backup di
    # configurazione. Nessuno di quei file veniva nemmeno letto dal bundle:
    # data_config.get_path() risolve su SENTINELNET_DATA_DIR o cwd/data, mai su
    # _MEIPASS, che serve solo a templates/, static/ e schema.sql. Al primo
    # avvio la cartella viene creata vuota e parte il wizard di setup.
    # drivers/ NON serve come 'data': nessun caricamento dinamico (grep
    # importlib), li importa staticamente drivers/registry.py via
    # core_engine, quindi PyInstaller li include gia' compilati.
    datas=[('templates', 'templates'), ('static', 'static'),
           ('observability/storage/schema.sql', 'observability/storage')],
    # pysnmp risolve i moduli di protocollo per nome a runtime: senza questi
    # l'exe importa la libreria ma fallisce al primo GET.
    hiddenimports=[
        'pysnmp.smi.mibs',
        # 'pysnmp.proto.acmod.rfc3412' non esiste piu' nella pysnmp installata:
        # la build lo segnalava come ERROR a ogni giro. Gli altri sette
        # risolvono, verificati con importlib prima di togliere questo.
        'pysnmp.proto.mpmod.rfc2576',
        'pysnmp.proto.mpmod.rfc3412',
        'pysnmp.proto.secmod.rfc2576',
        'pysnmp.proto.secmod.rfc3414',
        'pysnmp.proto.secmod.rfc3826',
        'pysnmp.proto.secmod.eso',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'test', 'doctest', 'pdb'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

# onedir, non onefile. Un onefile e' un bootloader che a OGNI avvio
# decomprime ~34 MB in %TEMP%\_MEIxxxx prima che Python parta: misurato,
# 8.2s contro 3.5s da sorgente sulla stessa macchina. Con onedir i file
# stanno gia' su disco e quel tempo sparisce. Il prezzo e' una cartella
# invece di un singolo file, che per un prodotto installato da un
# installer non e' un prezzo: nessuno lancia l'exe da una chiavetta.
#
# upx=False per lo stesso motivo (ogni DLL va decompressa a ogni avvio) e
# perche' l'exe compresso con UPX e' una firma euristica che gli antivirus
# segnalano di routine.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SentinelNet',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # console=True e' deliberato: l'exe ha modalita' CLI (--reset-admin,
    # --mcp) il cui output deve restare visibile; la finestra console e' il
    # prezzo, non un difetto.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='SentinelNet',
)
