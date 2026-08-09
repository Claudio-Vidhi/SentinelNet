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
    datas=[('templates', 'templates'), ('static', 'static'), ('drivers', 'drivers'),
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

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SentinelNet',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['python3*.dll', 'vcruntime140.dll', 'vcruntime140_1.dll', 'api-ms-win-*.dll'],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
