import re

with open("test_ui_revamp.py", "r", encoding="utf-8") as f:
    code = f.read()

code = code.replace("hasattr(routers.inventory, 'list_models')", "hasattr(routers.catalog, 'list_models')")
code = code.replace("hasattr(routers.inventory, 'create_model')", "hasattr(routers.catalog, 'create_model')")
code = code.replace("hasattr(routers.inventory, 'remove_model')", "hasattr(routers.catalog, 'remove_model')")

with open("test_ui_revamp.py", "w", encoding="utf-8") as f:
    f.write(code)
