import re

with open("test_ui_revamp.py", "r", encoding="utf-8") as f:
    code = f.read()

# Insert the router imports
import_str = "import app_server  # noqa: E402\nimport routers.inventory, routers.topology, routers.catalog, routers.mac, routers.analyzer, routers.backup, routers.sites, routers.mcp\n"
code = code.replace("import app_server  # noqa: E402\n", import_str)

mapping = {
    'list_models': 'routers.inventory',
    'create_model': 'routers.inventory',
    'remove_model': 'routers.inventory',
    'get_topology_adjacency': 'routers.topology',
    'export_map_vsdx': 'routers.topology',
    'create_device_category': 'routers.catalog',
    'mac_switch': 'routers.mac',
    'config_analyzer_device': 'routers.analyzer',
    'config_analyzer_all': 'routers.analyzer',
    'download_backup': 'routers.backup',
    'update_site_ep': 'routers.sites',
    'get_mcp_tool_config': 'routers.mcp',
    'get_mcp_settings': 'routers.mcp',
    'set_mcp_settings': 'routers.mcp'
}

for func, module in mapping.items():
    code = code.replace(f"hasattr(_app_server, '{func}')", f"hasattr({module}, '{func}')")
    
code = code.replace("hasattr(_app_server, fn)", "hasattr(routers.sites, fn)")

with open("test_ui_revamp.py", "w", encoding="utf-8") as f:
    f.write(code)
