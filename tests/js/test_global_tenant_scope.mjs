// The tenant selected at the top scopes every device selection.
// Each case below was a list that showed every tenant's devices.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const fnSrc = (src, head) => {
    const start = src.indexOf(head);
    assert.ok(start >= 0, `missing ${head}`);
    return src.slice(start, src.indexOf('\n}\n', start) + 2);
};

// FortiGate: the device selects (token, target manager) filter by tenant.
{
    const src = read('../../static/js/fortigate-management.js');
    const window = { globalSelectedTenant: 't1' };
    const globalDevices = [
        { IP: '192.0.2.1', Vendor: 'Fortinet', Group: 't1' },
        { IP: '192.0.2.2', Vendor: 'Fortinet', Group: 't2' },
        { IP: '192.0.2.3', Vendor: 'Cisco', Group: 't1' },
    ];
    const fgtInventoryDevices = eval(`(${fnSrc(src, 'function fgtInventoryDevices(')})`);
    assert.deepEqual(fgtInventoryDevices().map(d => d.IP), ['192.0.2.1']);
    window.globalSelectedTenant = 'all';
    assert.deepEqual(fgtInventoryDevices().map(d => d.IP), ['192.0.2.1', '192.0.2.2']);
    for (const f of ['function populateFgtPrevDeviceSelects(', 'function populateFgtMgrDeviceSelect(']) {
        assert.ok(fnSrc(src, f).includes('fgtInventoryDevices()'), `${f} must use fgtInventoryDevices`);
    }
    const onChange = src.slice(src.indexOf("window.addEventListener('globalTenantChanged'"));
    assert.ok(onChange.includes('populateFgtPrevDeviceSelects()') && onChange.includes('populateFgtMgrDeviceSelect()'),
              'a tenant change redraws the FortiGate device selects');
}

// Command palette: devices come from the selected tenant only.
{
    const core = read('../../static/js/core.js');
    assert.ok(core.includes("(globalDevices || []).filter(d => scopeTenant === 'all' || d.Group === scopeTenant).forEach("),
              'command palette must filter devices by the global tenant');
    assert.ok(/'bulkGroupFilter', 'dhTenant'\]/.test(core), 'device history tenant filter follows the global tenant');
}

// AI tab: attach-device and template lists start in the global tenant and follow it.
{
    const ai = read('../../static/js/ai.js');
    assert.ok(ai.includes("tenantSelectSeed(curTenant, groups, '')"), 'AI attach tenant seeded from the global tenant');
    assert.ok(ai.includes("tenantSelectSeed('', allTenants, allTenants[0])"), 'config generator tenant seeded from the global tenant');
    const onChange = ai.slice(ai.indexOf("window.addEventListener('globalTenantChanged'"));
    assert.ok(onChange.includes('populateAiAttachDevices()') && onChange.includes('populateGenCfgTemplates()'),
              'a tenant change redraws the AI device lists');
}

// Scheduler: a new schedule starts in the global tenant.
{
    const dv = read('../../static/js/devices.js');
    assert.ok(dv.includes("tenantSelectSeed('', Object.keys(globalGroups), tenantSelect.value)"),
              'new schedule tenant seeded from the global tenant');
}

console.log('global_tenant_scope: ok');
