// Multi-VDOM command text (manual-config.js), extracted and run in isolation.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/manual-config.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
// Functions inside the module's IIFE, indented by four spaces.
const fn = name => {
    const start = src.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `missing ${name}`);
    const end = src.indexOf('\n    }\n', start) + 6;
    return (0, eval)(`(${src.slice(start, end)})`);
};
const vdomName = fn('vdomName');
const vdomCommands = fn('vdomCommands');

// Name validation: letters, digits, _ and -, at most 31; else the last valid one.
assert.equal(vdomName('root', 'root'), 'root');
assert.equal(vdomName(' dmz-vdom ', 'root'), 'dmz-vdom');
assert.equal(vdomName('vd_2', 'root'), 'vd_2');
assert.equal(vdomName('', 'dmz-vdom'), 'dmz-vdom');
assert.equal(vdomName('bad name', 'root'), 'root');
assert.equal(vdomName('x"; end', 'root'), 'root');
assert.equal(vdomName('a'.repeat(31), 'root'), 'a'.repeat(31));
assert.equal(vdomName('a'.repeat(32), 'root'), 'root');

const split = { global: ['show system global', 'show system interface'], vdom: ['show firewall policy'] };
const paging = 'config system console\n    set output standard\nend';
const text = vdomCommands(split, paging, ['get system status'], 'dmz-vdom');
assert.equal(text, [
    'config global', 'config system console', '    set output standard', 'end',
    'show system global', 'show system interface', 'get system status', 'end',
    'config vdom', 'edit dmz-vdom', 'show firewall policy', 'end',
].join('\n'));

// No paging, no info commands: nothing empty in between.
assert.equal(vdomCommands(split, '', [], 'root'),
    'config global\nshow system global\nshow system interface\nend\nconfig vdom\nedit root\nshow firewall policy\nend');

console.log('manual_config_vdom: ok');
