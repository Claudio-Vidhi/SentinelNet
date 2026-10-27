// Map title block in the editable exports (static/js/topology.js): the same
// drawing replayed into Visio primitives and draw.io cells.
//
//   node tests/js/test_map_title_block.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/topology.js'), 'utf8');

function extract(marker) {
    const start = src.indexOf(marker);
    assert.ok(start > 0, `${marker} not found in topology.js`);
    let depth = 0;
    for (let j = src.indexOf('{', start); j < src.length; j++) {
        if (src[j] === '{') depth++;
        else if (src[j] === '}' && --depth === 0) return src.slice(start, j + 1);
    }
    throw new Error(`unbalanced braces after ${marker}`);
}

// 6px per character: enough for the layout, no real canvas needed.
const document = { createElement: () => ({ getContext: () => ({ font: '', measureText: t => ({ width: String(t).length * 6 }) }) }) };
const T = { tbCustomer: 'Cliente', tbProject: 'Progetto', tbAuthor: 'Redatto da', tbDate: 'Data', tbRev: 'Rev.', tbDefaultTitle: 'Topologia di rete' };
const api = new Function('document', 'tbCfg', 'tbLogoImg', `
    const tr = k => (${JSON.stringify(T)})[k] || k;
    const tbInfo = () => ({ customer: tbCfg.customer, title: tbCfg.title, author: tbCfg.author, company: tbCfg.company, rev: tbCfg.rev, date: '2026-10-27' });
    const TB_SIZE = { classic: [480, 150], modern: [460, 132], minimal: [440, 92] };
    ${extract('function visioColor(')}
    ${extract('function makeRecordingCtx(')}
    ${extract('function drawTitleBlock(')}
    ${extract('function shiftedCtx(')}
    ${extract('function titleBlockPrims(')}
    ${extract('function drawioTitleBlock(')}
    return { titleBlockPrims, drawioTitleBlock };`);

const cfg = { style: 'classic', customer: 'Example S.p.A.', title: 'Rete sede', author: 'M. Rossi', company: 'Acme Networks', rev: 'B', accent: '#1f4e79' };
const logo = { width: 200, height: 100, src: 'data:image/png;base64,iVBORw0KGgo=' };
const { titleBlockPrims, drawioTitleBlock } = api(document, cfg, logo);

// Visio: shifted to the corner asked for, every field written, no logo.
const p = titleBlockPrims(1000, 500, false);
const texts = p.texts.map(t => t.text);
['Example S.p.A.', 'Rete sede', 'M. Rossi', '2026-10-27', 'B', 'CLIENTE'].forEach(s => assert.ok(texts.includes(s), s));
assert.ok(!p.images, 'no logo in Visio');
assert.ok(texts.includes('Acme Networks'), 'company name stands in for the logo');
const xs = [...p.rects.map(r => r.x), ...p.lines.flatMap(l => l.points.map(q => q[0]))];
const ys = [...p.rects.map(r => r.y), ...p.lines.flatMap(l => l.points.map(q => q[1]))];
assert.equal(Math.min(...xs), 1000);
assert.equal(Math.min(...ys), 500);
assert.ok(Math.max(...xs) <= 1480 && Math.max(...ys) <= 650, 'inside the 480 x 150 block');

// draw.io: one group under the map, right-aligned, logo embedded without ';base64'.
const cells = drawioTitleBlock(2000, 800, s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')).join('');
assert.match(cells, /<mxCell id="sn-title-block" value="" style="group;"[^>]*><mxGeometry x="1520" y="860" width="480" height="150"/);
assert.match(cells, /image=data:image\/png,iVBORw0KGgo=;/);
assert.ok(!cells.includes(';base64'));
assert.ok(cells.includes('value="Example S.p.A."'));
assert.ok((cells.match(/parent="sn-title-block"/g) || []).length > 10);

// --- Visio: one page per site --------------------------------------------
const { visioPages } = new Function(extract('function visioPages(') + '\nreturn { visioPages };')();
const vNodes = [{ id: 'sw-n1', x: 0, y: 0, w: 100, h: 40 }, { id: 'sw-n2', x: 300, y: 0, w: 100, h: 40 },
                { id: 'sw-s1', x: 2000, y: 0, w: 100, h: 40 }];
const zone = id => (id.startsWith('sw-n') ? { key: 'n', label: 'Sede Nord' } : { key: 's', label: 'Sede Sud' });
const vPrims = { lines: [], rects: [{ x: 1990, y: -30, w: 20, h: 10, fill: '#fff' }],
                 polys: [{ points: [[-40, -40], [340, -40], [340, 40], [-40, 40]], fill: '#eee' }],
                 texts: [{ x: -36, y: -46, text: 'SEDE NORD' }] };
const vConns = [{ from: 'sw-n1', to: 'sw-n2', points: [[50, 0], [250, 0]] }, { from: 'sw-s1', to: 'sw-n2', points: [[1950, 0], [350, 0]] }];
const pages = visioPages(vNodes, [], vPrims, vConns, zone);
assert.deepEqual(pages.map(p => p.name), ['Sede Nord', 'Sede Sud']);
assert.deepEqual(pages[0].nodes.map(n => n.id), ['sw-n1', 'sw-n2']);
assert.equal(pages[0].primitives.polys.length, 1, 'site frame on its own page');
assert.equal(pages[0].primitives.texts[0].text, 'SEDE NORD');
assert.equal(pages[1].primitives.rects.length, 1);
assert.deepEqual(pages.map(p => p.connectors.length), [1, 1], 'a cable to another site stays on the page it leaves from');

console.log('map title block: ok');
