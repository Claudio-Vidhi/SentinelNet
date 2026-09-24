// ui-wizard.js against a fake DOM: Next is gated by validate(), skip() drops
// a step from both navigation and the rail, the rail is clickable only in
// edit mode, and Next on the last active step calls onFinish.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/ui-wizard.js', import.meta.url), 'utf8');

function el(tag) {
    return {
        tagName: tag, hidden: false, disabled: false, textContent: '', className: '',
        children: [], attrs: {}, listeners: {},
        setAttribute(k, v) { this.attrs[k] = v; },
        appendChild(c) { this.children.push(c); return c; },
        replaceChildren(...c) { this.children = c; },
        addEventListener(t, f) { (this.listeners[t] ||= []).push(f); },
        fire(t) { (this.listeners[t] || []).forEach((f) => f({})); },
    };
}

const sections = { a: el('section'), b: el('section'), c: el('section') };
const rail = el('ol'), back = el('button'), next = el('button');
const panel = el('div');
panel.querySelector = (sel) => {
    if (sel === '[data-wizard-rail]') return rail;
    if (sel === '[data-wizard-back]') return back;
    if (sel === '[data-wizard-next]') return next;
    const m = /data-step="(\w+)"/.exec(sel);
    return m ? sections[m[1]] : null;
};
global.window = {};
global.document = { getElementById: (id) => (id === 'wiz' ? panel : null), createElement: el };
global.tr = (k) => k;
let opened = null;
global.openModal = (id) => { opened = id; };
global.closeModal = (id) => { if (opened === id) opened = null; };

const createWizard = new Function(src + '; return createWizard;')();
assert.strictEqual(typeof window.createWizard, 'function', 'window.createWizard not exposed');

let aValid = false, skipB = false, finished = null;
const wiz = createWizard('wiz', {
    steps: [
        { id: 'a', label: 'la', validate: () => aValid },
        { id: 'b', label: 'lb', skip: () => skipB },
        { id: 'c', label: 'lc', finishLabel: 'save' },
    ],
    onFinish: (id) => { finished = id; },
});
const tick = () => new Promise((r) => setTimeout(r, 0));

wiz.open();
assert.strictEqual(opened, 'wiz');
assert.strictEqual(wiz.current(), 'a');
assert.ok(sections.b.hidden && sections.c.hidden && !sections.a.hidden, 'only the current step is visible');
assert.strictEqual(next.disabled, true, 'Next must be disabled while validate() is false');
assert.strictEqual(back.hidden, true, 'no Back on the first step');

next.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'a', 'a failing validate() must not advance');

aValid = true; panel.fire('input');
assert.strictEqual(next.disabled, false, 'refresh on input re-enables Next');
next.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'b');

back.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'a');

skipB = true; panel.fire('change');
assert.strictEqual(rail.children.length, 2, 'a change that skips a step updates the rail at once');
next.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'c', 'Next jumps over a skipped step');
assert.strictEqual(next.textContent, 'save', 'last step shows its finishLabel');

next.fire('click'); await tick();
assert.strictEqual(finished, 'c', 'Next on the last step calls onFinish');

// Rail: plain text when creating, buttons (except the current step) in edit mode.
assert.ok(rail.children.every((li) => li.children.length === 0), 'rail is not clickable when creating');
wiz.open({ at: 'c', editable: true });
const buttons = rail.children.filter((li) => li.children.length === 1);
assert.strictEqual(buttons.length, 1, 'every non-current step is a button in edit mode');
buttons[0].children[0].fire('click');
assert.strictEqual(wiz.current(), 'a');
assert.strictEqual(rail.children[0].attrs['aria-current'], 'step');

wiz.close();
assert.strictEqual(opened, null);
console.log('ok - ui-wizard navigation, validation, skip, rail');
