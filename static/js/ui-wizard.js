// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// Step-by-step panel on top of the modal manager (ui-modal.js): a rail of
// steps, one visible section at a time, Next gated by the step's validate().
// Shared by the site, device and provisioning flows.
//
// Markup contract inside the panel: [data-wizard-rail] (an <ol>),
// [data-wizard-back], [data-wizard-next], and one [data-step="<id>"] per step.
// A step: { id, label (i18n key), validate?, onEnter?, skip?, finishLabel? }.
function createWizard(panelId, { steps, onFinish }) {
    const panel = document.getElementById(panelId);
    const rail = panel.querySelector('[data-wizard-rail]');
    const btnBack = panel.querySelector('[data-wizard-back]');
    const btnNext = panel.querySelector('[data-wizard-next]');
    let index = 0;
    let editable = false;

    const section = (step) => panel.querySelector(`[data-step="${step.id}"]`);
    const active = () => steps.filter((s) => !(s.skip && s.skip()));

    function refresh() {
        const cur = steps[index];
        btnNext.disabled = !!cur.validate && !cur.validate();
    }

    function render() {
        const cur = steps[index];
        const list = active();
        const pos = list.indexOf(cur);
        steps.forEach((s) => { section(s).hidden = s !== cur; });
        rail.replaceChildren(...list.map((s, i) => {
            const li = document.createElement('li');
            li.className = 'wizard-step' + (s === cur ? ' is-current' : i < pos ? ' is-done' : '');
            if (s === cur) li.setAttribute('aria-current', 'step');
            const text = `${i + 1}. ${tr(s.label)}`;
            if (editable && s !== cur) {
                const b = document.createElement('button');
                b.type = 'button';
                b.textContent = text;
                b.addEventListener('click', () => goTo(s.id));
                li.appendChild(b);
            } else {
                li.textContent = text;
            }
            return li;
        }));
        btnBack.hidden = pos <= 0;
        btnNext.textContent = tr(pos === list.length - 1 ? (cur.finishLabel || 'wizNext') : 'wizNext');
        refresh();
    }

    function goTo(id) {
        const i = steps.findIndex((s) => s.id === id);
        if (i === -1) return;
        index = i;
        if (steps[i].onEnter) steps[i].onEnter();
        render();
    }

    function move(delta) {
        const list = active();
        const target = list[list.indexOf(steps[index]) + delta];
        if (target) goTo(target.id);
    }

    async function next() {
        const cur = steps[index];
        if (cur.validate && !cur.validate()) return;
        const list = active();
        if (list[list.length - 1] === cur) {
            await onFinish(cur.id);
            return;
        }
        move(1);
    }

    btnNext.addEventListener('click', next);
    btnBack.addEventListener('click', () => move(-1));
    // Any edit inside the panel may change what the current step accepts.
    panel.addEventListener('input', refresh);
    panel.addEventListener('change', refresh);

    return {
        /** @param {{at?: string, editable?: boolean, onClose?: Function}} [opts] */
        open({ at, editable: canJump = false, onClose } = {}) {
            editable = canJump;
            openModal(panelId, onClose);
            goTo(at || active()[0].id);
        },
        close() { closeModal(panelId); },
        goTo,
        refresh,
        current: () => steps[index].id,
    };
}
window.createWizard = createWizard;
