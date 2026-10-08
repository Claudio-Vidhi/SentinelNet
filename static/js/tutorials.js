// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// Guided tutorials and interactive product walkthrough engine.
// Provides both on-demand guided tours (via Help Hub & Command Palette)
// and initial onboarding guidance for new users.

(function () {
    let _activeTutorial = null;
    let _currentStepIdx = 0;
    let _keydownHandler = null;
    let _resizeHandler = null;

    const TUTORIAL_DEFINITIONS = {
        intro: {
            id: 'intro',
            titleKey: 'tutHubIntroTitle',
            descKey: 'tutHubIntroDesc',
            badgeKey: 'tutBadgeIntro',
            duration: 2,
            icon: 'fa-gauge-high',
            steps: [
                {
                    target: null,
                    badgeKey: 'tutBadgeIntro',
                    titleKey: 'tutIntroS1Title',
                    textKey: 'tutIntroS1Text'
                },
                {
                    tab: 'tab-home',
                    target: '#homeVerdicts',
                    badgeKey: 'tutBadgeIntro',
                    titleKey: 'tutIntroS2Title',
                    textKey: 'tutIntroS2Text'
                },
                {
                    tab: 'tab-home',
                    target: '#btnHomeRunTriage',
                    badgeKey: 'tutBadgeIntro',
                    titleKey: 'tutIntroS3Title',
                    textKey: 'tutIntroS3Text'
                },
                {
                    target: '#appSidebar',
                    badgeKey: 'tutBadgeIntro',
                    titleKey: 'tutIntroS4Title',
                    textKey: 'tutIntroS4Text'
                },
                {
                    target: '#btnOpenCommandPalette',
                    badgeKey: 'tutBadgeIntro',
                    titleKey: 'tutIntroS5Title',
                    textKey: 'tutIntroS5Text'
                },
                {
                    target: '#btnOpenTutorials',
                    badgeKey: 'tutBadgeIntro',
                    titleKey: 'tutIntroS6Title',
                    textKey: 'tutIntroS6Text'
                }
            ]
        },
        inventory: {
            id: 'inventory',
            titleKey: 'tutHubInvTitle',
            descKey: 'tutHubInvDesc',
            badgeKey: 'tutBadgeInv',
            duration: 2,
            icon: 'fa-list-check',
            steps: [
                {
                    tab: 'tab-devices',
                    target: '#tab-devices',
                    badgeKey: 'tutBadgeInv',
                    titleKey: 'tutInvS1Title',
                    textKey: 'tutInvS1Text'
                },
                {
                    tab: 'tab-devices',
                    target: '#filterDeviceText',
                    badgeKey: 'tutBadgeInv',
                    titleKey: 'tutInvS2Title',
                    textKey: 'tutInvS2Text'
                },
                {
                    tab: 'tab-devices',
                    target: '#tableDevices',
                    badgeKey: 'tutBadgeInv',
                    titleKey: 'tutInvS3Title',
                    textKey: 'tutInvS3Text'
                },
                {
                    tab: 'tab-provisioning',
                    target: '#tab-provisioning',
                    badgeKey: 'tutBadgeInv',
                    titleKey: 'tutInvS4Title',
                    textKey: 'tutInvS4Text'
                }
            ]
        },
        triage: {
            id: 'triage',
            titleKey: 'tutHubTriageTitle',
            descKey: 'tutHubTriageDesc',
            badgeKey: 'tutBadgeTriage',
            duration: 3,
            icon: 'fa-bolt-lightning',
            steps: [
                {
                    tab: 'tab-home',
                    target: '#verdictReachability',
                    badgeKey: 'tutBadgeTriage',
                    titleKey: 'tutTriageS1Title',
                    textKey: 'tutTriageS1Text'
                },
                {
                    tab: 'tab-home',
                    target: '#verdictCve',
                    badgeKey: 'tutBadgeTriage',
                    titleKey: 'tutTriageS2Title',
                    textKey: 'tutTriageS2Text'
                },
                {
                    tab: 'tab-home',
                    target: '#verdictDrift',
                    badgeKey: 'tutBadgeTriage',
                    titleKey: 'tutTriageS3Title',
                    textKey: 'tutTriageS3Text'
                },
                {
                    tab: 'tab-home',
                    target: '#btnHomeRunTriage',
                    badgeKey: 'tutBadgeTriage',
                    titleKey: 'tutTriageS4Title',
                    textKey: 'tutTriageS4Text'
                }
            ]
        },
        command_palette: {
            id: 'command_palette',
            titleKey: 'tutHubCmdTitle',
            descKey: 'tutHubCmdDesc',
            badgeKey: 'tutBadgeCmd',
            duration: 1,
            icon: 'fa-terminal',
            steps: [
                {
                    target: '#btnOpenCommandPalette',
                    badgeKey: 'tutBadgeCmd',
                    titleKey: 'tutCmdS1Title',
                    textKey: 'tutCmdS1Text'
                },
                {
                    target: null,
                    badgeKey: 'tutBadgeCmd',
                    titleKey: 'tutCmdS2Title',
                    textKey: 'tutCmdS2Text'
                }
            ]
        },
        ai_mcp: {
            id: 'ai_mcp',
            titleKey: 'tutHubMcpTitle',
            descKey: 'tutHubMcpDesc',
            badgeKey: 'tutBadgeMcp',
            duration: 2,
            icon: 'fa-robot',
            steps: [
                {
                    tab: 'tab-ai',
                    target: '#tab-ai',
                    badgeKey: 'tutBadgeMcp',
                    titleKey: 'tutMcpS1Title',
                    textKey: 'tutMcpS1Text'
                },
                {
                    tab: 'tab-mcp',
                    target: '#tab-mcp',
                    badgeKey: 'tutBadgeMcp',
                    titleKey: 'tutMcpS2Title',
                    textKey: 'tutMcpS2Text'
                }
            ]
        }
    };

    function isTutorialCompleted(id) {
        try {
            return localStorage.getItem('sentinel_tut_' + id) === 'done';
        } catch (_) {
            return false;
        }
    }

    function setTutorialCompleted(id) {
        try {
            localStorage.setItem('sentinel_tut_' + id, 'done');
        } catch (_) {}
    }

    function renderTutorialsHubCards() {
        const container = document.getElementById('tutorialsHubList');
        if (!container) return;

        let html = '';
        Object.values(TUTORIAL_DEFINITIONS).forEach(tut => {
            const completed = isTutorialCompleted(tut.id);
            const badgeClass = completed ? 'tutorial-hub-badge completed' : 'tutorial-hub-badge';
            const badgeText = completed ? `${tr('tutCompleted')} ✓` : tr('tutDuration', { m: tut.duration });
            const btnLabel = completed ? tr('tutBtnRestartTour') : tr('tutBtnStartTour');

            html += `
            <div class="tutorial-hub-card">
              <div class="tutorial-hub-card-top">
                <div class="tutorial-hub-icon"><i class="fa-solid ${tut.icon}"></i></div>
                <div class="tutorial-hub-meta">
                  <div class="tutorial-hub-header-row">
                    <h4 class="tutorial-hub-title">${escapeHtml(tr(tut.titleKey))}</h4>
                    <span class="${badgeClass}">${escapeHtml(badgeText)}</span>
                  </div>
                  <p class="tutorial-hub-desc">${escapeHtml(tr(tut.descKey))}</p>
                </div>
              </div>
              <div class="tutorial-hub-actions">
                <span class="tutorial-hub-duration"><i class="fa-regular fa-clock"></i> ${tut.duration} min</span>
                <button type="button" class="btn btn-primary btn-small" data-start-tutorial="${tut.id}">
                  <i class="fa-solid fa-play" style="font-size:10px; margin-right:4px;"></i> ${escapeHtml(btnLabel)}
                </button>
              </div>
            </div>`;
        });
        container.innerHTML = html;
    }

    function openTutorialsHub() {
        renderTutorialsHubCards();
        openModal('modalTutorialsHub');
    }

    function closeTutorialsHub() {
        closeModal('modalTutorialsHub');
    }

    function resetTutorialsOnboarding() {
        try {
            localStorage.removeItem('sentinel_onboarding_dismissed');
            Object.keys(TUTORIAL_DEFINITIONS).forEach(id => {
                localStorage.removeItem('sentinel_tut_' + id);
            });
            renderTutorialsHubCards();
            alert(tr('tutResetPromptsDone'));
        } catch (_) {}
    }

    async function startTutorial(id) {
        const tut = TUTORIAL_DEFINITIONS[id];
        if (!tut) return;

        closeTutorialsHub();
        dismissOnboardingToast(false);

        _activeTutorial = tut;
        _currentStepIdx = 0;

        const overlay = document.getElementById('tutorialOverlay');
        const card = document.getElementById('tutorialCard');

        if (overlay) overlay.classList.add('active');
        if (card) card.classList.add('active');

        _keydownHandler = (e) => {
            if (!_activeTutorial) return;
            if (e.key === 'Escape') {
                e.preventDefault();
                endTutorial();
            } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
                e.preventDefault();
                nextTutorialStep();
            } else if (e.key === 'ArrowLeft') {
                e.preventDefault();
                prevTutorialStep();
            }
        };
        window.addEventListener('keydown', _keydownHandler, true);

        _resizeHandler = () => {
            if (_activeTutorial) positionTutorialStep();
        };
        window.addEventListener('resize', _resizeHandler);

        await showStep(_currentStepIdx);
    }

    async function showStep(idx) {
        if (!_activeTutorial || idx < 0 || idx >= _activeTutorial.steps.length) return;
        _currentStepIdx = idx;
        const step = _activeTutorial.steps[idx];

        // Switch tab if step targets a specific tab
        if (step.tab && typeof switchTab === 'function') {
            await switchTab(step.tab);
            await new Promise(r => setTimeout(r, 100));
        }

        renderCardContent(step);
        positionTutorialStep();
    }

    function renderCardContent(step) {
        const card = document.getElementById('tutorialCard');
        if (!card) return;

        const total = _activeTutorial.steps.length;
        const current = _currentStepIdx + 1;

        const pill = card.querySelector('.tutorial-card-pill');
        if (pill) pill.textContent = tr(step.badgeKey || _activeTutorial.badgeKey);

        const stepCount = card.querySelector('.tutorial-card-step');
        if (stepCount) stepCount.textContent = tr('tutStepOf', { current, total });

        const title = card.querySelector('.tutorial-card-title');
        if (title) title.textContent = tr(step.titleKey);

        const text = card.querySelector('.tutorial-card-text');
        if (text) text.innerHTML = tr(step.textKey);

        const progress = card.querySelector('.tutorial-progress-fill');
        if (progress) progress.style.width = `${(current / total) * 100}%`;

        const btnPrev = card.querySelector('.tut-btn-prev');
        if (btnPrev) btnPrev.style.visibility = _currentStepIdx > 0 ? 'visible' : 'hidden';

        const btnNext = card.querySelector('.tut-btn-next');
        if (btnNext) {
            btnNext.textContent = _currentStepIdx === total - 1 ? tr('tutBtnFinish') : tr('tutBtnNext');
        }
    }

    function positionTutorialStep() {
        if (!_activeTutorial) return;
        const step = _activeTutorial.steps[_currentStepIdx];
        const card = document.getElementById('tutorialCard');
        const cutout = document.getElementById('tutorialCutout');
        const border = document.getElementById('tutorialCutoutBorder');
        if (!card) return;

        let targetEl = null;
        if (step.target) {
            try {
                targetEl = document.querySelector(step.target);
            } catch (_) {}
        }

        const cardWidth = 410;
        const cardHeight = card.offsetHeight || 220;
        const margin = 14;

        if (targetEl && targetEl.offsetParent !== null) {
            try {
                targetEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            } catch (_) {}

            const rect = targetEl.getBoundingClientRect();
            const pad = 6;
            const x = Math.max(0, rect.left - pad);
            const y = Math.max(0, rect.top - pad);
            const w = rect.width + pad * 2;
            const h = rect.height + pad * 2;

            if (cutout) {
                cutout.setAttribute('x', String(x));
                cutout.setAttribute('y', String(y));
                cutout.setAttribute('width', String(w));
                cutout.setAttribute('height', String(h));
            }
            if (border) {
                border.style.display = 'block';
                border.setAttribute('x', String(x));
                border.setAttribute('y', String(y));
                border.setAttribute('width', String(w));
                border.setAttribute('height', String(h));
            }

            // Determine optimal popover location (below, above, right, left)
            let top = rect.bottom + margin;
            let left = rect.left;

            // Space below check
            if (top + cardHeight > window.innerHeight - margin) {
                // Try above
                if (rect.top - cardHeight - margin > margin) {
                    top = rect.top - cardHeight - margin;
                } else {
                    top = Math.max(margin, (window.innerHeight - cardHeight) / 2);
                }
            }

            // Screen horizontal clamp
            if (left + cardWidth > window.innerWidth - margin) {
                left = window.innerWidth - cardWidth - margin;
            }
            if (left < margin) left = margin;

            card.style.top = `${top}px`;
            card.style.left = `${left}px`;
            card.style.transform = 'none';
        } else {
            // General or center modal step
            if (cutout) {
                cutout.setAttribute('width', '0');
                cutout.setAttribute('height', '0');
            }
            if (border) {
                border.style.display = 'none';
            }

            card.style.top = '50%';
            card.style.left = '50%';
            card.style.transform = 'translate(-50%, -50%)';
        }
    }

    async function nextTutorialStep() {
        if (!_activeTutorial) return;
        if (_currentStepIdx < _activeTutorial.steps.length - 1) {
            await showStep(_currentStepIdx + 1);
        } else {
            setTutorialCompleted(_activeTutorial.id);
            endTutorial();
        }
    }

    async function prevTutorialStep() {
        if (!_activeTutorial) return;
        if (_currentStepIdx > 0) {
            await showStep(_currentStepIdx - 1);
        }
    }

    function endTutorial() {
        _activeTutorial = null;
        _currentStepIdx = 0;

        const overlay = document.getElementById('tutorialOverlay');
        const card = document.getElementById('tutorialCard');
        const cutout = document.getElementById('tutorialCutout');
        const border = document.getElementById('tutorialCutoutBorder');

        if (overlay) overlay.classList.remove('active');
        if (card) {
            card.classList.remove('active');
            card.style.top = '';
            card.style.left = '';
            card.style.transform = '';
        }
        if (cutout) {
            cutout.setAttribute('width', '0');
            cutout.setAttribute('height', '0');
        }
        if (border) {
            border.style.display = 'none';
        }

        if (_keydownHandler) {
            window.removeEventListener('keydown', _keydownHandler, true);
            _keydownHandler = null;
        }
        if (_resizeHandler) {
            window.removeEventListener('resize', _resizeHandler);
            _resizeHandler = null;
        }
    }

    function dismissOnboardingToast(permanent = true) {
        const toast = document.getElementById('onboardingWelcomeCard');
        if (toast) toast.style.display = 'none';
        if (permanent) {
            try {
                localStorage.setItem('sentinel_onboarding_dismissed', '1');
            } catch (_) {}
        }
    }

    function initTutorialsOnboarding() {
        try {
            const dismissed = localStorage.getItem('sentinel_onboarding_dismissed');
            const introDone = localStorage.getItem('sentinel_tut_intro');
            if (!dismissed && !introDone) {
                setTimeout(() => {
                    const toast = document.getElementById('onboardingWelcomeCard');
                    if (toast && !document.getElementById('authOverlay')?.offsetParent) {
                        toast.style.display = 'block';
                    }
                }, 1500);
            }
        } catch (_) {}
    }

    function setupTutorialEventListeners() {
        // Topbar trigger
        document.getElementById('btnOpenTutorials')?.addEventListener('click', openTutorialsHub);
        document.getElementById('btnCloseTutorialsHub')?.addEventListener('click', closeTutorialsHub);
        document.getElementById('btnResetTutorials')?.addEventListener('click', resetTutorialsOnboarding);

        // Delegated clicks inside Hub modal
        document.getElementById('tutorialsHubList')?.addEventListener('click', (e) => {
            const target = e.target instanceof Element ? e.target.closest('[data-start-tutorial]') : null;
            if (target) {
                const tutId = target.getAttribute('data-start-tutorial');
                if (tutId) startTutorial(tutId);
            }
        });

        // Onboarding Toast
        document.getElementById('btnStartOnboardingTour')?.addEventListener('click', () => {
            dismissOnboardingToast(true);
            startTutorial('intro');
        });
        document.getElementById('btnDismissOnboardingTour')?.addEventListener('click', () => {
            dismissOnboardingToast(true);
        });
        document.getElementById('btnCloseOnboardingToast')?.addEventListener('click', () => {
            dismissOnboardingToast(true);
        });

        // Card controls
        const card = document.getElementById('tutorialCard');
        if (card) {
            card.querySelector('.tutorial-card-close')?.addEventListener('click', endTutorial);
            card.querySelector('.tut-btn-skip')?.addEventListener('click', endTutorial);
            card.querySelector('.tut-btn-prev')?.addEventListener('click', prevTutorialStep);
            card.querySelector('.tut-btn-next')?.addEventListener('click', nextTutorialStep);
        }

        // Overlay backdrop click dismisses tour
        document.getElementById('tutorialBackdropRect')?.addEventListener('click', endTutorial);
    }

    document.addEventListener('DOMContentLoaded', setupTutorialEventListeners);

    window.startTutorial = startTutorial;
    window.openTutorialsHub = openTutorialsHub;
    window.closeTutorialsHub = closeTutorialsHub;
    window.initTutorialsOnboarding = initTutorialsOnboarding;
    window.resetTutorialsOnboarding = resetTutorialsOnboarding;
})();
