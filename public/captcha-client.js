(function() {
    const DEFAULT_SERVER_URL = "https://captcha.hsyst.org";
    const scriptTag = document.currentScript || document.querySelector('script[data-verigate]');
    const CAPTCHA_SERVER_URL = (scriptTag && scriptTag.getAttribute('data-server-url')) || window.VeriGateCaptchaServer || DEFAULT_SERVER_URL;
    const CAPTCHA_COOKIE_NAME = "verigate_captcha_token";

    // Utilidades
    function clamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
    }

    function getPointerPosition(canvas, clientX, clientY) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        return {
            x: (clientX - rect.left) * scaleX,
            y: (clientY - rect.top) * scaleY
        };
    }

    function isTouchDevice() {
        return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    }

    function preventDefaultTouch(e) {
        if (e.cancelable) e.preventDefault();
    }

    // Configurações específicas para mobile
    const MOBILE_CONFIG = {
        movementSendIntervalMs: 120, // Mais lento para mobile
        movementSendPixelThreshold: 8, // Menor sensibilidade
        focusPadding: 20, // Mais espaço para toque
        canvasMaxWidth: 400, // Largura máxima para mobile
        pieceSizeMultiplier: 1.2 // Peça maior para toque
    };

    window.VeriGateCaptcha = {
        _captchaState: {
            captchaContainer: null,
            captchaLoading: null,
            captchaError: null,
            startCaptchaBtn: null,
            captchaTimerDisplay: null,
            challengeIdInput: null,
            formSubmitBtn: null,

            canvasContainer: null,
            canvas: null,
            ctx: null,
            backgroundImage: null,
            canvasWidth: 0,
            canvasHeight: 0,
            pieceSize: 0,
            pieceColor: '#0d6efd',
            targetShape: 'rect',
            overlayScale: 1,
            overlaySize: 0,
            focusOnPiece: false,
            focusPadding: 14,
            pendingResult: null,
            resultTimer: null,
            pieceX: 0,
            pieceY: 0,
            dragOffsetX: 0,
            dragOffsetY: 0,
            dragging: false,
            interactionEnabled: false,
            lastMovementSend: 0,
            movePixelDistance: 0,
            moveSendInFlight: null,
            lastMovePoint: null,
            movementSendIntervalMs: 80,
            movementSendPixelThreshold: 12,

            currentChallengeId: null,
            captchaTimerInterval: null,
            maxChallengeTime: 0,
            tokenExpirationMinutes: 60,
            movementData: [],
            
            // Mobile specific
            isMobile: false,
            touchActive: false,
            currentTouchId: null,
            modalOpen: false
        },

        init: function(containerId, successCallback, errorCallback, formToBind = null, options = {}) {
            const state = this._captchaState;
            state.serverUrl = options.serverUrl || CAPTCHA_SERVER_URL;
            state.isMobile = isTouchDevice();
            
            // Ajustar configurações para mobile
            if (state.isMobile) {
                state.movementSendIntervalMs = MOBILE_CONFIG.movementSendIntervalMs;
                state.movementSendPixelThreshold = MOBILE_CONFIG.movementSendPixelThreshold;
                state.focusPadding = MOBILE_CONFIG.focusPadding;
            }

            state.captchaContainer = document.getElementById(containerId);
            if (!state.captchaContainer) {
                console.error("VeriGateCaptcha: Container DIV com ID '" + containerId + "' não encontrado.");
                return;
            }

            // Adicionar estilos responsivos
            if (!document.getElementById('verigate-captcha-style')) {
                const style = document.createElement('style');
                style.id = 'verigate-captcha-style';
                style.textContent = `
                    :root {
                        --verigate-primary: #0d6efd;
                        --verigate-success: #0f5132;
                        --verigate-error: #842029;
                        --verigate-light-bg: #f9fafc;
                        --verigate-dark-bg: #161a1f;
                        --verigate-border-light: #d6d9dd;
                        --verigate-border-dark: #2a2f36;
                    }

                    .verigate-result {
                        display: inline-flex;
                        align-items: center;
                        gap: 6px;
                        font-size: 12px;
                        font-weight: 600;
                    }

                    .verigate-result-icon {
                        width: 18px;
                        height: 18px;
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        border-radius: 50%;
                        font-size: 12px;
                        font-weight: 700;
                        transform: scale(0.6);
                        opacity: 0;
                        animation: verigate-pop 0.25s ease forwards;
                    }

                    .verigate-result-success {
                        color: var(--verigate-success);
                    }

                    .verigate-result-success .verigate-result-icon {
                        background: rgba(15,81,50,0.12);
                        color: var(--verigate-success);
                    }

                    .verigate-result-error {
                        color: var(--verigate-error);
                    }

                    .verigate-result-error .verigate-result-icon {
                        background: rgba(132,32,41,0.12);
                        color: var(--verigate-error);
                    }

                    .verigate-card-success {
                        border-color: #b7dfc3 !important;
                        box-shadow: 0 0 0 2px rgba(15,81,50,0.08) inset !important;
                    }

                    .verigate-card-error {
                        border-color: #f1aeb5 !important;
                        box-shadow: 0 0 0 2px rgba(132,32,41,0.08) inset !important;
                    }

                    .verigate-shake {
                        animation: verigate-shake 0.35s ease;
                    }

                    .verigate-modal {
                        opacity: 0;
                        pointer-events: none;
                        transition: opacity 0.25s ease;
                    }

                    .verigate-modal-open {
                        opacity: 1;
                        pointer-events: auto;
                    }

                    .verigate-modal-exit {
                        animation: verigate-fade 0.35s ease forwards;
                    }

                    .verigate-modal-overlay {
                        backdrop-filter: blur(0px);
                        transition: backdrop-filter 0.35s ease;
                        background: radial-gradient(circle at 20% 30%, rgba(255,255,255,0.08), rgba(0,0,0,0) 45%);
                    }

                    .verigate-modal-open .verigate-modal-overlay {
                        backdrop-filter: blur(6px);
                        animation: verigate-veil 6s ease-in-out infinite;
                    }

                    .verigate-modal-exit .verigate-modal-overlay {
                        animation: verigate-blur-out 0.35s ease forwards;
                    }

                    .verigate-theme-dark {
                        background: var(--verigate-dark-bg) !important;
                        border-color: var(--verigate-border-dark) !important;
                        color: #e6e9ee !important;
                    }

                    .verigate-theme-dark .verigate-title {
                        color: #e6e9ee !important;
                    }

                    .verigate-theme-dark .verigate-subtle {
                        color: #a4abb4 !important;
                    }

                    .verigate-theme-dark .verigate-panel {
                        background: #0f1216 !important;
                        border-color: var(--verigate-border-dark) !important;
                    }

                    .verigate-theme-dark .verigate-btn {
                        background: #1f2530 !important;
                        border-color: #313744 !important;
                        color: #d5d9df !important;
                    }

                    .verigate-theme-dark .verigate-pill {
                        background: #202633 !important;
                        border-color: #2f3645 !important;
                        color: #c7cbd2 !important;
                    }

                    .verigate-theme-dark .verigate-pill.active {
                        background: var(--verigate-primary) !important;
                        border-color: var(--verigate-primary) !important;
                        color: #fff !important;
                    }

                    /* Responsividade */
                    @media (max-width: 480px) {
                        .verigate-modal-card {
                            width: 95vw !important;
                            max-height: 90vh !important;
                            padding: 12px !important;
                            border-radius: 8px !important;
                        }
                        
                        .verigate-btn {
                            padding: 8px 12px !important;
                            font-size: 14px !important;
                        }
                        
                        .verigate-title {
                            font-size: 14px !important;
                        }
                        
                        .verigate-subtle {
                            font-size: 13px !important;
                        }
                    }

                    @media (max-width: 360px) {
                        .verigate-modal-card {
                            padding: 10px !important;
                        }
                        
                        .verigate-header-actions {
                            flex-wrap: wrap !important;
                            gap: 4px !important;
                        }
                        
                        .verigate-pill {
                            padding: 3px 6px !important;
                            font-size: 10px !important;
                        }
                    }

                    /* Animações */
                    @keyframes verigate-pop {
                        to {
                            transform: scale(1);
                            opacity: 1;
                        }
                    }

                    @keyframes verigate-shake {
                        0% { transform: translateX(0); }
                        20% { transform: translateX(-6px); }
                        40% { transform: translateX(6px); }
                        60% { transform: translateX(-4px); }
                        80% { transform: translateX(4px); }
                        100% { transform: translateX(0); }
                    }

                    @keyframes verigate-fade {
                        to { opacity: 0; }
                    }

                    @keyframes verigate-blur-out {
                        to { backdrop-filter: blur(0px); }
                    }

                    @keyframes verigate-veil {
                        0% { background-position: 0% 0%; }
                        50% { background-position: 100% 50%; }
                        100% { background-position: 0% 0%; }
                    }

                    /* Prevenir zoom em iOS ao tocar em inputs */
                    @media screen and (max-width: 768px) {
                        input, select, textarea {
                            font-size: 16px !important;
                        }
                    }

                    /* Melhorar feedback de toque */
                    .verigate-btn:active {
                        transform: scale(0.98);
                        transition: transform 0.1s;
                    }
                `;
                document.head.appendChild(style);
            }

            // Criar HTML responsivo
            state.captchaContainer.innerHTML = `
                <button type="button" id="${containerId}-open-btn" class="verigate-open-btn" style="
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    border: 1px solid var(--verigate-border-light);
                    background: #f3f5f7;
                    color: #2b3035;
                    font-size: 12px;
                    font-weight: 600;
                    padding: 6px 12px;
                    border-radius: 999px;
                    cursor: pointer;
                    box-shadow: inset 0 1px 2px rgba(10,23,42,0.08);
                    touch-action: manipulation;
                    -webkit-tap-highlight-color: transparent;
                ">
                    <span style="
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        width: 16px;
                        height: 16px;
                        border-radius: 50%;
                        background: var(--verigate-primary);
                        color: #fff;
                        font-size: 10px;
                        font-weight: 700;
                    ">V</span>
                    VeriGate CAPTCHA
                </button>
                
                <div id="${containerId}-modal" class="verigate-modal" style="
                    position: fixed;
                    inset: 0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: rgba(12,14,18,0.45);
                    z-index: 9999;
                    padding: 16px;
                    touch-action: none;
                ">
                    <div class="verigate-modal-overlay" style="position:absolute; inset:0;"></div>
                    
                    <div id="${containerId}-card" class="verigate-modal-card verigate-theme-dark" style="
                        width: min(${MOBILE_CONFIG.canvasMaxWidth}px, 96vw);
                        max-height: 90vh;
                        overflow: auto;
                        background: var(--verigate-light-bg);
                        border: 1px solid var(--verigate-border-light);
                        border-radius: 10px;
                        box-shadow: 0 18px 40px rgba(10,23,42,0.18);
                        padding: 14px;
                        display: flex;
                        flex-direction: column;
                        gap: 12px;
                        position: relative;
                        z-index: 1;
                        -webkit-overflow-scrolling: touch;
                    ">
                        <div class="verigate-header" style="display:flex; align-items:center; justify-content:space-between; flex-wrap: wrap; gap: 8px;">
                            <div class="verigate-title" style="font-weight:700; font-size:13px; color:#2b3035;">VeriGate CAPTCHA</div>
                            <div class="verigate-header-actions" style="display:flex; align-items:center; gap:6px;">
                                <button type="button" id="${containerId}-theme-dark" class="verigate-pill active" style="
                                    border: 1px solid var(--verigate-border-light);
                                    background: #eef1f4;
                                    color: #4a4f55;
                                    font-size: 11px;
                                    border-radius: 999px;
                                    padding: 2px 8px;
                                    cursor: pointer;
                                    touch-action: manipulation;
                                ">Escuro</button>
                                <button type="button" id="${containerId}-theme-light" class="verigate-pill" style="
                                    border: 1px solid var(--verigate-border-light);
                                    background: #eef1f4;
                                    color: #4a4f55;
                                    font-size: 11px;
                                    border-radius: 999px;
                                    padding: 2px 8px;
                                    cursor: pointer;
                                    touch-action: manipulation;
                                ">Claro</button>
                                <button type="button" id="${containerId}-close-btn" class="verigate-btn" style="
                                    border: 1px solid var(--verigate-border-light);
                                    background: #ffffff;
                                    color: #2b3035;
                                    font-size: 12px;
                                    border-radius: 6px;
                                    padding: 4px 8px;
                                    cursor: pointer;
                                    touch-action: manipulation;
                                ">Fechar</button>
                            </div>
                        </div>
                        
                        <div class="verigate-subtle" style="display:flex; align-items:center; justify-content:space-between; font-size:12px; color:#4a4f55; flex-wrap: wrap; gap: 4px;">
                            <div id="${containerId}-status">Carregando…</div>
                            <span id="${containerId}-timer" class="verigate-pill" style="
                                display: none;
                                padding: 2px 8px;
                                border-radius: 999px;
                                background: #eef1f4;
                                border: 1px solid #d8dde3;
                                color: #5a6067;
                            "></span>
                        </div>
                        
                        <div id="${containerId}-canvas-container" class="captcha-container verigate-panel" style="
                            display: none;
                            padding: 6px;
                            background: #ffffff;
                            border-radius: 6px;
                            border: 1px solid #d7dbe0;
                            box-shadow: inset 0 1px 2px rgba(10,23,42,0.06);
                            width: 100%;
                            overflow: hidden;
                            touch-action: none;
                        ">
                            <canvas id="${containerId}-canvas" style="width: 100%; height: auto; display: block;"></canvas>
                        </div>
                        
                        <div id="${containerId}-loading" class="verigate-subtle" style="display:none; font-size:12px; color:#5b6168; text-align: center; padding: 20px;">Carregando desafio…</div>
                        
                        <div class="verigate-subtle" style="font-size:12px; color:#5b6168; text-align: center;">
                            Arraste a peça até o alvo${state.isMobile ? ' com o dedo' : ''}.
                        </div>
                        
                        <div id="${containerId}-result" style="font-size:12px; min-height:18px; color:#4b5258; text-align: center; padding: 4px 0;" aria-live="polite"></div>
                        
                        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap: wrap; gap: 8px;">
                            <button type="button" id="${containerId}-start-btn" class="verigate-btn" style="
                                border: 1px solid #bcd0f8;
                                background: #e7f0ff;
                                color: #0a58ca;
                                font-size: 12px;
                                border-radius: 6px;
                                padding: 8px 16px;
                                cursor: pointer;
                                flex: 1;
                                min-width: 140px;
                                touch-action: manipulation;
                                -webkit-tap-highlight-color: transparent;
                            " disabled>Iniciar CAPTCHA</button>
                            <div id="${containerId}-error" style="display:none; color:#842029; font-size:12px; flex: 1; text-align: center;"></div>
                        </div>
                    </div>
                </div>
                
                <input type="hidden" id="${containerId}-challenge-id">
            `;

            // Referências aos elementos
            state.canvasContainer = document.getElementById(containerId + '-canvas-container');
            state.canvas = document.getElementById(containerId + '-canvas');
            state.ctx = state.canvas.getContext('2d');
            state.captchaLoading = document.getElementById(containerId + '-loading');
            state.captchaError = document.getElementById(containerId + '-error');
            state.startCaptchaBtn = document.getElementById(containerId + '-start-btn');
            state.captchaTimerDisplay = document.getElementById(containerId + '-timer');
            state.challengeIdInput = document.getElementById(containerId + '-challenge-id');
            state.captchaStatus = document.getElementById(containerId + '-status');
            state.captchaResult = document.getElementById(containerId + '-result');
            state.modal = document.getElementById(containerId + '-modal');
            state.openBtn = document.getElementById(containerId + '-open-btn');
            state.closeBtn = document.getElementById(containerId + '-close-btn');
            state.modalCard = document.getElementById(containerId + '-card');
            state.themeDarkBtn = document.getElementById(containerId + '-theme-dark');
            state.themeLightBtn = document.getElementById(containerId + '-theme-light');
            state.theme = options.theme || 'dark';
            state.badge = state.openBtn;
            state.badgeState = 'idle';
            state.badgeBlockReason = '';
            state.successCallback = successCallback;
            state.errorCallback = errorCallback;
            state.formToBind = formToBind;
            state.formSubmitBtn = state.formToBind ? state.formToBind.querySelector('button[type="submit"], input[type="submit"]') : null;
            
            if (state.formSubmitBtn) {
                state.formSubmitBtn.disabled = true;
            }

            // Event Listeners
            state.startCaptchaBtn.addEventListener('click', (e) => {
                if (state.isMobile) preventDefaultTouch(e);
                if (state.startCaptchaBtn.classList.contains('btn-danger') || state.startCaptchaBtn.textContent === 'Recarregar CAPTCHA') {
                    this._loadCaptcha();
                } else {
                    this._startChallenge();
                }
            });

            const applyTheme = (theme) => {
                state.theme = theme;
                if (state.modalCard) {
                    state.modalCard.classList.toggle('verigate-theme-dark', theme === 'dark');
                }
                if (state.themeDarkBtn) state.themeDarkBtn.classList.toggle('active', theme === 'dark');
                if (state.themeLightBtn) state.themeLightBtn.classList.toggle('active', theme === 'light');
            };

            const openModal = () => {
                if (state.modalOpen) return;
                
                state.modalOpen = true;
                state.modal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
                document.documentElement.style.overflow = 'hidden';
                
                // Prevenir rolagem do corpo em mobile
                if (state.isMobile) {
                    document.body.style.position = 'fixed';
                    document.body.style.width = '100%';
                    document.body.style.height = '100%';
                }
                
                requestAnimationFrame(() => {
                    state.modal.classList.add('verigate-modal-open');
                });
            };

            const closeModal = () => {
                if (!state.modalOpen) return;
                
                state.modalOpen = false;
                state.modal.classList.remove('verigate-modal-open');
                state.modal.classList.add('verigate-modal-exit');
                
                setTimeout(() => {
                    state.modal.style.display = 'none';
                    state.modal.classList.remove('verigate-modal-exit');
                    document.body.style.overflow = '';
                    document.documentElement.style.overflow = '';
                    
                    if (state.isMobile) {
                        document.body.style.position = '';
                        document.body.style.width = '';
                        document.body.style.height = '';
                    }
                }, 360);
            };

            state.closeModal = closeModal;

            applyTheme(state.theme);

            state.openBtn.addEventListener('click', (e) => {
                if (state.isMobile) preventDefaultTouch(e);
                if (state.openBtn.disabled) {
                    if (state.badgeBlockReason) {
                        alert(state.badgeBlockReason);
                    }
                    return;
                }
                openModal();
            });

            state.closeBtn.addEventListener('click', (e) => {
                if (state.isMobile) preventDefaultTouch(e);
                closeModal();
            });

            // Melhorar eventos de toque para mobile
            state.modal.addEventListener('touchmove', (e) => {
                if (state.modal.classList.contains('verigate-modal-open')) {
                    e.preventDefault();
                }
            }, { passive: false });

            // Prevenir rolagem acidental no modal
            state.modalCard.addEventListener('touchmove', (e) => {
                if (state.modalOpen && e.target === state.modalCard) {
                    e.preventDefault();
                }
            }, { passive: false });

            // Redimensionamento responsivo
            window.addEventListener('resize', () => {
                if (state.canvas && state.canvas.width && state.canvas.height) {
                    this._drawScene();
                }
            });

            // Suporte a orientação
            window.addEventListener('orientationchange', () => {
                setTimeout(() => {
                    if (state.canvas && state.canvas.width && state.canvas.height) {
                        this._drawScene();
                    }
                }, 100);
            });

            if (state.themeDarkBtn) {
                state.themeDarkBtn.addEventListener('click', (e) => {
                    if (state.isMobile) preventDefaultTouch(e);
                    applyTheme('dark');
                });
            }
            if (state.themeLightBtn) {
                state.themeLightBtn.addEventListener('click', (e) => {
                    if (state.isMobile) preventDefaultTouch(e);
                    applyTheme('light');
                });
            }

            if (state.formToBind) {
                state.formToBind.addEventListener('submit', (e) => {
                    if (!state.captchaToken) {
                        e.preventDefault();
                        this._showCaptchaError('Por favor, complete o CAPTCHA antes de enviar o formulário.');
                    } else {
                        let tokenInput = state.formToBind.querySelector('input[name="captchaToken"]');
                        if (!tokenInput) {
                            tokenInput = document.createElement('input');
                            tokenInput.type = 'hidden';
                            tokenInput.name = 'captchaToken';
                            state.formToBind.appendChild(tokenInput);
                        }
                        tokenInput.value = state.captchaToken;
                    }
                });
            }

            this._attachCanvasEvents();
            this._loadCaptcha();
        },

        _attachCanvasEvents: function() {
            const state = this._captchaState;
            const canvas = state.canvas;

            // Eventos para mouse/touch unificados
            const handleStart = (e) => {
                if (!state.interactionEnabled) return;
                
                const clientX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
                const clientY = e.type.includes('touch') ? e.touches[0].clientY : e.clientY;
                
                const pos = getPointerPosition(canvas, clientX, clientY);
                if (
                    pos.x >= state.pieceX && pos.x <= state.pieceX + state.overlaySize &&
                    pos.y >= state.pieceY && pos.y <= state.pieceY + state.overlaySize
                ) {
                    state.dragging = true;
                    state.dragOffsetX = pos.x - state.pieceX;
                    state.dragOffsetY = pos.y - state.pieceY;
                    state.movementData = [{ x: pos.x, y: pos.y, timestamp: Date.now() }];
                    state.lastMovementSend = Date.now();
                    state.movePixelDistance = 0;
                    state.lastMovePoint = { x: pos.x, y: pos.y };
                    
                    if (state.isMobile) {
                        e.preventDefault();
                        state.touchActive = true;
                        state.currentTouchId = e.type.includes('touch') ? e.touches[0].identifier : null;
                    }
                }
            };

            const handleMove = (e) => {
                if (!state.dragging) return;
                
                const clientX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
                const clientY = e.type.includes('touch') ? e.touches[0].clientY : e.clientY;
                
                e.preventDefault();
                const pos = getPointerPosition(canvas, clientX, clientY);
                state.pieceX = clamp(pos.x - state.dragOffsetX, 0, state.canvasWidth - state.overlaySize);
                state.pieceY = clamp(pos.y - state.dragOffsetY, 0, state.canvasHeight - state.overlaySize);
                state.movementData.push({ x: pos.x, y: pos.y, timestamp: Date.now() });
                
                if (state.lastMovePoint) {
                    const dx = pos.x - state.lastMovePoint.x;
                    const dy = pos.y - state.lastMovePoint.y;
                    state.movePixelDistance += Math.sqrt(dx * dx + dy * dy);
                }
                state.lastMovePoint = { x: pos.x, y: pos.y };
                this._maybeSendMovementBatch(false);
                this._drawScene();
            };

            const handleEnd = async (e) => {
                if (!state.dragging) return;
                
                state.dragging = false;
                state.interactionEnabled = false;
                state.touchActive = false;
                
                if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);

                const clientX = e.type.includes('touch') ? e.changedTouches[0].clientX : e.clientX;
                const clientY = e.type.includes('touch') ? e.changedTouches[0].clientY : e.clientY;
                
                const pos = getPointerPosition(canvas, clientX, clientY);
                state.movementData.push({ x: pos.x, y: pos.y, timestamp: Date.now() });

                const finalX = state.pieceX + state.overlaySize / 2;
                const finalY = state.pieceY + state.overlaySize / 2;
                state.focusOnPiece = true;
                this._drawScene();

                try {
                    await this._maybeSendMovementBatch(true);
                    const image = state.canvas.toDataURL('image/png');
                    const response = await fetch(state.serverUrl + '/captcha/verify', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            finalX: finalX,
                            finalY: finalY,
                            challengeId: state.currentChallengeId,
                            image: image
                        })
                    });

                    const result = await response.json();
                    state.pendingResult = result;
                    if (state.captchaStatus) state.captchaStatus.textContent = 'Analisando…';
                    if (state.captchaResult) state.captchaResult.textContent = 'Validando movimento…';
                    state.resultTimer = setTimeout(() => {
                        this._applyResult();
                    }, 3000);
                } catch (error) {
                    this._showCaptchaError('Erro de comunicação com o servidor CAPTCHA.');
                }
            };

            // Mouse events
            canvas.addEventListener('mousedown', handleStart);
            canvas.addEventListener('mousemove', handleMove);
            canvas.addEventListener('mouseup', handleEnd);
            canvas.addEventListener('mouseleave', handleEnd);

            // Touch events com suporte a múltiplos toques
            canvas.addEventListener('touchstart', handleStart, { passive: false });
            canvas.addEventListener('touchmove', handleMove, { passive: false });
            canvas.addEventListener('touchend', handleEnd, { passive: false });
            canvas.addEventListener('touchcancel', handleEnd, { passive: false });

            // Prevenir comportamento padrão do touch
            canvas.addEventListener('touchstart', preventDefaultTouch, { passive: false });
            canvas.addEventListener('touchmove', preventDefaultTouch, { passive: false });
        },

        _maybeSendMovementBatch: async function(force) {
            const state = this._captchaState;
            if (!state.currentChallengeId) return;
            
            const now = Date.now();
            const shouldSendByTime = (now - state.lastMovementSend) >= state.movementSendIntervalMs;
            const shouldSendByDistance = state.movePixelDistance >= state.movementSendPixelThreshold;
            
            if (!force && !shouldSendByTime && !shouldSendByDistance) return;
            
            if (state.moveSendInFlight) {
                if (force) {
                    await state.moveSendInFlight;
                } else {
                    return;
                }
            }
            
            state.movePixelDistance = 0;
            state.lastMovementSend = now;
            const image = state.canvas.toDataURL('image/png');
            
            state.moveSendInFlight = fetch(state.serverUrl + '/captcha/move', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    challengeId: state.currentChallengeId,
                    image: image
                })
            }).then(async (res) => {
                if (!res.ok) {
                    let msg = 'Movimento inválido.';
                    try {
                        const data = await res.json();
                        msg = data && data.message ? data.message : msg;
                    } catch (e) {}
                    this._showCaptchaError(msg);
                }
            }).catch(() => {}).finally(() => {
                state.moveSendInFlight = null;
            });
            
            if (force) {
                await state.moveSendInFlight;
            }
        },

        _showCaptchaError: function(message) {
            const state = this._captchaState;
            state.captchaError.textContent = message;
            state.captchaError.style.display = 'block';
            state.captchaTimerDisplay.style.display = 'none';
            state.startCaptchaBtn.textContent = 'Recarregar CAPTCHA';
            state.startCaptchaBtn.disabled = false;
            state.startCaptchaBtn.style.display = 'inline-block';
            state.canvasContainer.style.display = 'none';
            state.interactionEnabled = false;
            
            if (state.captchaStatus) state.captchaStatus.textContent = 'Erro';
            if (state.captchaResult) {
                const msg = message || 'Movimentação suspeita';
                state.captchaResult.innerHTML = `<span class="verigate-result verigate-result-error"><span class="verigate-result-icon">✖</span><span>${msg}</span></span>`;
            }
            
            if (state.modalCard) {
                state.modalCard.classList.remove('verigate-card-success');
                state.modalCard.classList.add('verigate-card-error', 'verigate-shake');
            }
            
            if (state.badge) {
                state.badge.disabled = true;
                state.badge.style.cursor = 'not-allowed';
                state.badge.style.background = '#fdecec';
                state.badge.style.borderColor = '#f1aeb5';
                state.badge.style.color = '#842029';
                state.badgeState = 'error';
                state.badgeBlockReason = message || 'Movimentação suspeita';
                state.badge.innerHTML = `
                    <span style="
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                        width: 16px;
                        height: 16px;
                        border-radius: 50%;
                        background: #842029;
                        color: #fff;
                        font-size: 10px;
                        font-weight: 700;
                    ">✖</span>
                    VeriGate CAPTCHA
                `;
            }
            
            if (state.resultTimer) clearTimeout(state.resultTimer);
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);
            if (state.errorCallback) state.errorCallback(message);
            if (state.formSubmitBtn) state.formSubmitBtn.disabled = true;
            
            if (state.modalCard) {
                setTimeout(() => state.modalCard.classList.remove('verigate-shake'), 500);
            }
        },

        _startTimer: function() {
            const state = this._captchaState;
            let timeLeft = state.maxChallengeTime;
            state.captchaTimerDisplay.textContent = 'Tempo: ' + timeLeft + 's';
            state.captchaTimerDisplay.style.display = 'inline-block';
            if (state.captchaStatus) state.captchaStatus.textContent = 'Em andamento';

            state.captchaTimerInterval = setInterval(() => {
                timeLeft--;
                if (timeLeft <= 0) {
                    clearInterval(state.captchaTimerInterval);
                    state.captchaTimerDisplay.textContent = 'Tempo esgotado!';
                    state.interactionEnabled = false;
                    this._showCaptchaError('Tempo esgotado. Por favor, recarregue o CAPTCHA.');
                } else {
                    state.captchaTimerDisplay.textContent = 'Tempo: ' + timeLeft + 's';
                }
            }, 1000);
        },

        _loadCaptcha: async function() {
            const state = this._captchaState;
            state.captchaError.style.display = 'none';
            state.startCaptchaBtn.disabled = true;
            state.startCaptchaBtn.textContent = 'Aguarde...';
            state.startCaptchaBtn.classList.remove('btn-danger');
            state.startCaptchaBtn.classList.add('btn-info');
            state.startCaptchaBtn.style.display = 'inline-block';
            state.captchaTimerDisplay.style.display = 'none';
            state.canvasContainer.style.display = 'none';
            state.captchaToken = null;
            state.interactionEnabled = false;
            
            if (state.captchaStatus) state.captchaStatus.textContent = 'Carregando…';
            if (state.captchaResult) state.captchaResult.textContent = '';
            if (state.modalCard) {
                state.modalCard.classList.remove('verigate-card-error', 'verigate-card-success');
            }
            
            state.captchaError.style.display = 'none';
            state.focusOnPiece = false;
            state.pendingResult = null;
            if (state.resultTimer) clearTimeout(state.resultTimer);
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);
            if (state.formSubmitBtn) state.formSubmitBtn.disabled = true;

            state.captchaLoading.style.display = 'block';

            try {
                const response = await fetch(state.serverUrl + '/captcha/generate');
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.reason || 'Falha ao carregar o CAPTCHA.');
                }
                
                const { image, challengeId, maxTime, width, height, pieceSize, pieceColor, tokenExpirationMinutes, targetShape, overlayScale } = await response.json();

                state.captchaLoading.style.display = 'none';

                state.currentChallengeId = challengeId;
                state.challengeIdInput.value = challengeId;
                state.maxChallengeTime = maxTime;
                state.tokenExpirationMinutes = tokenExpirationMinutes || state.tokenExpirationMinutes;
                
                // Ajustar dimensões para mobile
                let finalWidth = width;
                let finalHeight = height;
                
                if (state.isMobile && width > MOBILE_CONFIG.canvasMaxWidth) {
                    const scale = MOBILE_CONFIG.canvasMaxWidth / width;
                    finalWidth = MOBILE_CONFIG.canvasMaxWidth;
                    finalHeight = Math.round(height * scale);
                }
                
                state.canvasWidth = finalWidth;
                state.canvasHeight = finalHeight;
                state.pieceSize = pieceSize * (state.isMobile ? MOBILE_CONFIG.pieceSizeMultiplier : 1);
                state.targetShape = targetShape || state.targetShape;
                state.overlayScale = overlayScale || state.overlayScale;
                state.overlaySize = Math.max(20, Math.round(state.pieceSize * state.overlayScale));
                state.pieceColor = pieceColor || state.pieceColor;
                state.movementData = [];
                state.lastMovementSend = 0;
                state.movePixelDistance = 0;
                state.lastMovePoint = null;
                state.focusOnPiece = false;
                state.pendingResult = null;
                
                if (state.resultTimer) clearTimeout(state.resultTimer);

                state.canvas.width = finalWidth;
                state.canvas.height = finalHeight;
                
                // Melhorar qualidade de renderização em mobile
                if (state.isMobile) {
                    state.canvas.style.imageRendering = 'crisp-edges';
                }

                const img = new Image();
                img.onload = () => {
                    state.backgroundImage = img;
                    state.pieceX = Math.floor((finalWidth - state.overlaySize) * 0.1);
                    state.pieceY = Math.floor((finalHeight - state.overlaySize) * 0.5);
                    this._drawScene();
                    if (state.captchaStatus) state.captchaStatus.textContent = 'Pronto';
                    state.startCaptchaBtn.textContent = 'Iniciar CAPTCHA';
                    state.startCaptchaBtn.disabled = false;
                    state.canvasContainer.style.display = 'block';
                };
                img.onerror = () => {
                    state.captchaLoading.style.display = 'none';
                    this._showCaptchaError('Falha ao carregar imagem do CAPTCHA.');
                };
                img.src = image;
            } catch (error) {
                state.captchaLoading.style.display = 'none';
                this._showCaptchaError(error.message);
            }
        },

        _startChallenge: async function() {
            const state = this._captchaState;
            state.startCaptchaBtn.disabled = true;
            state.startCaptchaBtn.textContent = 'Iniciando...';
            state.captchaError.style.display = 'none';
            state.captchaToken = null;

            try {
                const response = await fetch(state.serverUrl + '/captcha/start-challenge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ challengeId: state.currentChallengeId })
                });

                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.message || 'Falha ao iniciar o desafio.');
                }

                state.interactionEnabled = true;
                state.startCaptchaBtn.style.display = 'none';
                this._startTimer();
            } catch (error) {
                this._showCaptchaError(error.message);
                state.startCaptchaBtn.textContent = 'Tentar Novamente';
                state.startCaptchaBtn.disabled = false;
                state.startCaptchaBtn.style.display = 'inline-block';
            }
        },

        _drawScene: function() {
            const state = this._captchaState;
            if (!state.backgroundImage || !state.ctx) return;
            
            // Limpar canvas
            state.ctx.clearRect(0, 0, state.canvasWidth, state.canvasHeight);
            
            // Desenhar imagem de fundo com blur
            state.ctx.filter = 'blur(1.6px)';
            state.ctx.drawImage(state.backgroundImage, 0, 0, state.canvasWidth, state.canvasHeight);
            state.ctx.filter = 'none';
            
            // Overlay sutil
            state.ctx.fillStyle = 'rgba(255,255,255,0.04)';
            state.ctx.fillRect(0, 0, state.canvasWidth, state.canvasHeight);
            
            // Cor da peça
            state.ctx.fillStyle = state.pieceColor;
            state.ctx.strokeStyle = '#0a58ca';
            state.ctx.lineWidth = state.isMobile ? 2 : 1;
            
            const size = state.overlaySize || state.pieceSize;
            
            // Efeito de foco
            if (state.focusOnPiece) {
                state.ctx.save();
                state.ctx.fillStyle = 'rgba(0,0,0,0.45)';
                state.ctx.fillRect(0, 0, state.canvasWidth, state.canvasHeight);
                state.ctx.globalCompositeOperation = 'destination-out';
                state.ctx.fillStyle = 'rgba(0,0,0,1)';
                state.ctx.fillRect(
                    Math.max(0, state.pieceX - state.focusPadding),
                    Math.max(0, state.pieceY - state.focusPadding),
                    Math.min(state.canvasWidth, size + state.focusPadding * 2),
                    Math.min(state.canvasHeight, size + state.focusPadding * 2)
                );
                state.ctx.restore();
            }
            
            // Desenhar peça baseado na forma
            if (state.targetShape === 'circle') {
                const radius = size / 2;
                const cx = state.pieceX + radius;
                const cy = state.pieceY + radius;
                state.ctx.beginPath();
                state.ctx.arc(cx, cy, radius, 0, Math.PI * 2);
                state.ctx.fill();
                state.ctx.stroke();
            } else if (state.targetShape === 'rounded') {
                const radius = Math.max(6, Math.floor(size / 5));
                const x = state.pieceX;
                const y = state.pieceY;
                const w = size;
                const h = size;
                state.ctx.beginPath();
                state.ctx.moveTo(x + radius, y);
                state.ctx.arcTo(x + w, y, x + w, y + h, radius);
                state.ctx.arcTo(x + w, y + h, x, y + h, radius);
                state.ctx.arcTo(x, y + h, x, y, radius);
                state.ctx.arcTo(x, y, x + w, y, radius);
                state.ctx.closePath();
                state.ctx.fill();
                state.ctx.stroke();
            } else {
                state.ctx.fillRect(state.pieceX, state.pieceY, size, size);
                state.ctx.strokeRect(state.pieceX, state.pieceY, size, size);
            }
        },

        _applyResult: function() {
            const state = this._captchaState;
            if (!state.pendingResult) return;
            
            const result = state.pendingResult;
            state.pendingResult = null;
            
            if (result.success) {
                state.captchaToken = result.token;
                const maxAge = (state.tokenExpirationMinutes || 60) * 60;
                const secure = window.location && window.location.protocol === 'https:' ? '; Secure' : '';
                document.cookie = CAPTCHA_COOKIE_NAME + '=' + encodeURIComponent(result.token) + '; Max-Age=' + maxAge + '; Path=/; SameSite=Lax' + secure;
                
                state.captchaTimerDisplay.textContent = 'CAPTCHA Válido!';
                if (state.captchaStatus) state.captchaStatus.textContent = 'CAPTCHA resolvido';
                if (state.captchaResult) {
                    state.captchaResult.innerHTML = '<span class="verigate-result verigate-result-success"><span class="verigate-result-icon">✔</span><span>Captcha resolvido</span></span>';
                }
                
                if (state.modalCard) {
                    state.modalCard.classList.remove('verigate-card-error');
                    state.modalCard.classList.add('verigate-card-success');
                }
                
                if (state.badge) {
                    state.badge.disabled = true;
                    state.badge.style.cursor = 'not-allowed';
                    state.badge.style.background = '#e6f4ea';
                    state.badge.style.borderColor = '#b7dfc3';
                    state.badge.style.color = '#0f5132';
                    state.badgeState = 'success';
                    state.badgeBlockReason = 'Captcha já resolvido.';
                    state.badge.innerHTML = `
                        <span style="
                            display: inline-flex;
                            align-items: center;
                            justify-content: center;
                            width: 16px;
                            height: 16px;
                            border-radius: 50%;
                            background: #0f5132;
                            color: #fff;
                            font-size: 10px;
                            font-weight: 700;
                        ">✔</span>
                        VeriGate CAPTCHA
                    `;
                }
                
                if (state.successCallback) state.successCallback(result.token);
                if (state.formSubmitBtn) state.formSubmitBtn.disabled = false;
                
                if (typeof state.closeModal === 'function') {
                    setTimeout(() => state.closeModal(), 700);
                }
            } else {
                this._showCaptchaError(result.message || 'Movimentação suspeita.');
            }
        }
    };
})();
