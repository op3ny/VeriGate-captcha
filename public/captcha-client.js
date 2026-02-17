
(function() {
    const DEFAULT_SERVER_URL = "https://captcha.hsyst.org";
    const scriptTag = document.currentScript || document.querySelector('script[data-verigate]');
    const CAPTCHA_SERVER_URL = (scriptTag && scriptTag.getAttribute('data-server-url')) || window.VeriGateCaptchaServer || DEFAULT_SERVER_URL;
    const CAPTCHA_COOKIE_NAME = "verigate_captcha_token";

    window.VeriGateCaptcha = {
        _captchaState: {
            captchaContainer: null,
            captchaLoading: null,
            captchaError: null,
            startCaptchaBtn: null,
            captchaTimerDisplay: null,
            finalXInput: null,
            finalYInput: null,
            challengeIdInput: null,
            formSubmitBtn: null, // Opcional, para desabilitar o submit enquanto CAPTCHA não está pronto

            dragItem: null,
            currentChallengeId: null,
            active: false,
            currentX: 0, currentY: 0, initialX: 0, initialY: 0,
            xOffset: 0, yOffset: 0,
            captchaTimerInterval: null,
            maxChallengeTime: 0,
            movementData: [] // Armazenar dados de movimento
        },

        init: function(containerId, successCallback, errorCallback, formToBind = null, options = {}) {
            const state = this._captchaState;
            state.serverUrl = options.serverUrl || CAPTCHA_SERVER_URL;
            state.captchaContainer = document.getElementById(containerId);
            if (!state.captchaContainer) {
                console.error("VeriGateCaptcha: Container DIV com ID '" + containerId + "' não encontrado.");
                return;
            }

            state.captchaContainer.innerHTML = `
                <div id="${containerId}-display" class="border rounded p-2 mb-2" style="min-height: 170px; display: flex; justify-content: center; align-items: center; flex-direction: column;">
                    <div id="${containerId}-svg-container" class="captcha-container">
                        <!-- CAPTCHA SVG será carregado aqui -->
                    </div>
                    <div id="${containerId}-loading" class="spinner-border text-primary" role="status" style="display: none;">
                        <span class="visually-hidden">Carregando...</span>
                    </div>
                </div>
                <div id="${containerId}-info" class="d-flex justify-content-between align-items-center mb-2">
                    <button type="button" id="${containerId}-start-btn" class="btn btn-sm btn-info" disabled>Iniciar CAPTCHA</button>
                    <span id="${containerId}-timer" class="badge bg-secondary" style="display: none;"></span>
                </div>
                <div id="${containerId}-error" class="text-danger mt-1" style="display: none;"></div>
                <input type="hidden" id="${containerId}-x">
                <input type="hidden" id="${containerId}-y">
                <input type="hidden" id="${containerId}-challenge-id">
            `;


            // Atribuir elementos ao estado
            state.captchaSvgContainer = document.getElementById(containerId + '-svg-container');
            state.captchaLoading = document.getElementById(containerId + '-loading');
            state.captchaError = document.getElementById(containerId + '-error');
            state.startCaptchaBtn = document.getElementById(containerId + '-start-btn');
            state.captchaTimerDisplay = document.getElementById(containerId + '-timer');
            state.finalXInput = document.getElementById(containerId + '-x');
            state.finalYInput = document.getElementById(containerId + '-y');
            state.challengeIdInput = document.getElementById(containerId + '-challenge-id');
            state.successCallback = successCallback;
            state.errorCallback = errorCallback;
            state.formToBind = formToBind; // O formulário a ser "protegido"
            state.formSubmitBtn = state.formToBind ? state.formToBind.querySelector('button[type="submit"], input[type="submit"]') : null;
            if (state.formSubmitBtn) {
                state.formSubmitBtn.disabled = true;
            }

            // Ocultar o container do SVG inicialmente
            state.captchaSvgContainer.style.display = 'none';

            // Evento para o botão Iniciar/Recarregar
            state.startCaptchaBtn.addEventListener('click', () => {
                if (state.startCaptchaBtn.classList.contains('btn-danger') || state.startCaptchaBtn.textContent === 'Recarregar CAPTCHA') {
                    this._loadCaptcha(); // Recarrega se estiver em estado de erro
                } else {
                    this._startChallenge(); // Inicia o desafio
                }
            });

            // Se um formulário foi fornecido, previne o submit antes do CAPTCHA
            if (state.formToBind) {
                state.formToBind.addEventListener('submit', (e) => {
                    if (!state.captchaToken) { // Se o token não estiver presente
                        e.preventDefault();
                        this._showCaptchaError('Por favor, complete o CAPTCHA antes de enviar o formulário.');
                    } else {
                        // Anexa/atualiza o token ao formulário antes de submit
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

            this._loadCaptcha(); // Carrega o primeiro CAPTCHA
        },

        _showCaptchaError: function(message) {
            const state = this._captchaState;
            state.captchaError.textContent = message;
            state.captchaError.style.display = 'block';
            state.captchaTimerDisplay.style.display = 'none';
            state.startCaptchaBtn.textContent = 'Recarregar CAPTCHA';
            state.startCaptchaBtn.classList.remove('btn-info');
            state.startCaptchaBtn.classList.add('btn-danger');
            state.startCaptchaBtn.disabled = false;
            state.captchaSvgContainer.style.display = 'none'; // Esconde o SVG em caso de erro
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);
            if (state.errorCallback) state.errorCallback(message);
            if (state.formSubmitBtn) state.formSubmitBtn.disabled = true;
        },

        _startTimer: function() {
            const state = this._captchaState;
            let timeLeft = state.maxChallengeTime;
            state.captchaTimerDisplay.textContent = 'Tempo restante: ' + timeLeft + 's';
            state.captchaTimerDisplay.style.display = 'inline-block';
            
            state.captchaTimerInterval = setInterval(() => {
                timeLeft--;
                if (timeLeft <= 0) {
                    clearInterval(state.captchaTimerInterval);
                    state.captchaTimerDisplay.textContent = 'Tempo esgotado!';
                    this._showCaptchaError('Tempo esgotado. Por favor, recarregue o CAPTCHA.');
                    if (state.dragItem) state.dragItem.style.pointerEvents = 'none';
                } else {
                    state.captchaTimerDisplay.textContent = 'Tempo restante: ' + timeLeft + 's';
                }
            }, 1000);
        },

        _loadCaptcha: async function() {
            const state = this._captchaState;
            state.captchaSvgContainer.innerHTML = '';
            state.captchaError.style.display = 'none';
            state.startCaptchaBtn.disabled = true;
            state.startCaptchaBtn.textContent = 'Aguarde...';
            state.startCaptchaBtn.classList.remove('btn-danger');
            state.startCaptchaBtn.classList.add('btn-info');
            state.captchaTimerDisplay.style.display = 'none';
            state.captchaSvgContainer.style.display = 'none';
            state.captchaToken = null; // Limpa qualquer token anterior
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval);
            if (state.formSubmitBtn) state.formSubmitBtn.disabled = true;

            state.captchaLoading.style.display = 'block';

            try {
                const response = await fetch(state.serverUrl + '/captcha/generate');
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.reason || 'Falha ao carregar o CAPTCHA.');
                }
                const { svg, pieceId, challengeId, maxTime } = await response.json();
                
                state.captchaLoading.style.display = 'none';
                state.captchaSvgContainer.innerHTML = svg;

                state.dragItem = document.getElementById(pieceId);
                state.currentChallengeId = challengeId;
                state.challengeIdInput.value = challengeId;
                state.maxChallengeTime = maxTime;

                if (!state.dragItem) {
                    throw new Error('Elemento arrastável do CAPTCHA não encontrado.');
                }
                
                state.dragItem.style.pointerEvents = 'none'; // Desabilitar drag inicialmente
                state.startCaptchaBtn.textContent = 'Iniciar CAPTCHA';
                state.startCaptchaBtn.disabled = false;
                state.captchaSvgContainer.style.display = 'block'; // Exibe o SVG
                state.movementData = []; // Zera dados de movimento
                
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
            state.captchaToken = null; // Garante que não haja token antigo

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

                state.dragItem.style.pointerEvents = 'auto';
                state.dragItem.style.cursor = 'grab';
                state.startCaptchaBtn.style.display = 'none'; // Esconder o botão iniciar
                this._startTimer();

                // Adicionar listeners para drag-and-drop
                state.captchaSvgContainer.addEventListener('mousedown', this._dragStart.bind(this), false);
                state.captchaSvgContainer.addEventListener('mouseup', this._dragEnd.bind(this), false);
                state.captchaSvgContainer.addEventListener('mousemove', this._drag.bind(this), false);

                state.captchaSvgContainer.addEventListener('touchstart', this._dragStart.bind(this), { passive: false });
                state.captchaSvgContainer.addEventListener('touchend', this._dragEnd.bind(this), false);
                state.captchaSvgContainer.addEventListener('touchmove', this._drag.bind(this), { passive: false });

            } catch (error) {
                this._showCaptchaError(error.message);
                state.startCaptchaBtn.textContent = 'Tentar Novamente';
                state.startCaptchaBtn.disabled = false;
                state.startCaptchaBtn.style.display = 'inline-block';
            }
        },

        _dragStart: function(e) {
            const state = this._captchaState;
            if (e.target === state.dragItem) {
                if (e.type === 'touchstart') {
                    state.initialX = e.touches[0].clientX - state.xOffset;
                    state.initialY = e.touches[0].clientY - state.yOffset;
                } else {
                    state.initialX = e.clientX - state.xOffset;
                    state.initialY = e.clientY - state.yOffset;
                }
                state.active = true;
                state.dragItem.style.cursor = 'grabbing';
                state.movementData = [{x: e.clientX, y: e.clientY, timestamp: Date.now()}]; // Inicia coleta
            }
        },

        _dragEnd: async function(e) {
            const state = this._captchaState;
            if (!state.active) return;
            state.initialX = state.currentX;
            state.initialY = state.currentY;
            state.active = false;
            state.dragItem.style.cursor = 'grab';
            state.dragItem.style.pointerEvents = 'none'; // Desabilita interação após soltar
            if (state.captchaTimerInterval) clearInterval(state.captchaTimerInterval); // Para o timer

            state.movementData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()}); // Finaliza coleta

            const svgElement = state.captchaSvgContainer.querySelector('svg');
            if (!svgElement) return;

            const svgRect = svgElement.getBoundingClientRect();
            const dragRect = state.dragItem.getBoundingClientRect();

            const finalX = dragRect.left - svgRect.left + (dragRect.width / 2);
            const finalY = dragRect.top - svgRect.top + (dragRect.height / 2);

            state.finalXInput.value = finalX;
            state.finalYInput.value = finalY;

            // Enviar para verificação
            try {
                const response = await fetch(state.serverUrl + '/captcha/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        finalX: finalX,
                        finalY: finalY,
                        challengeId: state.currentChallengeId,
                        movementData: state.movementData // Envia os dados de movimento
                    })
                });

                const result = await response.json();

                if (result.success) {
                    state.captchaToken = result.token;
                    const maxAge = 60 * 60;
                    const secure = window.location && window.location.protocol === 'https:' ? '; Secure' : '';
                    document.cookie = CAPTCHA_COOKIE_NAME + '=' + encodeURIComponent(result.token) + '; Max-Age=' + maxAge + '; Path=/; SameSite=Lax' + secure;
                    state.captchaTimerDisplay.textContent = 'CAPTCHA Válido!';
                    state.captchaTimerDisplay.classList.remove('bg-secondary');
                    state.captchaTimerDisplay.classList.add('bg-success');
                    if (state.successCallback) state.successCallback(result.token);
                    if (state.formSubmitBtn) state.formSubmitBtn.disabled = false;
                } else {
                    this._showCaptchaError(result.message);
                }
            } catch (error) {
                this._showCaptchaError('Erro de comunicação com o servidor CAPTCHA.');
            }
        },

        _drag: function(e) {
            const state = this._captchaState;
            if (state.active) {
                e.preventDefault();
                if (e.type === 'touchmove') {
                    state.currentX = e.touches[0].clientX - state.initialX;
                    state.currentY = e.touches[0].clientY - state.initialY;
                } else {
                    state.currentX = e.clientX - state.initialX;
                    state.currentY = e.clientY - state.initialY;
                }
                state.xOffset = state.currentX;
                state.yOffset = state.currentY;
                this._setTranslate(state.currentX, state.currentY, state.dragItem);
                state.movementData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()}); // Coleta movimento
            }
        },

        _setTranslate: function(xPos, yPos, el) {
            el.style.transform = 'translate3d(' + xPos + 'px, ' + yPos + 'px, 0)';
        }
    };
})();
    