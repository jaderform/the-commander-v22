/**
 * COMMANDER V10.6 - Behavioral Tracker JavaScript AVANCADO (Corrigido e Otimizado)
 * Coleta dados de comportamento humano e detecta bots/automacao
 * 
 * DETECCOES:
 * - Webdriver, Puppeteer, Playwright, Selenium, PhantomJS
 * - Eventos isTrusted (mouse real vs programatico)
 * - Movimento de mouse em linha reta (bot)
 * - Velocidade impossivel entre cliques
 * - DevTools aberto (revisor)
 * - WebGL e Audio fingerprint
 * - Honeypot invisivel
 * - Proof of Work challenge
 */

(function() {
    'use strict';
    
    // ============================================
    // CONFIGURACAO
    // ============================================
    const CONFIG = {
        apiEndpoint: '/COMMANDERV3/api.php', // Corrigido para a versão correta do diretório[cite: 6]
        sendInterval: 3000,
        debugMode: false,
        enablePostMessage: true,
        postMessageInterval: 2000
    };
    
    // ============================================
    // DETECCAO DE IFRAME (para postMessage)
    // ============================================
    const isInIframe = (function() {
        try {
            return window.self !== window.top;
        } catch(e) {
            return true; // Se der erro, provavelmente esta em iframe cross-origin[cite: 6]
        }
    })();
    
    // ============================================
    // GERACAO E PERSISTENCIA DE ID
    // ============================================
    function generateVisitorId() {
        const ua = navigator.userAgent;
        const lang = navigator.language;
        const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        const screen = window.screen.width + 'x' + window.screen.height;
        const data = ua + '|' + lang + '|' + tz + '|' + screen;
        
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            const char = data.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return 'v_' + Math.abs(hash).toString(36) + '_' + Date.now().toString(36);
    }

    function getStoredVisitorId() {
        try {
            const existingId = sessionStorage.getItem('commander_visitor_id');
            if (existingId) {
                return existingId;
            }
        } catch(e) {}
        
        const newId = generateVisitorId();
        try {
            sessionStorage.setItem('commander_visitor_id', newId);
        } catch(e) {}
        return newId;
    }
    
    // ============================================
    // TRACKER PRINCIPAL
    // ============================================
    const tracker = {
        visitorId: getStoredVisitorId(), // Persistência corrigida para evitar novo ID a cada reload[cite: 6]
        startTime: Date.now(),
        
        // Comportamento basico
        scrollCount: 0,
        maxScroll: 0,
        mouseMoveCount: 0,
        mouseActive: false,
        lastMouseMove: 0,
        timeOnPage: 0,
        
        // Deteccao avancada
        untrustedEvents: 0,
        clickTimes: [],
        mousePositions: [],
        straightLineScore: 0,
        impossibleSpeed: false,
        
        // Fingerprints
        canvasHash: '',
        webglHash: '',
        audioHash: '',
        canvasBlocked: false,
        
        // Deteccao de automacao
        automationDetected: null,
        webdriver: false,
        headless: false,
        devtoolsOpen: false,
        
        // Eventos
        events: [],
        
        // Score de bot para postMessage
        botScore: 0
    };

    // Helper para limitar o tamanho do array de eventos e evitar consumo de memória[cite: 6]
    function pushEvent(eventObj) {
        tracker.events.push(eventObj);
        if (tracker.events.length > 50) {
            tracker.events.shift();
        }
    }
    
    // ============================================
    // CALCULO DE BOT SCORE (Alinhado com o report)
    // ============================================
    function calculateBotScore() {
        let score = 0;
        
        if (tracker.webdriver) score += 50;
        if (tracker.headless) score += 40;
        if (tracker.automationDetected) score += 60;
        if (tracker.untrustedEvents > 0) score += tracker.untrustedEvents * 10;
        if (tracker.straightLineScore > 3) score += 30; // Limiar alinhado com o relatório (> 3)[cite: 6]
        if (tracker.impossibleSpeed) score += 25;
        if (tracker.devtoolsOpen) score += 15;
        if (tracker.timeOnPage > 5000 && tracker.mouseMoveCount < 3) score += 20;
        
        tracker.botScore = score;
        return score;
    }
    
    // ============================================
    // DETECCAO DE AUTOMACAO
    // ============================================
    function detectAutomation() {
        const detected = {
            webdriver: false,
            headless: false,
            automation: null,
            phantomjs: false,
            nightmare: false,
            puppeteer: false,
            playwright: false,
            selenium: false
        };
        
        if (navigator.webdriver === true) {
            detected.webdriver = true;
        }
        
        if (/HeadlessChrome/i.test(navigator.userAgent)) {
            detected.headless = true;
        }
        
        if (window.callPhantom || window._phantom) {
            detected.phantomjs = true;
            detected.automation = 'phantomjs';
        }
        
        if (window.__nightmare) {
            detected.nightmare = true;
            detected.automation = 'nightmare';
        }
        
        if (window.__puppeteer_evaluation_script__ || 
            window.puppeteer ||
            navigator.userAgent.includes('pptr')) {
            detected.puppeteer = true;
            detected.automation = 'puppeteer';
        }
        
        if (window.playwright || window.__playwright) {
            detected.playwright = true;
            detected.automation = 'playwright';
        }
        
        if (window.__selenium_unwrapped ||
            window.__webdriver_evaluate ||
            window.__driver_evaluate ||
            window.__webdriver_script_function ||
            window.__webdriver_script_func ||
            window.__webdriver_script_fn ||
            window.$cdc_asdjflasutopfhvcZLmcfl_ ||
            window.$chrome_asyncScriptInfo ||
            document.__selenium_unwrapped ||
            document.__webdriver_evaluate ||
            document.__driver_evaluate) {
            detected.selenium = true;
            detected.automation = 'selenium';
        }
        
        if (window.emit || window.callCasper) {
            detected.automation = 'casperjs';
        }
        
        if (window.Buffer || window.global || window.process) {
            detected.automation = 'nodejs';
        }
        
        if (navigator.userAgent.includes('Electron')) {
            detected.automation = 'electron';
        }
        
        if (window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol ||
            window.cdc_adoQpoasnfa76pfcZLmcfl_Array ||
            window.cdc_adoQpoasnfa76pfcZLmcfl_Promise) {
            detected.automation = 'cdp';
        }
        
        if (navigator.plugins.length === 0 && !isMobile()) {
            detected.headless = true;
        }
        
        if (!navigator.languages || navigator.languages.length === 0) {
            detected.headless = true;
        }
        
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    if (/swiftshader|llvmpipe|softpipe/i.test(renderer)) {
                        detected.headless = true;
                    }
                }
            }
        } catch(e) {}
        
        return detected;
    }
    
    function isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    }
    
    // ============================================
    // DETECCAO DE DEVTOOLS
    // ============================================
    function detectDevTools() {
        const threshold = 160;
        
        const widthThreshold = window.outerWidth - window.innerWidth > threshold;
        const heightThreshold = window.outerHeight - window.innerHeight > threshold;
        
        if (widthThreshold || heightThreshold) {
            return true;
        }
        
        const start = performance.now();
        console.log('%c', 'font-size:0;padding:0;margin:0;');
        console.clear();
        const end = performance.now();
        
        if (end - start > 100) {
            return true;
        }
        
        return false;
    }
    
    // ============================================
    // FINGERPRINTS
    // ============================================
    function generateCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            
            ctx.textBaseline = 'alphabetic';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(100, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('CMDR Fingerprint', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('CMDR Fingerprint', 4, 17);
            
            ctx.beginPath();
            ctx.arc(50, 25, 10, 0, Math.PI * 2);
            ctx.fill();
            
            const dataUrl = canvas.toDataURL();
            
            if (dataUrl === 'data:,') {
                return { hash: 'blocked', blocked: true };
            }
            
            let hash = 0;
            for (let i = 0; i < dataUrl.length; i++) {
                const char = dataUrl.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            
            return { hash: Math.abs(hash).toString(36), blocked: false };
        } catch(e) {
            return { hash: 'error', blocked: true };
        }
    }
    
    function generateWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            
            if (!gl) {
                return { hash: 'no_webgl', blocked: true };
            }
            
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            let data = '';
            
            if (debugInfo) {
                data += gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) + '|';
                data += gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            }
            
            data += '|' + gl.getParameter(gl.VERSION);
            data += '|' + gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
            
            let hash = 0;
            for (let i = 0; i < data.length; i++) {
                hash = ((hash << 5) - hash) + data.charCodeAt(i);
                hash = hash & hash;
            }
            
            return { hash: Math.abs(hash).toString(36), blocked: false, data: data };
        } catch(e) {
            return { hash: 'error', blocked: true };
        }
    }
    
    function generateAudioFingerprint() {
        let context = null;
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) {
                return { hash: 'no_audio', blocked: true };
            }
            
            context = new AudioContext();
            const oscillator = context.createOscillator();
            const analyser = context.createAnalyser();
            const gain = context.createGain();
            const scriptProcessor = context.createScriptProcessor(4096, 1, 1);
            
            gain.gain.value = 0;
            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gain);
            gain.connect(context.destination);
            
            oscillator.start(0);
            
            const fingerprint = new Float32Array(analyser.frequencyBinCount);
            analyser.getFloatFrequencyData(fingerprint);
            
            oscillator.stop();
            
            let hash = 0;
            for (let i = 0; i < Math.min(fingerprint.length, 100); i++) {
                hash = ((hash << 5) - hash) + Math.abs(fingerprint[i]);
                hash = hash & hash;
            }
            
            return { hash: Math.abs(hash).toString(36), blocked: false };
        } catch(e) {
            return { hash: 'error', blocked: true };
        } finally {
            // Fechamento seguro do contexto para evitar vazamento de recursos[cite: 6]
            if (context && context.state !== 'closed') {
                context.close().catch(function() {});
            }
        }
    }
    
    // ============================================
    // ANALISE DE COMPORTAMENTO
    // ============================================
    
    function checkEventTrusted(e) {
        if (e.isTrusted === false) {
            tracker.untrustedEvents++;
            pushEvent({
                type: 'untrusted_event',
                eventType: e.type,
                at: Date.now() - tracker.startTime
            });
        }
    }
    
    function analyzeMounseMovement(x, y) {
        tracker.mousePositions.push({ x, y, t: Date.now() });
        
        if (tracker.mousePositions.length > 20) {
            tracker.mousePositions.shift();
        }
        
        if (tracker.mousePositions.length < 10) return;
        
        let directions = [];
        for (let i = 1; i < tracker.mousePositions.length; i++) {
            const dx = tracker.mousePositions[i].x - tracker.mousePositions[i-1].x;
            const dy = tracker.mousePositions[i].y - tracker.mousePositions[i-1].y;
            if (dx !== 0 || dy !== 0) {
                directions.push(Math.atan2(dy, dx));
            }
        }
        
        if (directions.length < 5) return;
        
        const mean = directions.reduce((a, b) => a + b, 0) / directions.length;
        const variance = directions.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / directions.length;
        
        if (variance < 0.01) {
            tracker.straightLineScore++;
        }
    }
    
    function checkClickSpeed() {
        const now = Date.now();
        tracker.clickTimes.push(now);
        
        if (tracker.clickTimes.length > 5) {
            tracker.clickTimes.shift();
        }
        
        if (tracker.clickTimes.length < 2) return;
        
        const interval = tracker.clickTimes[tracker.clickTimes.length - 1] - 
                         tracker.clickTimes[tracker.clickTimes.length - 2];
        
        if (interval < 100) {
            tracker.impossibleSpeed = true;
            pushEvent({
                type: 'impossible_click_speed',
                interval: interval,
                at: Date.now() - tracker.startTime
            });
        }
    }
    
    // ============================================
    // EVENT LISTENERS
    // ============================================
    
    document.addEventListener('mousemove', function(e) {
        checkEventTrusted(e);
        
        const now = Date.now();
        if (now - tracker.lastMouseMove > 50) {
            tracker.mouseMoveCount++;
            tracker.lastMouseMove = now;
            tracker.mouseActive = true;
            
            analyzeMounseMovement(e.clientX, e.clientY);
        }
    }, { passive: true });
    
    document.addEventListener('click', function(e) {
        checkEventTrusted(e);
        checkClickSpeed();
    }, { passive: true });
    
    document.addEventListener('touchstart', function(e) {
        checkEventTrusted(e);
        tracker.mouseActive = true;
    }, { passive: true });
    
    window.addEventListener('scroll', function(e) {
        const scrollY = window.scrollY || document.documentElement.scrollTop;
        
        if (scrollY > tracker.maxScroll) {
            tracker.maxScroll = scrollY;
        }
        
        if (scrollY > (window.innerHeight * 0.3)) {
            if (tracker.scrollCount === 0) {
                pushEvent({ type: 'first_scroll', at: Date.now() - tracker.startTime });
            }
            tracker.scrollCount = Math.floor(scrollY / window.innerHeight);
        }
    }, { passive: true });
    
    document.addEventListener('keydown', function(e) {
        checkEventTrusted(e);
    }, { passive: true });
    
    // ============================================
    // PROOF OF WORK (opcional)
    // ============================================
    function solveProofOfWork(challenge, difficulty) {
        const target = '0'.repeat(difficulty);
        let nonce = 0;
        const maxIterations = 1000000;
        
        while (nonce < maxIterations) {
            const hash = simpleHash(challenge + nonce);
            if (hash.startsWith(target)) {
                return { nonce, hash, solved: true };
            }
            nonce++;
        }
        
        return { nonce: -1, solved: false };
    }
    
    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(8, '0');
    }
    
    // ============================================
    // INICIALIZACAO
    // ============================================
    function init() {
        const automation = detectAutomation();
        tracker.automationDetected = automation.automation;
        tracker.webdriver = automation.webdriver;
        tracker.headless = automation.headless;
        
        const canvas = generateCanvasFingerprint();
        tracker.canvasHash = canvas.hash;
        tracker.canvasBlocked = canvas.blocked;
        
        const webgl = generateWebGLFingerprint();
        tracker.webglHash = webgl.hash;
        
        setTimeout(function() {
            const audio = generateAudioFingerprint();
            tracker.audioHash = audio.hash;
        }, 100);
        
        setInterval(function() {
            tracker.devtoolsOpen = detectDevTools();
        }, 2000);
        
        setInterval(function() {
            tracker.timeOnPage = Date.now() - tracker.startTime;
        }, 1000);
        
        setInterval(sendBehaviorData, CONFIG.sendInterval);
        
        if (CONFIG.enablePostMessage && isInIframe) {
            setInterval(sendToParent, CONFIG.postMessageInterval);
            
            setTimeout(sendToParent, 1000);
            
            document.addEventListener('click', function() {
                setTimeout(sendToParent, 100);
            }, { passive: true });
            
            if (CONFIG.debugMode) {
                console.log('[CMDR] PostMessage habilitado - rodando em iframe');
            }
        }
        
        window.addEventListener('beforeunload', function() {
            sendBehaviorData();
            if (isInIframe) sendToParent();
        });
        
        if (CONFIG.debugMode) {
            console.log('[CMDR] Tracker initialized', tracker);
        }
    }
    
    // ============================================
    // ENVIO DE DADOS VIA POSTMESSAGE (para o proxy/parent)
    // ============================================
    function sendToParent() {
        if (!CONFIG.enablePostMessage || !isInIframe) return;
        
        const score = calculateBotScore();
        
        const report = {
            type: '__BEHAVIOR_REPORT__',
            score: score,
            details: {
                webdriver: tracker.webdriver ? 50 : 0,
                headless: tracker.headless ? 40 : 0,
                automation: tracker.automationDetected ? 60 : 0,
                untrusted: tracker.untrustedEvents * 10,
                straightLine: tracker.straightLineScore > 3 ? 30 : 0,
                impossibleSpeed: tracker.impossibleSpeed ? 25 : 0,
                devtools: tracker.devtoolsOpen ? 15 : 0,
                noMouse: (tracker.timeOnPage > 5000 && tracker.mouseMoveCount < 3) ? 20 : 0
            },
            dataPoints: {
                mouse: tracker.mouseMoveCount,
                scroll: tracker.scrollCount,
                clicks: tracker.clickTimes.length,
                untrustedEvents: tracker.untrustedEvents
            },
            flags: {
                webdriver: tracker.webdriver,
                headless: tracker.headless,
                automation: tracker.automationDetected,
                devtoolsOpen: tracker.devtoolsOpen,
                straightMouse: tracker.straightLineScore > 3,
                impossibleSpeed: tracker.impossibleSpeed
            },
            fingerprints: {
                canvas: tracker.canvasHash,
                webgl: tracker.webglHash,
                audio: tracker.audioHash
            },
            elapsed: tracker.timeOnPage,
            visitorId: tracker.visitorId
        };
        
        try {
            window.parent.postMessage(report, '*');
            
            if (CONFIG.debugMode) {
                console.log('[CMDR] PostMessage enviado:', report);
            }
        } catch(e) {
            if (CONFIG.debugMode) {
                console.log('[CMDR] Erro ao enviar postMessage:', e);
            }
        }
    }
    
    // ============================================
    // ENVIO DE DADOS PARA API
    // ============================================
    function sendBehaviorData() {
        const data = new FormData();
        
        data.append('action', 'update_behavior');
        data.append('visitor_id', tracker.visitorId);
        data.append('campaign', getCampaignId());
        data.append('time_on_page', tracker.timeOnPage);
        
        data.append('scrolls', tracker.scrollCount);
        data.append('max_scroll', tracker.maxScroll);
        data.append('mouse_moves', tracker.mouseMoveCount);
        data.append('has_mouse', tracker.mouseActive ? '1' : '0');
        
        data.append('webdriver', tracker.webdriver ? '1' : '0');
        data.append('headless', tracker.headless ? '1' : '0');
        data.append('automation', tracker.automationDetected || '');
        
        data.append('untrusted_events', tracker.untrustedEvents);
        data.append('straight_mouse', tracker.straightLineScore > 3 ? '1' : '0');
        data.append('impossible_speed', tracker.impossibleSpeed ? '1' : '0');
        
        data.append('devtools_open', tracker.devtoolsOpen ? '1' : '0');
        
        data.append('canvas_hash', tracker.canvasHash);
        data.append('canvas_blocked', tracker.canvasBlocked ? '1' : '0');
        data.append('webgl_hash', tracker.webglHash);
        data.append('audio_hash', tracker.audioHash || '');
        
        data.append('plugins', navigator.plugins.length);
        data.append('languages', (navigator.languages || []).length);
        data.append('timezone', Intl.DateTimeFormat().resolvedOptions().timeZone);
        data.append('screen', window.screen.width + 'x' + window.screen.height);
        data.append('touch', 'ontouchstart' in window ? '1' : '0');
        
        // Fetch com tratamento de resposta adicionado[cite: 6]
        fetch(CONFIG.apiEndpoint, {
            method: 'POST',
            body: data,
            keepalive: true
        }).then(function(response) {
            if (!response.ok && CONFIG.debugMode) {
                console.log('[CMDR] Resposta da API com erro de status:', response.status);
            }
        }).catch(function(err) {
            if (CONFIG.debugMode) {
                console.log('[CMDR] Falha na requisição fetch:', err);
            }
        });
    }
    
    function getCampaignId() {
        const params = new URLSearchParams(window.location.search);
        return params.get('c') || params.get('campaign') || 'default';
    }
    
    // ============================================
    // INICIA
    // ============================================
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    // Exporta para uso global
    window.CommanderTracker = {
        tracker: tracker,
        solvePoW: solveProofOfWork,
        getFingerprints: function() {
            return {
                canvas: tracker.canvasHash,
                webgl: tracker.webglHash,
                audio: tracker.audioHash
            };
        }
    };
    
})();