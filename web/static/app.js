document.addEventListener('DOMContentLoaded', () => {
    const addNodeBtn = document.getElementById('add-node-btn');
    const modal = document.getElementById('add-node-modal');
    const closeBtn = document.getElementById('close-modal-btn');
    const cancelBtn = document.getElementById('cancel-node-btn');
    const addNodeForm = document.getElementById('add-node-form');
    const nodesContainer = document.getElementById('nodes-container');
    const template = document.getElementById('node-card-template');

    let ws = null;
    let nodes = [];
    let workspaceNodeIds = new Set();
    let activeControlNodeId = null;
    const nodeStateMap = {};
    const ATTACK_TYPES = ['dos', 'repeat', 'replay', 'fuzz', 'spoof'];

    // Allow running from Live Server (5500) while pointing to FastAPI (8000)
    const API_BASE = window.location.port === '5500' ? 'http://localhost:8000' : '';
    const WS_BASE = window.location.port === '5500' ? 'ws://localhost:8000' : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

    // --- Modal Logic ---
    function openModal() {
        modal.style.display = 'flex';
        // tiny delay to allow display:flex to apply before adding class for transition
        setTimeout(() => modal.classList.add('show'), 10);
    }

    function closeModal() {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            addNodeForm.reset();
        }, 300);
    }

    addNodeBtn.addEventListener('click', openModal);
    closeBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);

    // --- API Interactions ---
    async function fetchNodes() {
        try {
            const res = await fetch(`${API_BASE}/api/nodes`);
            if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
            nodes = await res.json();
            renderNodes();
        } catch (e) {
            console.error('Failed to fetch nodes', e);
        }
    }

    async function readErrorMessage(res) {
        const contentType = res.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
            const data = await res.json();
            return data.detail || JSON.stringify(data);
        }

        const text = await res.text();
        return text || `HTTP ${res.status}`;
    }

    addNodeForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('node-name').value.trim();
        const port = document.getElementById('node-port').value.trim();
        const id = 'node_' + Date.now();

        try {
            const res = await fetch(`${API_BASE}/api/nodes`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id, name, port })
            });
            if (res.ok) {
                closeModal();
                fetchNodes();
            } else {
                const errorMessage = await readErrorMessage(res);
                alert(`Error: ${errorMessage}`);
            }
        } catch (e) {
            alert(`Error connecting to node: ${e.message}`);
        }
    });

    async function deleteNode(nodeId) {
        if (!confirm('Are you sure you want to disconnect this node?')) return;
        try {
            const res = await fetch(`${API_BASE}/api/nodes/${nodeId}`, { method: 'DELETE' });
            if (res.ok) {
                fetchNodes();
            }
        } catch (e) {
            console.error('Failed to delete node', e);
        }
    }

    async function sendMessage(nodeId, idStr, dlcStr, dataStr) {
        try {
            const res = await fetch(`${API_BASE}/api/nodes/${nodeId}/send`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    id: idStr,
                    dlc: parseInt(dlcStr),
                    data: dataStr
                })
            });
            if (!res.ok) {
                const errorMessage = await readErrorMessage(res);
                alert(`Error sending: ${errorMessage}`);
            }
        } catch (e) {
            alert(`Error sending message: ${e.message}`);
        }
    }

    async function controlDefense(nodeId, action, duration = null) {
        const payload = { action };
        if (duration !== null) {
            payload.duration = duration;
        }

        const res = await fetch(`${API_BASE}/api/nodes/${nodeId}/defense`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            throw new Error(await readErrorMessage(res));
        }

        return res.json();
    }

    function setDefenseState(nodeId, active, text) {
        if (!nodeStateMap[nodeId]) return;
        nodeStateMap[nodeId].defense_active = !!active;
        nodeStateMap[nodeId].defense_text = text || (active ? 'Defense active' : 'Defense idle');

        if (activeControlNodeId === nodeId) {
            updateGlobalDefenseUI();
        }
    }

    function setAutoDefenseState(nodeId, enabled) {
        if (!nodeStateMap[nodeId]) return;
        nodeStateMap[nodeId].auto_defense = !!enabled;

        if (activeControlNodeId === nodeId) {
            updateGlobalDefenseUI();
        }
    }

    function syncDefenseStateFromLog(nodeId, raw) {
        const autoMatch = raw.match(/\[STATUS\]\s+auto_defense=(\d+)/);
        if (autoMatch) {
            setAutoDefenseState(nodeId, autoMatch[1] !== '0');
            return;
        }

        const statusMatch = raw.match(/\[STATUS\]\s+defense_active=(\d+)/);
        if (statusMatch) {
            const active = statusMatch[1] !== '0';
            setDefenseState(nodeId, active, active ? 'Defense active' : 'Defense idle');
            return;
        }

        if (/\[DEFENSE\].*(Activated|Simulation defense enabled|Dropped)/.test(raw)) {
            setDefenseState(nodeId, true, 'Defense active');
            return;
        }

        if (/\[DEFENSE\].*(All defense blocks cleared|Simulation defense disabled)/.test(raw)) {
            setDefenseState(nodeId, false, 'Defense idle');
            return;
        }

        if (/\[ERROR\].*No alert has been recorded yet/.test(raw)) {
            setDefenseState(nodeId, false, 'No alert to defend');
        }
    }

    function syncAttackStateFromLog(nodeId, raw) {
        if (!nodeStateMap[nodeId]) return;
        const attackPatterns = [
            { type: 'dos', start: /\[STATE\].*DoS attack started/i, stop: /\[STATE\].*DoS attack stopped/i },
            { type: 'replay', start: /\[STATE\].*Replay attack started/i, stop: /\[STATE\].*Replay attack stopped/i },
            { type: 'fuzz', start: /\[STATE\].*Fuzzing attack started/i, stop: /\[STATE\].*Fuzzing attack stopped/i },
            { type: 'spoof', start: /\[STATE\].*Spoofing attack started/i, stop: /\[STATE\].*Spoofing attack stopped/i },
            { type: 'repeat', start: /\[STATE\].*Repeat transmission started/i, stop: /\[STATE\].*Repeat transmission stopped/i }
        ];

        for (const pattern of attackPatterns) {
            if (pattern.start.test(raw)) {
                ATTACK_TYPES.forEach(type => {
                    nodeStateMap[nodeId].attacks[type] = type === pattern.type;
                });
                if (activeControlNodeId === nodeId) {
                    updateGlobalAttacksUI();
                }
                return;
            }

            if (pattern.stop.test(raw)) {
                nodeStateMap[nodeId].attacks[pattern.type] = false;
                if (activeControlNodeId === nodeId) {
                    updateGlobalAttacksUI();
                }
                return;
            }
        }
    }

    function renderLogMessage(msgEl, raw) {
        const match = raw.match(/^\[(.*?)\]\s*\[(ALERT|DEFENSE|STATUS|STATE|ERROR)\]\s*(.*)$/);
        if (!match) {
            msgEl.className = 'system-msg';
            msgEl.textContent = raw;
            return;
        }

        const [, timestamp, tag, text] = match;
        const tagClass = tag.toLowerCase();
        msgEl.className = `message-item log ${tagClass}`;
        msgEl.innerHTML = `
            <div class="msg-header">
                <span class="msg-time">${timestamp.trim()}</span>
                <span class="msg-dir">${tag}</span>
            </div>
            <div class="msg-body">
                <span class="msg-data">${text}</span>
            </div>
        `;
    }

    function attackLabel(type) {
        const labels = {
            dos: 'DoS',
            repeat: 'Repeat',
            replay: 'Replay',
            fuzz: 'Fuzz',
            spoof: 'Spoof'
        };
        return labels[type] || type;
    }

    // --- Global Right Bar Setup ---
    function updateGlobalDefenseUI() {
        if (!activeControlNodeId || !nodeStateMap[activeControlNodeId]) return;
        const state = nodeStateMap[activeControlNodeId];
        const badge = document.getElementById('global-defense-status');
        badge.textContent = state.defense_text;
        badge.classList.toggle('active', state.defense_active);
        badge.classList.toggle('idle', !state.defense_active);

        const autoBtn = document.getElementById('global-auto-defense-btn');
        if (autoBtn) {
            autoBtn.textContent = state.auto_defense ? 'Auto-Defend: On' : 'Auto-Defend: Off';
            autoBtn.classList.toggle('active', !!state.auto_defense);
        }
    }

    function updateGlobalAttacksUI() {
        if (!activeControlNodeId || !nodeStateMap[activeControlNodeId]) return;
        const state = nodeStateMap[activeControlNodeId];
        let anyActive = false;
        
        ATTACK_TYPES.forEach(type => {
            const btn = document.querySelector(`#global-${type}-form .atk-btn`);
            if (!btn) return;
            if (state.attacks && state.attacks[type]) {
                btn.classList.remove('warning-outline');
                btn.classList.add('danger');
                btn.textContent = 'Stop';
                anyActive = true;
            } else {
                btn.classList.remove('danger');
                btn.classList.add('warning-outline');
                btn.textContent = 'Start ' + attackLabel(type);
            }
        });

        const panel = document.getElementById('global-security-panel');
        if (anyActive) {
            panel.classList.add('active');
        } else {
            panel.classList.remove('active');
        }
    }

    function setupGlobalRightBar() {
        // Send Form
        document.getElementById('global-send-form').addEventListener('submit', (e) => {
            e.preventDefault();
            if (!activeControlNodeId) return;
            const id = document.getElementById('global-send-id').value;
            const dlc = document.getElementById('global-send-dlc').value;
            const data = document.getElementById('global-send-data').value;
            sendMessage(activeControlNodeId, id, dlc, data);
        });

        // Defense
        document.getElementById('global-defense-on-btn').addEventListener('click', async () => {
            if (!activeControlNodeId) return;
            const duration = parseInt(document.getElementById('global-defense-duration').value, 10);
            if (Number.isNaN(duration)) return alert('Invalid duration.');
            try {
                const result = await controlDefense(activeControlNodeId, 'on', duration);
                setDefenseState(activeControlNodeId, result.defense_active ?? true, result.message || `Defense active for ${duration} ms`);
            } catch (e) { alert(`Error: ${e.message}`); }
        });

        document.getElementById('global-defense-status-btn').addEventListener('click', async () => {
            if (!activeControlNodeId) return;
            try {
                const result = await controlDefense(activeControlNodeId, 'status');
                if (typeof result.defense_active === 'boolean') {
                    setDefenseState(activeControlNodeId, result.defense_active, result.message);
                } else {
                    const currentActive = nodeStateMap[activeControlNodeId].defense_active;
                    setDefenseState(activeControlNodeId, currentActive, result.message || 'Status requested');
                }
            } catch (e) { alert(`Error: ${e.message}`); }
        });

        document.getElementById('global-defense-off-btn').addEventListener('click', async () => {
            if (!activeControlNodeId) return;
            try {
                const result = await controlDefense(activeControlNodeId, 'off');
                setDefenseState(activeControlNodeId, false, result.message || 'Defense cleared');
            } catch (e) { alert(`Error: ${e.message}`); }
        });

        document.getElementById('global-auto-defense-btn').addEventListener('click', async () => {
            if (!activeControlNodeId || !nodeStateMap[activeControlNodeId]) return;
            const enabled = !nodeStateMap[activeControlNodeId].auto_defense;
            try {
                const res = await fetch(`${API_BASE}/api/nodes/${activeControlNodeId}/auto-defense`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled })
                });
                if (!res.ok) throw new Error(await readErrorMessage(res));
                const result = await res.json();
                setAutoDefenseState(activeControlNodeId, result.auto_defense_active ?? enabled);
            } catch (e) { alert(`Error: ${e.message}`); }
        });

        // Attack Tabs
        const tabs = document.querySelectorAll('#global-security-panel .attack-tab');
        const contents = document.querySelectorAll('#global-security-panel .attack-tab-content');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                if (document.getElementById('global-security-panel').classList.contains('active')) return;
                tabs.forEach(t => t.classList.remove('active'));
                contents.forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.querySelector(`#global-security-panel .attack-tab-content[data-tab="${tab.dataset.target}"]`).classList.add('active');
            });
        });

        // Attacks Submit
        async function handleGlobalAttack(type, payloadBuilder) {
            if (!activeControlNodeId || !nodeStateMap[activeControlNodeId]) return;
            const state = nodeStateMap[activeControlNodeId];
            const isRunning = state.attacks[type];
            const action = isRunning ? 'stop' : 'start';
            const payload = { action };
            if (action === 'start') Object.assign(payload, payloadBuilder());

            try {
                const res = await fetch(`${API_BASE}/api/nodes/${activeControlNodeId}/attack/${type}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                if (res.ok) {
                    if (isRunning) {
                        state.attacks[type] = false;
                    } else {
                        Object.keys(state.attacks).forEach(k => state.attacks[k] = false);
                        state.attacks[type] = true;
                    }
                    updateGlobalAttacksUI();
                } else {
                    alert(`Error: ${await readErrorMessage(res)}`);
                }
            } catch (e) { alert(`Error: ${e.message}`); }
        }

        document.getElementById('global-dos-form').addEventListener('submit', (e) => {
            e.preventDefault();
            handleGlobalAttack('dos', () => ({
                id: document.querySelector('#global-dos-form .atk-id').value,
                period: parseInt(document.querySelector('#global-dos-form .atk-period').value)
            }));
        });
        document.getElementById('global-repeat-form').addEventListener('submit', (e) => {
            e.preventDefault();
            handleGlobalAttack('repeat', () => ({
                id: document.querySelector('#global-repeat-form .atk-id').value,
                dlc: parseInt(document.querySelector('#global-repeat-form .atk-dlc').value),
                data: document.querySelector('#global-repeat-form .atk-data').value,
                period: parseInt(document.querySelector('#global-repeat-form .atk-period').value)
            }));
        });
        document.getElementById('global-replay-form').addEventListener('submit', (e) => {
            e.preventDefault();
            handleGlobalAttack('replay', () => ({
                period: parseInt(document.querySelector('#global-replay-form .atk-period').value)
            }));
        });
        document.getElementById('global-fuzz-form').addEventListener('submit', (e) => {
            e.preventDefault();
            handleGlobalAttack('fuzz', () => ({
                period: parseInt(document.querySelector('#global-fuzz-form .atk-period').value)
            }));
        });
        document.getElementById('global-spoof-form').addEventListener('submit', (e) => {
            e.preventDefault();
            handleGlobalAttack('spoof', () => ({
                period: parseInt(document.querySelector('#global-spoof-form .atk-period').value)
            }));
        });
    }

    // --- Rendering Logic ---
    function selectNode(id) {
        document.querySelectorAll('.node-list-item').forEach(el => el.classList.remove('active'));
        const item = document.querySelector(`.node-list-item[data-node-id="${id}"]`);
        if(item) item.classList.add('active');

        activeControlNodeId = id;
        const node = nodes.find(n => n.id === id);
        if (node) {
            document.getElementById('active-node-name').textContent = node.name;
            document.getElementById('active-node-port').textContent = node.port;
        }

        updateGlobalDefenseUI();
        updateGlobalAttacksUI();
    }

    function toggleWorkspaceNode(id) {
        if (workspaceNodeIds.has(id)) {
            workspaceNodeIds.delete(id);
        } else {
            workspaceNodeIds.add(id);
        }
        renderWorkspace();
    }

    function renderWorkspace() {
        // Find cards that exist but shouldn't, and remove them
        Array.from(nodesContainer.children).forEach(card => {
            if (!workspaceNodeIds.has(card.dataset.nodeId)) {
                card.remove();
            }
        });

        // Add cards that should exist but don't
        nodes.forEach(node => {
            if (workspaceNodeIds.has(node.id) && !document.querySelector(`.node-card[data-node-id="${node.id}"]`)) {
                const clone = template.content.cloneNode(true);
                const card = clone.querySelector('.node-card');
                card.dataset.nodeId = node.id;
                
                card.querySelector('.node-name').textContent = node.name;
                card.querySelector('.node-port').textContent = node.port;
                
                nodesContainer.appendChild(clone);
            }
        });

        // Update toggle button icons in sidebar
        document.querySelectorAll('.toggle-workspace-btn').forEach(btn => {
            const li = btn.closest('.node-list-item');
            if (!li) return;
            const id = li.dataset.nodeId;
            if (workspaceNodeIds.has(id)) {
                btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
                btn.classList.add('active');
            } else {
                btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`;
                btn.classList.remove('active');
            }
        });

        // Update container grid class based on count
        let count = workspaceNodeIds.size;
        let gridClass = 'grid-more';
        if (count >= 1 && count <= 4) gridClass = `grid-${count}`;
        else if (count === 0) gridClass = '';
        nodesContainer.className = `app-workspace ${gridClass}`;
    }

    function renderNodes() {
        const sidebarList = document.getElementById('sidebar-node-list');
        if (sidebarList) sidebarList.innerHTML = '';

        nodes.forEach(node => {
            // Initialize state map if missing
            if (!nodeStateMap[node.id]) {
                nodeStateMap[node.id] = {
                    defense_active: !!node.defense_active,
                    defense_text: node.defense_active ? 'Defense active' : 'Defense idle',
                    auto_defense: !!node.auto_defense,
                    attacks: { dos: false, repeat: false, replay: false, fuzz: false, spoof: false }
                };
            }

            // --- 1. Append Sidebar Item ---
            if (sidebarList) {
                const li = document.createElement('li');
                li.className = 'node-list-item';
                li.dataset.nodeId = node.id;
                li.innerHTML = `
                    <button class="icon-btn toggle-workspace-btn" title="Toggle Workspace View">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    </button>
                    <div class="node-list-info" style="flex: 1;">
                        <div class="name">${node.name}</div>
                        <div class="port">${node.port}</div>
                    </div>
                    <button class="icon-btn delete-node-btn" style="padding: 4px;" title="Remove Node">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"></path><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                `;
                li.addEventListener('click', (e) => {
                    if (e.target.closest('.delete-node-btn')) {
                        deleteNode(node.id);
                        workspaceNodeIds.delete(node.id);
                        renderWorkspace();
                    } else if (e.target.closest('.toggle-workspace-btn')) {
                        toggleWorkspaceNode(node.id);
                    } else {
                        selectNode(node.id);
                    }
                });
                sidebarList.appendChild(li);
            }
        });

        // Remove workspace nodes that no longer exist
        const currentIds = new Set(nodes.map(n => n.id));
        for (let id of workspaceNodeIds) {
            if (!currentIds.has(id)) workspaceNodeIds.delete(id);
        }

        renderWorkspace();

        if (nodes.length > 0 && (!activeControlNodeId || !currentIds.has(activeControlNodeId))) {
            selectNode(nodes[0].id);
        } else if (nodes.length === 0) {
            activeControlNodeId = null;
            document.getElementById('active-node-name').textContent = 'No Node Selected';
            document.getElementById('active-node-port').textContent = '';
        }
    }

    // --- WebSocket Logic ---
    function connectWebSocket() {
        ws = new WebSocket(`${WS_BASE}/ws`);

        ws.onopen = () => console.log('WebSocket connected');
        
        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                handleIncomingMessage(msg);
            } catch (e) {
                console.error("Failed to parse WebSocket message:", event.data);
            }
        };

        ws.onclose = () => {
            console.log('WebSocket disconnected, retrying in 3s...');
            setTimeout(connectWebSocket, 3000);
        };
    }

    function handleIncomingMessage(msg) {
        if (msg.type === 'can_message' && (!msg.parsed || msg.mode === 'legacy-text')) {
            return;
        }

        const card = document.querySelector(`.node-card[data-node-id="${msg.node_id}"]`);
        if (!card) return; // Node not found in UI

        const list = card.querySelector('.messages-list');
        const msgEl = document.createElement('div');

        if (msg.type === 'can_message' && msg.parsed) {
            msgEl.className = `message-item ${msg.direction.toLowerCase()}`;
            msgEl.innerHTML = `
                <div class="msg-header">
                    <span class="msg-time">${msg.timestamp}</span>
                    <span class="msg-dir">${msg.direction} (${msg.mode})</span>
                </div>
                <div class="msg-body">
                    <span class="msg-id">${msg.parsed.id}</span>
                    <span class="msg-data">${msg.parsed.data || '--'}</span>
                </div>
            `;
        } else if (msg.type === 'system' || msg.type === 'log') {
            const rawText = msg.message || msg.raw;
            if (msg.type === 'log' && rawText) {
                renderLogMessage(msgEl, rawText);
                syncDefenseStateFromLog(msg.node_id, rawText);
                syncAttackStateFromLog(msg.node_id, rawText);
            } else {
                msgEl.className = 'system-msg';
                msgEl.textContent = rawText;
            }
        } else {
            // raw text fallback
            msgEl.className = 'system-msg';
            msgEl.textContent = msg.raw;
        }

        list.appendChild(msgEl);
        // Auto scroll to bottom
        const container = card.querySelector('.messages-container');
        container.scrollTop = container.scrollHeight;
        
        // Flash indicator
        const indicator = card.querySelector('.node-status-indicator');
        indicator.style.animation = 'none';
        indicator.offsetHeight; // trigger reflow
        indicator.style.animation = 'pulse 2s infinite';
    }

    // Initialization
    setupGlobalRightBar();
    fetchNodes();
    connectWebSocket();
});
