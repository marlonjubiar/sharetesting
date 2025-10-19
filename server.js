const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs');
const axios = require('axios');
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Constants
const HOST = '0.0.0.0';
const PORT = 8080;
const KEYS_FILE = 'auth_keys.json';
const ADMIN_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
const GLOBAL_SHARE_COUNT_FILE = 'global_share_count.json';
const MAX_SHARES_PER_REQUEST = 1000;

const HEADERS = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': "Windows",
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'accept-encoding': 'gzip, deflate',
    'host': 'graph.facebook.com'
};

// KeyManager Class
class KeyManager {
    constructor(keysFile = KEYS_FILE) {
        this.keysFile = keysFile;
        this.keys = this._loadKeys();
    }

    _loadKeys() {
        if (fsSync.existsSync(this.keysFile)) {
            try {
                const data = fsSync.readFileSync(this.keysFile, 'utf8');
                return JSON.parse(data);
            } catch (error) {
                return {};
            }
        }
        return {};
    }

    _saveKeys() {
        fsSync.writeFileSync(this.keysFile, JSON.stringify(this.keys, null, 4));
    }

    _getPhilippineTime() {
        const now = new Date();
        const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
        const phTime = new Date(utc + (3600000 * 8));
        return phTime;
    }

    _formatDateTime(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }

    _formatTimestamp(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        return `${year}${month}${day}${hours}${minutes}${seconds}`;
    }

    generateKey() {
        const key = crypto.randomBytes(8).toString('hex');
        const phTime = this._getPhilippineTime();
        const timestamp = this._formatTimestamp(phTime);
        const fullKey = `${key}-${timestamp}`;

        const expiryDate = new Date(phTime.getTime() + (3 * 24 * 60 * 60 * 1000));
        const expiry = this._formatDateTime(expiryDate);

        this.keys[fullKey] = {
            expiry: expiry,
            active: false,
            created_at: this._formatDateTime(phTime),
            share_count: 0
        };

        this._saveKeys();
        return fullKey;
    }

    validateKey(key) {
        if (!(key in this.keys)) {
            return { valid: false, message: "Invalid key" };
        }

        const keyData = this.keys[key];
        const now = this._getPhilippineTime();

        if (!keyData.active) {
            return { valid: false, message: "Key not approved by admin" };
        }

        const expiryDate = new Date(keyData.expiry);

        if (now > expiryDate) {
            return { valid: false, message: "Key has expired" };
        }

        return { valid: true, message: "Key is valid" };
    }

    approveKey(key) {
        if (key in this.keys) {
            this.keys[key].active = true;
            this._saveKeys();
            return true;
        }
        return false;
    }

    incrementShareCount(key, count) {
        if (key in this.keys) {
            if (!this.keys[key].share_count) {
                this.keys[key].share_count = 0;
            }
            this.keys[key].share_count += count;
            this._saveKeys();
            return this.keys[key].share_count;
        }
        return 0;
    }

    getKeyInfo(key) {
        if (!(key in this.keys)) {
            return {};
        }

        const keyData = this.keys[key];
        const now = this._getPhilippineTime();
        const expiryDate = new Date(keyData.expiry);

        const remaining = expiryDate - now;
        const days = Math.floor(remaining / (1000 * 60 * 60 * 24));
        const hours = Math.floor((remaining % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));

        return {
            active: keyData.active,
            created_at: keyData.created_at,
            expiry: keyData.expiry,
            remaining: `${days}d ${hours}h ${minutes}m`,
            status: keyData.active ? "Active" : "Pending Approval",
            is_expired: now > expiryDate,
            share_count: keyData.share_count || 0
        };
    }
}

function loginRequired(req, res, next) {
    if (!req.session.key) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const keyManager = new KeyManager();
    const result = keyManager.validateKey(req.session.key);

    if (!result.valid) {
        return res.status(401).json({ error: result.message });
    }

    next();
}

function loadGlobalShareCount() {
    try {
        if (fsSync.existsSync(GLOBAL_SHARE_COUNT_FILE)) {
            const data = fsSync.readFileSync(GLOBAL_SHARE_COUNT_FILE, 'utf8');
            const json = JSON.parse(data);
            return parseInt(json.count || 0);
        }
        return 0;
    } catch (error) {
        return 0;
    }
}

function saveGlobalShareCount(count) {
    try {
        fsSync.writeFileSync(GLOBAL_SHARE_COUNT_FILE, JSON.stringify({ count: count }));
    } catch (error) {
        // Silent fail
    }
}

async function sharePost(postId, token, shareIndex) {
    try {
        const response = await axios.post(
            'https://graph.facebook.com/me/feed',
            null,
            {
                params: {
                    link: `https://facebook.com/${postId}`,
                    published: '0',
                    access_token: token
                },
                headers: HEADERS,
                timeout: 30000
            }
        );

        const data = response.data;

        if (data.id) {
            return { success: true, message: `Share ${shareIndex} successful` };
        } else if (data.error) {
            const errorMsg = data.error.message || 'Unknown error';
            if (['already shared', 'duplicate', 'posted'].some(msg => errorMsg.toLowerCase().includes(msg))) {
                return { success: true, message: `Share ${shareIndex} completed (duplicate)` };
            }
            return { success: false, message: `Share ${shareIndex} failed: ${errorMsg}` };
        }
        return { success: false, message: `Share ${shareIndex} failed: Unknown response format` };
    } catch (error) {
        return { success: false, message: `Share ${shareIndex} failed: ${error.message}` };
    }
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/admin/keys', (req, res) => {
    const keyManager = new KeyManager();
    const pendingKeys = {};
    const activeKeys = {};

    for (const [key, value] of Object.entries(keyManager.keys)) {
        if (!value.active) {
            pendingKeys[key] = value;
        } else {
            activeKeys[key] = value;
        }
    }

    const globalShares = loadGlobalShareCount();

    res.json({
        pending_keys: pendingKeys,
        active_keys: activeKeys,
        global_shares: globalShares
    });
});

app.post('/api/generate-key', (req, res) => {
    const keyManager = new KeyManager();
    const key = keyManager.generateKey();
    res.json({ key: key });
});

app.post('/api/validate-key', (req, res) => {
    const key = req.body.key;
    const keyManager = new KeyManager();
    const result = keyManager.validateKey(key);

    if (result.valid) {
        req.session.key = key;
    }

    res.json({ valid: result.valid, message: result.message });
});

app.post('/api/approve-key', (req, res) => {
    const adminPass = req.body.admin_password;
    const key = req.body.key;

    const hash = crypto.createHash('sha256').update(adminPass).digest('hex');

    if (hash !== ADMIN_HASH) {
        return res.status(401).json({ error: 'Invalid admin password' });
    }

    const keyManager = new KeyManager();
    const success = keyManager.approveKey(key);
    res.json({ success: success });
});

app.get('/api/key-info', loginRequired, (req, res) => {
    const key = req.session.key;
    const keyManager = new KeyManager();
    const info = keyManager.getKeyInfo(key);
    info.global_shares = loadGlobalShareCount();
    res.json(info);
});

app.post('/api/share', loginRequired, async (req, res) => {
    const postId = req.body.post_id;
    const tokens = req.body.tokens || [];
    const shareCount = parseInt(req.body.share_count || 1);

    if (!postId || tokens.length === 0) {
        return res.status(400).json({ error: 'Missing required parameters' });
    }

    if (shareCount > MAX_SHARES_PER_REQUEST) {
        return res.status(400).json({ error: `Maximum shares per request is ${MAX_SHARES_PER_REQUEST}` });
    }

    const keyManager = new KeyManager();
    let successCount = 0;
    let errorCount = 0;
    const statusUpdates = [];
    const totalShares = tokens.length * shareCount;
    let processedCount = 0;
    let globalShareCount = loadGlobalShareCount();

    const tasks = [];
    let shareIndex = 0;

    for (let i = 0; i < shareCount; i++) {
        for (const token of tokens) {
            tasks.push({ postId, token, index: shareIndex + 1 });
            shareIndex++;
        }
    }

    for (const task of tasks) {
        try {
            const result = await sharePost(task.postId, task.token, task.index);
            processedCount++;

            if (result.success) {
                successCount++;
                globalShareCount++;
            } else {
                errorCount++;
            }

            statusUpdates.push({
                status: result.success ? 'success' : 'error',
                message: result.message,
                progress: Math.round((processedCount / totalShares) * 100 * 100) / 100
            });

            if (result.success && processedCount % 10 === 0) {
                saveGlobalShareCount(globalShareCount);
            }

        } catch (error) {
            errorCount++;
            statusUpdates.push({
                status: 'error',
                message: `Unexpected error in share ${processedCount}: ${error.message}`,
                progress: Math.round((processedCount / totalShares) * 100 * 100) / 100
            });
        }
    }

    saveGlobalShareCount(globalShareCount);
    const currentKeyShares = keyManager.incrementShareCount(req.session.key, successCount);

    const result = {
        success_count: successCount,
        error_count: errorCount,
        total_attempts: totalShares,
        processed: processedCount,
        status_updates: statusUpdates.slice(-5),
        progress_percentage: Math.round((processedCount / totalShares) * 100 * 100) / 100,
        global_share_count: globalShareCount,
        key_share_count: currentKeyShares
    };

    res.json(result);
});

app.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
});
