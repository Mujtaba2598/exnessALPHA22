const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Tickerall } = require('@tickerall/sdk');

const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret (fallback)
const JWT_SECRET = process.env.JWT_SECRET || 'halal-exness-secret-key-2024';
if (!process.env.JWT_SECRET) {
  console.warn('⚠️ JWT_SECRET not set in environment. Using default.');
} else {
  console.log('✅ JWT_SECRET is set.');
}

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';

// ==================== CONFIG FILE ====================
const configFile = path.join(__dirname, 'data', 'config.json');

let config = { tickerallApiKey: '' };

function loadConfig() {
    try {
        if (fs.existsSync(configFile)) {
            const raw = fs.readFileSync(configFile, 'utf8');
            config = JSON.parse(raw);
            console.log('✅ Config loaded from file.');
        } else {
            config.tickerallApiKey = process.env.TICKERALL_API_KEY || '';
            fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
            console.log('📝 Created default config file.');
        }
    } catch (error) {
        console.error('❌ Failed to load config:', error);
        config.tickerallApiKey = process.env.TICKERALL_API_KEY || '';
    }
}

function saveConfig(newConfig) {
    try {
        fs.writeFileSync(configFile, JSON.stringify(newConfig, null, 2));
        config = newConfig;
        console.log('✅ Config saved.');
    } catch (error) {
        console.error('❌ Failed to save config:', error);
        throw error;
    }
}

loadConfig();

// ==================== TICKERALL INITIALIZATION ====================
let ticker = null;

function initTicker() {
    const apiKey = config.tickerallApiKey || process.env.TICKERALL_API_KEY || '';
    if (!apiKey) {
        console.warn('⚠️ No TickerAll API key found. Please set one.');
        ticker = null;
        return false;
    }
    try {
        ticker = new Tickerall({ apiKey: apiKey });
        console.log('✅ TickerAll initialized successfully');
        return true;
    } catch (error) {
        console.error('❌ TickerAll initialization error:', error.message);
        ticker = null;
        return false;
    }
}

initTicker();

// ==================== DATA SETUP ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir, { recursive: true });

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(dataDir, 'pending.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            tickerallSessionId: "",
            exnessLogin: "",
            exnessServer: "",
            lastBalance: 0,
            lastBalanceCurrency: "USD",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== BALANCE HELPER ====================
async function fetchBalance(accountId) {
    try {
        if (!ticker) throw new Error('TickerAll not initialized');
        if (!accountId) throw new Error('No account ID provided');
        
        const accountInfo = await ticker.accounts.get(accountId);
        if (!accountInfo) throw new Error('No account info returned');
        
        console.log('📊 Full account info from TickerAll:', JSON.stringify(accountInfo, null, 2));
        
        const balance = typeof accountInfo.balance === 'number' ? accountInfo.balance : 0;
        const currency = accountInfo.currency || 'USD';
        
        console.log(`💰 Balance fetched: ${balance} ${currency}`);
        return { balance, currency, full: accountInfo };
    } catch (error) {
        console.error('❌ Failed to fetch balance:', error.message);
        const users = readUsers();
        let lastBalance = 0;
        let lastCurrency = 'USD';
        for (const email in users) {
            if (users[email].tickerallSessionId === accountId) {
                lastBalance = users[email].lastBalance || 0;
                lastCurrency = users[email].lastBalanceCurrency || 'USD';
                break;
            }
        }
        console.warn(`⚠️ Using last known balance: ${lastBalance} ${lastCurrency}`);
        return { balance: lastBalance, currency: lastCurrency, full: null };
    }
}

// ==================== ADMIN: UPDATE API KEY (WITH VALIDATION) ====================
app.post('/api/admin/set-tickerall-key', authenticate, async (req, res) => {
    try {
        if (!req.user.isOwner) {
            return res.status(403).json({ success: false, message: 'Admin only' });
        }

        const { apiKey } = req.body;
        if (!apiKey || apiKey.trim() === '') {
            return res.status(400).json({ success: false, message: 'API key is required' });
        }

        const trimmedKey = apiKey.trim();

        // 1. Format check
        if (!trimmedKey.startsWith('cf_api_')) {
            return res.status(400).json({ success: false, message: 'Invalid API key format. Must start with "cf_api_".' });
        }

        // 2. Test the key with a real API call
        let testTicker;
        try {
            testTicker = new Tickerall({ apiKey: trimmedKey });
        } catch (err) {
            return res.status(400).json({ success: false, message: 'Invalid API key: ' + err.message });
        }

        // 3. If the user has an active session, try to fetch balance with the new key
        const users = readUsers();
        const user = users[req.user.email];
        let testSuccess = false;

        if (user && user.tickerallSessionId) {
            try {
                const accountInfo = await testTicker.accounts.get(user.tickerallSessionId);
                if (accountInfo && typeof accountInfo.balance === 'number') {
                    testSuccess = true;
                    console.log('✅ New API key validated successfully with existing session.');
                }
            } catch (err) {
                console.error('❌ New API key failed test with existing session:', err.message);
                return res.status(400).json({ 
                    success: false, 
                    message: 'The new API key is invalid or does not have permission to access this account. Error: ' + err.message 
                });
            }
        } else {
            // No active session – we can't fully test, but we'll save and warn
            console.warn('⚠️ No active session to test the new API key. Saving anyway, but user should reconnect.');
            testSuccess = true;
        }

        // 4. Save if valid
        if (testSuccess) {
            const newConfig = { tickerallApiKey: trimmedKey };
            saveConfig(newConfig);

            const reinitSuccess = initTicker();

            if (reinitSuccess) {
                console.log('✅ TickerAll API key updated and re-initialized successfully.');
                res.json({ 
                    success: true, 
                    message: user && user.tickerallSessionId 
                        ? 'TickerAll API key updated successfully! The bot is now using the new key.' 
                        : 'API key saved. Please reconnect your Exness account to complete the setup.' 
                });
            } else {
                res.json({ 
                    success: false, 
                    message: 'API key saved but TickerAll re-initialization failed. Please check the key and try again.' 
                });
            }
        } else {
            res.status(500).json({ success: false, message: 'Unexpected error during key validation.' });
        }
    } catch (error) {
        console.error('❌ Failed to update API key:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== ADMIN: TEST API KEY ====================
app.post('/api/admin/test-tickerall-key', authenticate, async (req, res) => {
    try {
        if (!req.user.isOwner) {
            return res.status(403).json({ success: false, message: 'Admin only' });
        }

        const { apiKey } = req.body;
        if (!apiKey || apiKey.trim() === '') {
            return res.status(400).json({ success: false, message: 'API key is required' });
        }

        const trimmedKey = apiKey.trim();

        if (!trimmedKey.startsWith('cf_api_')) {
            return res.status(400).json({ success: false, message: 'Invalid API key format. Must start with "cf_api_".' });
        }

        let testTicker;
        try {
            testTicker = new Tickerall({ apiKey: trimmedKey });
        } catch (err) {
            return res.status(400).json({ success: false, message: 'Invalid API key: ' + err.message });
        }

        const users = readUsers();
        const user = users[req.user.email];
        let valid = false;
        let details = '';

        if (user && user.tickerallSessionId) {
            try {
                const accountInfo = await testTicker.accounts.get(user.tickerallSessionId);
                if (accountInfo && typeof accountInfo.balance === 'number') {
                    valid = true;
                    details = `Successfully fetched balance: ${accountInfo.balance} ${accountInfo.currency || 'USD'}`;
                }
            } catch (err) {
                details = 'Failed to fetch account info: ' + err.message;
            }
        } else {
            valid = true;
            details = 'API key format is valid. Connect to Exness to fully verify.';
        }

        res.json({
            success: true,
            valid: valid,
            message: valid ? 'API key appears valid. ' + details : 'API key is invalid. ' + details
        });
    } catch (error) {
        console.error('❌ Key test error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== DEBUG BALANCE ENDPOINT ====================
app.get('/api/debug-balance', authenticate, async (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.tickerallSessionId) {
            return res.json({ success: false, message: 'No session ID found' });
        }
        
        if (!ticker) {
            return res.json({ success: false, message: 'TickerAll not initialized. Please check API key.' });
        }
        
        console.log(`🔍 Debug: Fetching account info for session: ${user.tickerallSessionId}`);
        const accountInfo = await ticker.accounts.get(user.tickerallSessionId);
        console.log('📊 Full account info from TickerAll:', JSON.stringify(accountInfo, null, 2));
        
        res.json({
            success: true,
            sessionId: user.tickerallSessionId,
            accountInfo: accountInfo,
            balance: accountInfo?.balance || 0,
            currency: accountInfo?.currency || 'USD',
            equity: accountInfo?.equity || 0,
            margin: accountInfo?.margin || 0,
            freeMargin: accountInfo?.freeMargin || 0,
            lastStoredBalance: user.lastBalance || 0
        });
    } catch (error) {
        console.error('❌ Debug balance error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== AUTH ROUTES ====================
app.post('/api/register', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User exists' });
    
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Already pending' });
    
    pending[email] = { email, password: bcrypt.hashSync(password, 10), requestedAt: new Date().toISOString() };
    writePending(pending);
    res.json({ success: true, message: 'Request sent to owner' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    
    if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Account blocked' });
    
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    console.log('✅ Login successful for:', email);
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: 'Missing Authorization header' });
    }
    
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(401).json({ success: false, message: 'Invalid Authorization format. Use: Bearer <token>' });
    }
    
    const token = parts[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        console.error('❌ Token verification failed:', err.message);
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    res.json({ success: true, pending: Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt })) });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = { 
        email, 
        password: pending[email].password, 
        isOwner: false, 
        isApproved: true, 
        isBlocked: false, 
        tickerallSessionId: "",
        exnessLogin: "",
        exnessServer: "",
        lastBalance: 0,
        lastBalanceCurrency: "USD",
        createdAt: pending[email].requestedAt 
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Approved ${email}` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `Rejected ${email}` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'BLOCKED' : 'ACTIVE'}` });
});

app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({ 
        email, 
        hasExnessCreds: !!users[email].exnessLogin, 
        isOwner: users[email].isOwner, 
        isApproved: users[email].isApproved, 
        isBlocked: users[email].isBlocked,
        balance: users[email].lastBalance || 0
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.tickerallSessionId) {
            balances[email] = { balance: 0, hasConnection: false };
            continue;
        }
        
        try {
            if (!ticker) {
                balances[email] = { balance: userData.lastBalance || 0, hasConnection: false, error: 'TickerAll not initialized' };
                continue;
            }
            const result = await fetchBalance(userData.tickerallSessionId);
            balances[email] = { 
                balance: result.balance, 
                currency: result.currency,
                hasConnection: true,
                lastUpdated: new Date().toISOString()
            };
            userData.lastBalance = result.balance;
            userData.lastBalanceCurrency = result.currency;
            writeUsers(users);
        } catch (error) {
            balances[email] = { balance: userData.lastBalance || 0, hasConnection: false, error: error.message };
        }
    }
    
    res.json({ success: true, balances });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    
    res.json({ success: true, trades: allTrades });
});

// ==================== EXNESS ACCOUNT ROUTES ====================
app.post('/api/set-exness-creds', authenticate, async (req, res) => {
    try {
        const { exnessLogin, exnessPassword, exnessServer } = req.body;
        if (!exnessLogin || !exnessPassword || !exnessServer) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }
        
        if (!ticker) {
            return res.status(500).json({ success: false, message: 'TickerAll not initialized. Please set API key in admin panel.' });
        }
        
        console.log(`📊 Connecting to Exness for user: ${req.user.email}`);
        console.log(`   Server: ${exnessServer}`);
        console.log(`   Account: ${exnessLogin}`);
        
        const { accountId } = await ticker.sessions.start({
            broker: 'mt5',
            server: exnessServer,
            account: parseInt(exnessLogin),
            password: exnessPassword,
        });
        
        console.log(`✅ Session created: ${accountId}`);
        
        const result = await fetchBalance(accountId);
        console.log(`💰 Balance: ${result.balance} ${result.currency}`);
        
        const users = readUsers();
        users[req.user.email].tickerallSessionId = accountId;
        users[req.user.email].exnessLogin = encrypt(exnessLogin);
        users[req.user.email].exnessServer = encrypt(exnessServer);
        users[req.user.email].lastBalance = result.balance;
        users[req.user.email].lastBalanceCurrency = result.currency;
        writeUsers(users);
        
        res.json({ 
            success: true, 
            message: `✅ Connected! Balance: ${result.balance} ${result.currency}`, 
            balance: result.balance,
            currency: result.currency
        });
    } catch (error) {
        console.error('❌ Exness connection error:', error);
        res.status(401).json({ 
            success: false, 
            message: error.message || 'Connection failed. Check your credentials.' 
        });
    }
});

app.post('/api/connect-exness', authenticate, async (req, res) => {
    try {
        const users = readUsers();
        const user = users[req.user.email];
        
        if (!user || !user.tickerallSessionId) {
            return res.status(400).json({ success: false, message: 'No Exness credentials saved.' });
        }
        
        if (!ticker) {
            return res.status(500).json({ success: false, message: 'TickerAll not initialized. Please set API key in admin panel.' });
        }
        
        const result = await fetchBalance(user.tickerallSessionId);
        
        user.lastBalance = result.balance;
        user.lastBalanceCurrency = result.currency;
        writeUsers(users);
        
        res.json({ 
            success: true, 
            balance: result.balance, 
            currency: result.currency,
            totalBalance: result.balance, 
            message: `Connected! Balance: ${result.balance} ${result.currency}` 
        });
    } catch (error) {
        console.error('Connection error:', error);
        res.status(401).json({ 
            success: false, 
            message: error.message || 'Connection failed. Please reconnect.' 
        });
    }
});

app.get('/api/get-exness-creds', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.exnessLogin) return res.json({ success: false });
    res.json({ 
        success: true, 
        exnessLogin: decrypt(user.exnessLogin),
        exnessServer: decrypt(user.exnessServer)
    });
});

// ==================== AI SIGNAL GENERATION ====================
function calculateRSI(prices, period = 14) {
    if (!prices || prices.length < period + 1) return 50;
    let gains = 0, losses = 0;
    for (let i = prices.length - period; i < prices.length; i++) {
        const change = prices[i] - prices[i - 1];
        if (change >= 0) gains += change;
        else losses -= change;
    }
    const avgGain = gains / period;
    const avgLoss = losses / period;
    if (avgLoss === 0) return 100;
    const rs = avgGain / avgLoss;
    return 100 - (100 / (1 + rs));
}

async function getAISignal(symbol, accountId) {
    try {
        if (!ticker) throw new Error('TickerAll not initialized');
        
        const rates = await ticker.market.getHistory(accountId, {
            symbol: symbol,
            timeframe: 'M1',
            limit: 100
        });
        
        if (!rates || rates.length < 20) {
            return { action: 'HOLD', confidence: 0, reasons: ['Insufficient data'], currentPrice: 0 };
        }
        
        const prices = rates.map(r => r.close);
        const currentPrice = prices[prices.length - 1] || 0;
        
        const rsi = calculateRSI(prices);
        const ma20 = prices.slice(-20).reduce((a, b) => a + b, 0) / 20;
        const ma50 = prices.slice(-50).reduce((a, b) => a + b, 0) / 50;
        const momentum = ((prices[prices.length - 1] - prices[prices.length - 5]) / (prices[prices.length - 5] || 1)) * 100;
        
        let action = 'HOLD';
        let confidence = 0;
        let reasons = [];
        
        if (rsi < 35) {
            action = 'BUY';
            confidence = 0.85;
            reasons.push(`RSI oversold (${rsi.toFixed(1)})`);
        } else if (rsi < 45 && ma20 > ma50) {
            action = 'BUY';
            confidence = 0.75;
            reasons.push(`RSI ${rsi.toFixed(1)} in buy zone, uptrend`);
        } else if (momentum > 0.15 && ma20 > ma50) {
            action = 'BUY';
            confidence = 0.7;
            reasons.push(`Positive momentum ${momentum.toFixed(2)}%`);
        } else if (rsi > 70) {
            action = 'SELL';
            confidence = 0.85;
            reasons.push(`RSI overbought (${rsi.toFixed(1)})`);
        } else if (rsi > 60 && ma20 < ma50) {
            action = 'SELL';
            confidence = 0.75;
            reasons.push(`RSI ${rsi.toFixed(1)} in sell zone, downtrend`);
        } else if (momentum < -0.15 && ma20 < ma50) {
            action = 'SELL';
            confidence = 0.7;
            reasons.push(`Negative momentum ${momentum.toFixed(2)}%`);
        } else if (ma20 > ma50 && momentum > 0) {
            action = 'BUY';
            confidence = 0.55;
            reasons.push(`Following uptrend (MA20 > MA50)`);
        } else if (ma20 < ma50 && momentum < 0) {
            action = 'SELL';
            confidence = 0.55;
            reasons.push(`Following downtrend (MA20 < MA50)`);
        } else {
            reasons.push(`Market ranging - RSI: ${rsi.toFixed(1)}`);
        }
        
        console.log(`🤖 AI [${symbol}]: ${action} (${(confidence*100).toFixed(0)}%) | RSI:${rsi.toFixed(1)} | ${reasons.join(', ')}`);
        
        return { action, confidence, reasons, currentPrice };
    } catch (error) {
        console.error('AI error:', error.message);
        return { action: 'BUY', confidence: 0.5, reasons: ['API error'], currentPrice: 0 };
    }
}

async function shouldClosePosition(position, accountId) {
    try {
        if (!ticker) throw new Error('TickerAll not initialized');
        
        const price = await ticker.market.getPrice(accountId, position.symbol);
        const currentPrice = position.side === 'buy' ? price.bid : price.ask;
        const profitPercent = ((currentPrice - position.entryPrice) / (position.entryPrice || 1)) * 100 * (position.side === 'buy' ? 1 : -1);
        
        const rates = await ticker.market.getHistory(accountId, {
            symbol: position.symbol,
            timeframe: 'M1',
            limit: 20
        });
        const prices = rates.map(r => r.close);
        const rsi = calculateRSI(prices);
        const momentum = ((prices[prices.length - 1] - prices[prices.length - 3]) / (prices[prices.length - 3] || 1)) * 100;
        
        let shouldClose = false;
        let reason = '';
        
        if (profitPercent > 0) {
            if (profitPercent >= 2) {
                shouldClose = true;
                reason = `High profit ${profitPercent.toFixed(2)}%`;
            } else if (profitPercent >= 1) {
                if ((position.side === 'buy' && rsi > 65) || (position.side === 'sell' && rsi < 35)) {
                    shouldClose = true;
                    reason = `Profit ${profitPercent.toFixed(2)}% with reversal signal`;
                } else if ((position.side === 'buy' && momentum < 0) || (position.side === 'sell' && momentum > 0)) {
                    shouldClose = true;
                    reason = `Profit ${profitPercent.toFixed(2)}% with weakening momentum`;
                }
            }
        } else if (profitPercent < 0) {
            if (profitPercent <= -1.5) {
                shouldClose = true;
                reason = `Stop loss ${Math.abs(profitPercent).toFixed(2)}%`;
            }
        }
        
        if (shouldClose) console.log(`🎯 CLOSE ${position.symbol}: ${reason}`);
        return { shouldClose, reason, profitPercent, currentPrice };
    } catch (error) {
        console.error('Close decision error:', error.message);
        return { shouldClose: false, reason: 'Error', profitPercent: 0, currentPrice: 0 };
    }
}

// ==================== TRADING ENGINE ====================
const engines = {};

class HalalTradingEngine {
    constructor(sessionId, userEmail, config, accountId) {
        this.sessionId = sessionId;
        this.userEmail = userEmail;
        this.config = config;
        this.accountId = accountId;
        this.isActive = true;
        this.currentProfit = 0;
        this.trades = [];
        this.winStreak = 0;
        this.analysisInterval = null;
        this.monitorInterval = null;
        this.startTime = Date.now();
        this.openPositions = [];
    }
    
    async start() {
        console.log(`🕋 Starting Halal trading engine for ${this.userEmail}`);
        console.log(`   Investment: $${this.config.investmentAmount} | Target: $${this.config.targetProfit} | Time: ${this.config.timeLimit}h`);
        console.log(`   ⚡ HIGH SPEED MODE: Analysis EVERY SECOND!`);
        
        this.analysisInterval = setInterval(async () => {
            if (!this.isActive) return;
            
            const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
            if (elapsedHours >= this.config.timeLimit) {
                console.log(`⏰ Time limit reached for ${this.userEmail}`);
                await this.stop();
                return;
            }
            
            if (this.currentProfit >= this.config.targetProfit) {
                console.log(`🎯 Target reached! Total profit: $${this.currentProfit.toFixed(2)}`);
                await this.stop();
                return;
            }
            
            for (const symbol of this.config.tradingPairs) {
                if (!this.isActive) break;
                
                const hasPosition = this.openPositions.some(p => p.symbol === symbol);
                
                if (!hasPosition) {
                    try {
                        const signal = await getAISignal(symbol, this.accountId);
                        
                        if (signal.action === 'BUY' && signal.confidence >= 0.55) {
                            await this.executeTrade(symbol, 'buy', signal);
                        } else if (signal.action === 'SELL' && signal.confidence >= 0.55) {
                            await this.executeTrade(symbol, 'sell', signal);
                        }
                    } catch (error) {
                        console.error(`Analysis error for ${symbol}:`, error.message);
                    }
                }
            }
        }, 1000);
        
        this.monitorInterval = setInterval(async () => {
            if (!this.isActive) return;
            
            for (const position of this.openPositions) {
                try {
                    const closeDecision = await shouldClosePosition(position, this.accountId);
                    
                    if (closeDecision.shouldClose) {
                        await this.closePosition(position, closeDecision.profitPercent, closeDecision.currentPrice);
                    }
                } catch (error) {
                    console.error(`Monitor error:`, error.message);
                }
            }
        }, 1000);
    }
    
    async executeTrade(symbol, side, signal) {
        if (this.openPositions.some(p => p.symbol === symbol)) return;
        
        try {
            if (!ticker) throw new Error('TickerAll not initialized');
            
            const result = await fetchBalance(this.accountId);
            const balance = result.balance;
            console.log(`💰 Current balance for ${this.userEmail}: ${balance} ${result.currency}`);
            
            let volume = this.config.investmentAmount / 100000;
            if (volume < 0.01) volume = 0.01;
            if (volume > 1.0) volume = 1.0;
            
            if (balance < this.config.investmentAmount + 50) {
                console.log(`⚠️ Insufficient balance: ${balance} ${result.currency}`);
                return;
            }
            
            const price = await ticker.market.getPrice(this.accountId, symbol);
            const entryPrice = side === 'buy' ? price.ask : price.bid;
            
            console.log(`📈 Opening ${side.toUpperCase()} for ${symbol} with ${volume} lots at $${entryPrice.toFixed(5)}`);
            console.log(`   AI Confidence: ${(signal.confidence * 100).toFixed(0)}% | Reason: ${signal.reasons[0]}`);
            
            const order = await ticker.orders.place(this.accountId, {
                type: 'market',
                symbol: symbol,
                side: side.toUpperCase(),
                volume: volume
            });
            
            this.openPositions.push({
                symbol: symbol,
                side: side,
                volume: volume,
                entryPrice: entryPrice,
                orderId: order.id,
                openedAt: Date.now(),
                aiConfidence: signal.confidence,
                aiReason: signal.reasons[0]
            });
            
            this.trades.unshift({
                symbol: symbol,
                side: `${side.toUpperCase()} OPEN`,
                entryPrice: entryPrice.toFixed(5),
                volume: volume,
                aiConfidence: `${(signal.confidence * 100).toFixed(0)}%`,
                aiReason: signal.reasons[0],
                timestamp: new Date().toISOString()
            });
            
            console.log(`✅ ${side.toUpperCase()} opened for ${symbol} at $${entryPrice.toFixed(5)}`);
        } catch (error) {
            console.error(`Trade execution error:`, error.message);
        }
    }
    
    async closePosition(position, profitPercent, currentPrice) {
        try {
            if (!ticker) throw new Error('TickerAll not initialized');
            
            await ticker.orders.close(this.accountId, position.orderId);
            
            const profit = (profitPercent / 100) * (position.volume * 100000 * position.entryPrice);
            this.currentProfit += profit;
            this.winStreak = profit > 0 ? this.winStreak + 1 : 0;
            
            this.trades.unshift({
                symbol: position.symbol,
                side: `${position.side.toUpperCase()} CLOSED`,
                entryPrice: position.entryPrice.toFixed(5),
                exitPrice: currentPrice.toFixed(5),
                profit: profit.toFixed(2),
                profitPercent: profitPercent.toFixed(2),
                timestamp: new Date().toISOString()
            });
            
            const tradeFile = path.join(tradesDir, this.userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(tradeFile)) allTrades = JSON.parse(fs.readFileSync(tradeFile));
            allTrades.unshift({
                symbol: position.symbol,
                side: position.side,
                entryPrice: position.entryPrice,
                exitPrice: currentPrice,
                profit: profit,
                profitPercent: profitPercent,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(tradeFile, JSON.stringify(allTrades, null, 2));
            
            this.openPositions = this.openPositions.filter(p => p.orderId !== position.orderId);
            
            const profitSymbol = profit >= 0 ? '+' : '';
            console.log(`✅ CLOSED ${position.symbol} | Profit: ${profitSymbol}$${profit.toFixed(2)} (${profitPercent.toFixed(2)}%) | Total: $${this.currentProfit.toFixed(2)}`);
        } catch (error) {
            console.error(`Close error:`, error.message);
        }
    }
    
    async stop() {
        console.log(`🛑 Stopping Halal trading engine for ${this.userEmail}`);
        this.isActive = false;
        
        if (this.analysisInterval) clearInterval(this.analysisInterval);
        if (this.monitorInterval) clearInterval(this.monitorInterval);
        
        for (const position of this.openPositions) {
            try {
                const closeDecision = await shouldClosePosition(position, this.accountId);
                await this.closePosition(position, closeDecision.profitPercent, closeDecision.currentPrice);
            } catch (error) {
                console.error(`Stop close error:`, error.message);
            }
        }
    }
    
    getStatus() {
        const elapsedHours = (Date.now() - this.startTime) / (1000 * 60 * 60);
        const timeRemaining = Math.max(0, this.config.timeLimit - elapsedHours);
        const progressPercent = this.config.targetProfit > 0 ? (this.currentProfit / this.config.targetProfit) * 100 : 0;
        
        return {
            isActive: this.isActive,
            currentProfit: this.currentProfit || 0,
            targetProfit: this.config.targetProfit || 0,
            winStreak: this.winStreak || 0,
            timeRemaining: timeRemaining || 0,
            progressPercent: progressPercent || 0,
            openPositions: this.openPositions.length || 0,
            trades: this.trades.slice(0, 30)
        };
    }
}

app.post('/api/start-trading', authenticate, async (req, res) => {
    try {
        const { investmentAmount, targetProfit, timeLimit, tradingPairs } = req.body;
        
        if (investmentAmount < 3) return res.status(400).json({ success: false, message: 'Minimum investment is $3' });
        if (targetProfit < 1) return res.status(400).json({ success: false, message: 'Target profit must be at least $1' });
        if (!timeLimit || timeLimit < 0.1) return res.status(400).json({ success: false, message: 'Time limit must be at least 0.1 hours' });

        const users = readUsers();
        const user = users[req.user.email];
        if (!user.tickerallSessionId) return res.status(400).json({ success: false, message: 'Please add Exness credentials first' });

        if (!ticker) {
            return res.status(500).json({ success: false, message: 'TickerAll not initialized. Please set API key in admin panel.' });
        }

        const result = await fetchBalance(user.tickerallSessionId);
        const balance = result.balance;
        
        if (balance < investmentAmount) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} ${result.currency}, need ${investmentAmount} USD` });
        }

        const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
        
        const config = {
            investmentAmount: investmentAmount,
            targetProfit: targetProfit,
            timeLimit: timeLimit,
            tradingPairs: tradingPairs || ['XAUUSD', 'EURUSD', 'GBPUSD']
        };
        
        const engine = new HalalTradingEngine(sessionId, req.user.email, config, user.tickerallSessionId);
        engines[sessionId] = engine;
        await engine.start();
        
        res.json({ 
            success: true, 
            sessionId, 
            message: `✅ HALAL TRADING STARTED! Investment: $${investmentAmount} | Target: $${targetProfit} | ⚡ HIGH SPEED: Analysis EVERY SECOND!` 
        });
    } catch (error) {
        console.error('Start trading error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (engines[sessionId]) {
        engines[sessionId].stop();
        delete engines[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const engine = engines[sessionId];
    if (!engine) return res.json({ success: true, currentProfit: 0, newTrades: [], isActive: false });
    
    const status = engine.getStatus();
    res.json({
        success: true,
        currentProfit: status.currentProfit || 0,
        targetProfit: status.targetProfit || 0,
        newTrades: status.trades || [],
        winStreak: status.winStreak || 0,
        timeRemaining: status.timeRemaining || 0,
        progressPercent: status.progressPercent || 0,
        openPositions: status.openPositions || 0,
        isActive: status.isActive
    });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: Date.now() }));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL EXNESS TRADING BOT`);
    console.log(`✅ Server: http://localhost:${PORT}`);
    console.log(`✅ Login: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ Minimum Investment: $3`);
    console.log(`✅ Default Time Limit: 1 hour (configurable higher)`);
    console.log(`✅ ⚡ HIGH SPEED: Analysis EVERY SECOND!`);
    console.log(`✅ NO FIXED TAKE PROFIT - AI decides when to close`);
    console.log(`✅ Admin can update TickerAll API key with validation`);
    console.log(`✅ 100% Halal - No Riba, No Gharar, No Maysir\n`);
});
