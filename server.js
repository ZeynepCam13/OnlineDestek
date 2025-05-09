// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const port = process.env.port||3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: 'güçlü-bir-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // localde secure false!
}));

// Veritabanı bağlantısı
const db = new sqlite3.Database('./database.db');

// Tablo oluşturma
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'open',
        user_id INTEGER
    )`);
});

// API: Kayıt Ol
app.post('/api/register', async (req, res) => {
    const { fullname, email, phone, username, password } = req.body;

    if (!fullname || !email || !phone || !username || !password) {
        return res.status(400).json({ error: 'Tüm alanlar doldurulmalıdır.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Şifre en az 6 karakter olmalıdır.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (fullname, email, phone, username, password) VALUES (?, ?, ?, ?, ?)',
        [fullname, email, phone, username, hashedPassword],
        function(err) {
            if (err) {
                console.error(err);
                res.status(500).json({ error: 'Kayıt başarısız: Kullanıcı adı veya e-posta zaten mevcut olabilir.' });
            } else {
                res.status(201).json({ message: 'Kayıt başarılı', userId: this.lastID });
            }
        });
});

// API: Giriş Yap
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Sunucu hatası' });

        if (user && await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            res.json({ message: 'Giriş başarılı', user: { id: user.id, username: user.username } });
        } else {
            res.status(401).json({ error: 'Kullanıcı adı veya şifre yanlış' });
        }
    });
});

// API: Çıkış Yap
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Çıkış yapılamadı' });
        res.json({ message: 'Çıkış başarılı' });
    });
});

// API: Kullanıcı Profili
app.get('/api/profile', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Giriş yapmanız gerekiyor' });

    db.get('SELECT id, fullname, email, phone, username FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Sunucu hatası' });
        res.json({ user });
    });
});

// API: Kullanıcının Kendi Ticket'ları
app.get('/api/tickets', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Giriş yapmanız gerekiyor' });

    db.all('SELECT * FROM tickets WHERE user_id = ?', [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// API: Belirli bir ticket'ı ID ile getir
app.get('/api/tickets/:id', (req, res) => {
    const ticketId = req.params.id;

    db.get('SELECT * FROM tickets WHERE id = ?', [ticketId], (err, ticket) => {
        if (err) {
            return res.status(500).json({ error: 'Sunucu hatası' });
        }
        if (!ticket) {
            return res.status(404).json({ error: 'Talep bulunamadı' });
        }
        res.json(ticket);
    });
});

// API: Ticket Oluştur
app.post('/api/tickets', (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Giriş yapmanız gerekiyor' });

    const { title, description } = req.body;
    db.run('INSERT INTO tickets (title, description, user_id) VALUES (?, ?, ?)', 
        [title, description, req.session.userId], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ id: this.lastID, title, description, status: 'open' });
        });
});

// API: Admin tüm ticket'ları görebilsin
app.get('/api/admin/tickets', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Giriş yapmanız gerekiyor' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Sunucu hatası' });

        if (!user || user.username !== 'admin') {
            return res.status(403).json({ error: 'Sadece admin erişebilir' });
        }

        db.all('SELECT * FROM tickets', [], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        });
    });
});

// API: Admin ticket durumu güncelle
app.post('/api/admin/tickets/:id/status', (req, res) => {
    const ticketId = req.params.id;
    const { status } = req.body;

    db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Sunucu hatası' });
        if (!user || user.username !== 'admin') {
            return res.status(403).json({ error: 'Sadece admin erişebilir' });
        }

        db.run('UPDATE tickets SET status = ? WHERE id = ?', [status, ticketId], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Veritabanı hatası' });
            }
            res.json({ message: 'Durum güncellendi' });
        });
    });
});

// Sunucuyu Başlat
app.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor`);
});

