const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
var router = express.Router();

// Middleware untuk parsing JSON
router.use(express.json());

// Koneksi ke MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'presensikita' // Sesuaikan dengan nama database Anda
});

db.connect((err) => {
    if (err) {
        throw err;
    }
    console.log('Terhubung ke database MySQL');
    console.log('Server berjalan di port 3000');
});

// Secret key untuk JWT
const jwtSecret = 'PresensiKita_KEY';

// API untuk login
router.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Cek apakah username ada di database
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, result) => {
        if (err) throw err;
        if (result.length === 0) {
            return res.status(401).json({ message: 'Username tidak ditemukan' });
        }

        const user = result[0];

        // Cek password
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (!isMatch) {
                return res.status(401).json({ message: 'Password salah' });
            }

            // hashing pass
            /*
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) throw err;
                // Simpan password yang sudah di-hash ke database
            });
            */

            // Buat token JWT
            const token = jwt.sign({ id: user.id, username: user.username }, jwtSecret, { expiresIn: '1h' });
            res.json({ message: 'Login berhasil', token });
        });
    });
});

// Middleware untuk memverifikasi token JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Token tidak tersedia' });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token tidak valid' });
        req.user = user;
        next();
    });
};

// API untuk melihat profil pengguna (autentikasi diperlukan)
router.get('/profil', authenticateToken, (req, res) => {
    const sql = 'SELECT id, username, nama, email, nomor_telepon FROM users WHERE id = ?';
    db.query(sql, [req.user.id], (err, result) => {
        if (err) throw err;
        if (result.length === 0) {
            return res.status(404).json({ message: 'Pengguna tidak ditemukan' });
        }

        res.json(result[0]);
    });
});

module.exports = router;