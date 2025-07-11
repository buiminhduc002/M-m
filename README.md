// even_odd_game_app.js // ------------------------------------------------------------ // Production‑ready EVEN/ODD betting app  ‑ demo integration MoMo // ------------------------------------------------------------ // 1️⃣  CÀI ĐẶT //    npm init -y //    npm install express express-session body-parser sqlite3 bcrypt axios dotenv uuid // // 2️⃣  TẠO FILE .env (cùng thư mục) //    PORT=3000 //    SESSION_SECRET=changeme //    MOMO_PARTNER_CODE=YOUR_PARTNER_CODE //    MOMO_ACCESS_KEY=YOUR_ACCESS_KEY //    MOMO_SECRET_KEY=YOUR_SECRET_KEY //    MOMO_REDIRECT_URL=https://yourdomain.com/momo_callback //    MOMO_IPN_URL=https://yourdomain.com/momo_ipn // // 3️⃣  KHỞI CHẠY //    node even_odd_game_app.js // // ™️  Ghi chú: MoMo yêu cầu tài khoản Business để lấy key. Bạn có thể dùng //             môi trường test (https://test-payment.momo.vn)

require('dotenv').config(); const express = require('express'); const session = require('express-session'); const bodyParser = require('body-parser'); const sqlite3 = require('sqlite3').verbose(); const bcrypt = require('bcrypt'); const axios = require('axios'); const crypto = require('crypto'); const { v4: uuidv4 } = require('uuid');

const app = express(); const PORT = process.env.PORT || 3000;

// ----------------------- DATABASE ----------------------- const db = new sqlite3.Database('db.sqlite'); db.serialize(() => { db.run(CREATE TABLE IF NOT EXISTS users( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, balance INTEGER DEFAULT 0 )); db.run(CREATE TABLE IF NOT EXISTS transactions( id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, trans_id TEXT, amount INTEGER, status TEXT, type TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP )); });

// ----------------------- MIDDLEWARE --------------------- app.use(bodyParser.urlencoded({ extended: true })); app.use( session({ secret: process.env.SESSION_SECRET || 'supersecret', resave: false, saveUninitialized: false, cookie: { httpOnly: true }, }) );

app.use((req, res, next) => { res.locals.user = req.session.user; next(); });

function requireLogin(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }

// ----------------------- ROUTES ------------------------- app.get('/', (req, res) => { if (res.locals.user) { return res.send(<!doctype html> <h1>Chào ${res.locals.user.username}</h1> <p>Số dư: <b>${res.locals.user.balance}</b></p> <a href="/deposit">Nạp tiền MoMo</a> | <a href="/play">Chơi Chẵn/Lẻ</a> | <a href="/logout">Đăng xuất</a> ); } res.send(<!doctype html> <h1>Game Chẵn/Lẻ</h1> <a href="/register">Đăng ký</a> | <a href="/login">Đăng nhập</a> ); });

// --------- Register ------------- app.get('/register', (req, res) => { res.send(<!doctype html> <h2>Đăng ký</h2> <form method="post" action="/register"> <input name="username" required placeholder="Tên đăng nhập" /><br> <input type="password" name="password" required placeholder="Mật khẩu" /><br> <button type="submit">Tạo tài khoản</button> </form> ); });

app.post('/register', async (req, res) => { const { username, password } = req.body; const hash = await bcrypt.hash(password, 10); db.run( 'INSERT INTO users(username, password_hash) VALUES (?, ?)', [username, hash], function (err) { if (err) return res.send('❌ Tên tài khoản đã tồn tại! <a href="/register">Quay lại</a>'); res.redirect('/login'); } ); });

// ---------- Login ------------- app.get('/login', (req, res) => { res.send(<!doctype html> <h2>Đăng nhập</h2> <form method="post" action="/login"> <input name="username" required placeholder="Tên đăng nhập" /><br> <input type="password" name="password" required placeholder="Mật khẩu" /><br> <button type="submit">Đăng nhập</button> </form> ); });

app.post('/login', (req, res) => { const { username, password } = req.body; db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => { if (!user) return res.send('❌ Không tìm thấy tài khoản! <a href="/login">Thử lại</a>'); const ok = await bcrypt.compare(password, user.password_hash); if (!ok) return res.send('❌ Sai mật khẩu! <a href="/login">Thử lại</a>'); req.session.user = { id: user.id, username, balance: user.balance }; res.redirect('/'); }); });

// ---------- Logout ------------- app.get('/logout', (req, res) => { req.session.destroy(() => res.redirect('/')); });

// --------------- Deposit via MoMo ----------- app.get('/deposit', requireLogin, (req, res) => { res.send(<!doctype html> <h2>Nạp tiền MoMo</h2> <form method="post" action="/deposit"> <input type="number" name="amount" min="1000" required /> <br> <button type="submit">Tạo giao dịch</button> </form> <a href="/">Trang chủ</a> ); });

app.post('/deposit', requireLogin, async (req, res) => { const amount = parseInt(req.body.amount, 10); if (isNaN(amount) || amount < 1000) return res.send('❌ Số tiền không hợp lệ!'); const orderId = Date.now().toString(); const requestId = uuidv4(); const { MOMO_PARTNER_CODE, MOMO_ACCESS_KEY, MOMO_SECRET_KEY, MOMO_REDIRECT_URL, MOMO_IPN_URL } = process.env; const requestBody = { partnerCode: MOMO_PARTNER_CODE, accessKey: MOMO_ACCESS_KEY, requestId, amount: amount.toString(), orderId, orderInfo: Nap tien cho user ${res.locals.user.username}, redirectUrl: MOMO_REDIRECT_URL, ipnUrl: MOMO_IPN_URL, requestType: 'captureWallet', extraData: Buffer.from(JSON.stringify({ userId: req.session.user.id })).toString('base64'), lang: 'vi', };

// signature const rawSignature = accessKey=${requestBody.accessKey}&amount=${requestBody.amount}&extraData=${requestBody.extraData}&ipnUrl=${requestBody.ipnUrl}&orderId=${requestBody.orderId}&orderInfo=${requestBody.orderInfo}&partnerCode=${requestBody.partnerCode}&redirectUrl=${requestBody.redirectUrl}&requestId=${requestBody.requestId}&requestType=${requestBody.requestType}; requestBody.signature = crypto.createHmac('sha256', MOMO_SECRET_KEY).update(rawSignature).digest('hex');

try { const response = await axios.post('https://test-payment.momo.vn/v2/gateway/api/create', requestBody); const payUrl = response.data.payUrl; // Save pending transaction db.run( 'INSERT INTO transactions(user_id, trans_id, amount, status, type) VALUES (?,?,?,?,?)', [req.session.user.id, orderId, amount, 'pending', 'deposit'] ); res.redirect(payUrl); } catch (err) { console.error(err.response?.data || err); res.send('❌ Lỗi tạo thanh toán MoMo'); } });

// -------- MoMo IPN ---------- app.post('/momo_ipn', express.json(), (req, res) => { const data = req.body; const { orderId, resultCode, amount, extraData, signature } = data;

// Verify signature const { MOMO_SECRET_KEY, MOMO_ACCESS_KEY, MOMO_PARTNER_CODE } = process.env; const rawSig = accessKey=${MOMO_ACCESS_KEY}&amount=${amount}&extraData=${extraData}&ipnUrl=${process.env.MOMO_IPN_URL}&orderId=${orderId}&orderInfo=${data.orderInfo}&partnerCode=${MOMO_PARTNER_CODE}&redirectUrl=${process.env.MOMO_REDIRECT_URL}&requestId=${data.requestId}&requestType=${data.requestType}&responseTime=${data.responseTime}&resultCode=${resultCode}&transId=${data.transId}; const calcSig = crypto.createHmac('sha256', MOMO_SECRET_KEY).update(rawSig).digest('hex'); if (calcSig !== signature) return res.status(400).send({ message: 'Invalid signature' });

db.get('SELECT * FROM transactions WHERE trans_id = ?', [orderId], (err, tx) => { if (err || !tx) return; if (tx.status !== 'pending') return res.send({ message: 'duplicate' });

if (resultCode === 0) {
  // success
  db.run('UPDATE transactions SET status = ? WHERE id = ?', ['success', tx.id]);
  // credit user
  db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, tx.user_id]);
} else {
  db.run('UPDATE transactions SET status = ? WHERE id = ?', ['fail', tx.id]);
}
res.send({ message: 'ok' });

}); });

// --------- MoMo Redirect --------- app.get('/momo_callback', requireLogin, (req, res) => { res.redirect('/'); // balance update via IPN });

// --------------- Game ------------- app.get('/play', requireLogin, (req, res) => { db.get('SELECT balance FROM users WHERE id ...

