require('dotenv').config();
const http = require('http');
const https = require('https');

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;

// ✅ Connexion à une base persistante
const db = new sqlite3.Database('./database.db');

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
  secret: 'clé-de-session-tres-secrete',
  resave: false,
  saveUninitialized: true
}));

// ✅ Création de la table si elle n'existe pas
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT
  )`, () => {
    // Ajout d’un admin si vide
    db.get("SELECT COUNT(*) AS count FROM users", (err, row) => {
      if (row.count === 0) {
        db.run("INSERT INTO users (username, password) VALUES ('admin', 'admin123')");
        db.run("INSERT INTO users (username, password) VALUES ('user', 'user123')");
      }
    });
  });
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    author TEXT,
    content TEXT
  )`);
});

// 📦 Fonction pour rendre une page HTML avec layout
function renderWithLayout(res, viewFile, options = {}) {
  const viewPath = path.join(__dirname, 'views', viewFile);
  const layoutPath = path.join(__dirname, 'views', 'layout.html');

  fs.readFile(viewPath, 'utf8', (err, viewContent) => {
    if (err) return res.status(500).send('Erreur de vue.');

    fs.readFile(layoutPath, 'utf8', (err, layoutContent) => {
      if (err) return res.status(500).send('Erreur de layout.');

      let finalHtml = layoutContent;

      // Inject content
      finalHtml = finalHtml.replace('{{content}}', viewContent);
      finalHtml = finalHtml.replace('{{username}}', options.username || '');
      finalHtml = finalHtml.replace('{{error}}', options.error || '');
      finalHtml = finalHtml.replace('{{comments}}', options.comments || '');

      // Auth UI blocks
      if (options.isLoggedIn) {
        finalHtml = finalHtml
          .replace(/<!-- IF_LOGGED_IN -->/g, '')
          .replace(/<!-- END_IF -->/g, '')
          .replace(/<!-- LOGIN_FORM -->[\s\S]*?<!-- END_LOGIN -->/g, '')
      } else {
        finalHtml = finalHtml
          .replace(/<!-- IF_LOGGED_IN -->[\s\S]*?<!-- END_IF -->/g, '')
          .replace(/<!-- LOGOUT_FORM -->[\s\S]*?<!-- END_LOGOUT -->/g, '')
      }

      res.send(finalHtml);
    });
  });
}


// 🏠 Routes

app.get('/', (req, res) => {
  renderWithLayout(res, 'home.html', {
    isLoggedIn: req.session.loggedIn,
    username: req.session.username
  });
});

app.get('/about', (req, res) => {
  renderWithLayout(res, 'about.html', {
    isLoggedIn: req.session.loggedIn,
    username: req.session.username
  });
});

app.get('/secret-insecure', (req, res) => {
  renderWithLayout(res, 'secret.html', {
    isLoggedIn: req.session.loggedIn,
    username: req.session.username
  });
});

app.get('/secret', (req, res) => {
  if (!req.session.loggedIn) {
    res.redirect('/');
  } else {
    renderWithLayout(res, 'secret.html', {
      isLoggedIn: req.session.loggedIn,
      username: req.session.username
    });
  }
});

app.get('/login', (req, res) => {
  renderWithLayout(res, 'login.html', {
    isLoggedIn: req.session.loggedIn,
    username: req.session.username
  });
});

app.get('/login-insecure', (req, res) => {
  renderWithLayout(res, 'login-insecure.html', {
    isLoggedIn: req.session.loggedIn,
    username: req.session.username
  });
});

// 🔓 Login vulnérable à l’injection SQL
app.post('/login-insecure', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log('Requête SQL exécutée :', query);

  db.get(query, (err, row) => {
    if (row) {
      req.session.loggedIn = true;
      req.session.username = row.username;
      res.redirect('/');
    } else {
      renderWithLayout(res, 'login-insecure.html', {
        isLoggedIn: false,
        username: '',
        error: '❌ Identifiants invalides'
      });
    }
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, row) => {
    if (row) {
      req.session.loggedIn = true;
      req.session.username = row.username;
      res.redirect('/');
    } else {
      renderWithLayout(res, 'login.html', {
        isLoggedIn: false,
        username: '',
        error: '❌ Identifiants invalides'
      });
    }
  });
});

// 🔐 Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// 🔓 Route vulnérable à la LFI
app.get('/page', (req, res) => {
  const page = req.query.name;
  const filePath = path.join(__dirname, 'pages', page);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(404).send('❌ Page introuvable');
    } else {
      res.send(data);
    }
  });
});

// Vulnérable à XSS stockée
app.get('/comments-xss', (req, res) => {
  db.all("SELECT * FROM comments", (err, rows) => {
    const commentsHtml = rows.map(c =>
      `<li><strong>${c.author}</strong>: ${c.content}</li>`
    ).join('');
    renderWithLayout(res, 'comments-xss.html', {
      comments: commentsHtml,
      isLoggedIn: req.session.loggedIn,
      username: req.session.username
    });
  });
});

app.post('/comments-xss', (req, res) => {
  const { author, content } = req.body;
  db.run("INSERT INTO comments (author, content) VALUES (?, ?)", [author, content], () => {
    res.redirect('/comments-xss');
  });
});

// Protégée contre XSS
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

app.get('/comments-safe', (req, res) => {
  db.all("SELECT * FROM comments", (err, rows) => {
    const commentsHtml = rows.map(c =>
      `<li><strong>${escapeHtml(c.author)}</strong>: ${escapeHtml(c.content)}</li>`
    ).join('');
    renderWithLayout(res, 'comments-safe.html', {
      comments: commentsHtml,
      isLoggedIn: req.session.loggedIn,
      username: req.session.username
    });
  });
});

app.post('/comments-safe', (req, res) => {
  const { author, content } = req.body;
  db.run("INSERT INTO comments (author, content) VALUES (?, ?)", [author, content], () => {
    res.redirect('/comments-safe');
  });
});

// 🚀 Serveur
const MODE = process.env.MODE || 'dev';

if (MODE === 'prod') {
  // Lecture du certificat auto-signé
  const privateKey = fs.readFileSync('./certs/selfsigned.key', 'utf8');
  const certificate = fs.readFileSync('./certs/selfsigned.crt', 'utf8');
  const credentials = { key: privateKey, cert: certificate };

  // Serveur HTTPS principal
  https.createServer(credentials, app).listen(443, () => {
    console.log('🔐 Serveur HTTPS lancé sur le port 443');
  });

  // Redirection HTTP → HTTPS
  http.createServer((req, res) => {
    const host = req.headers.host.replace(/:\d+$/, '');
    res.writeHead(301, { Location: `https://${host}${req.url}` });
    res.end();
  }).listen(80, () => {
    console.log('🌐 Redirection HTTP → HTTPS active sur le port 80');
  });

} else {
  // Mode développement : HTTP simple
  const PORT = 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Mode DEV - Serveur HTTP sur http://localhost:${PORT}`);
  });
}