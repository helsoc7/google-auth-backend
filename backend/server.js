const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
require('dotenv').config();
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');

// Initialisierung von Express
const app = express();
// Initialisierung der SQLite-Datenbank
const db = new sqlite3.Database('./database.db');

// Einrichtung der Cors-Options, da wir vom Frontend auf unser Backend zugreifen wollen
const corsOptions = {
  origin: 'http://localhost:3000',
  methods: 'GET,POST,PUT,DELETE',
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.urlencoded({ extended: true }));

// Benutzersitzungen ermöglichen
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Create SQLite schema
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, googleId TEXT, secret TEXT)");
});



// Passport Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:4000/auth/google/callback",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  // Ressourcen (Name und so) mit dem Key in die Datenbank schreiben
  function(accessToken, refreshToken, profile, cb) {
    db.get("SELECT * FROM users WHERE googleId = ?", [profile.id], (err, row) => {
      if (!row) {
        // If user does not exist, create a new one
        db.run("INSERT INTO users (username, name, googleId) VALUES (?, ?, ?)", [profile.displayName, profile.displayName, profile.id], (err) => {
          db.get("SELECT * FROM users WHERE googleId = ?", [profile.id], (err, newRow) => {
            return cb(err, newRow);
          });
        });
      } else {
        return cb(null, row);
      }
    });
  }
));

// Für die Session wichtig
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
    done(err, row);
  });
});


// Routen definieren
// Leitet den Benutzer zur Authentifizierung mit Google weiter
// Eigentlicher Start des OAuth 2.0-Authentifizierungsprozesses
// scope definieren, welche Informationen die Anwendung benötigt (profile)
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);


// callback URL (wird auch in der GoogleStrategy implementiert)
// Nach der Authentifizierung und Autorisierung durch Google wird der Benutzer zusammen mit Code an diesen Endpunkt weitergeleitet
// passport verantwortlich für Tausch von Autorisierungscode gegen Access Token
// Bei Fehler, wird auf /login geleitet
// Bei Erfolg wird auf / geleitet
app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});


app.get("/", (req, res) => {
    res.send("Welcome to the homepage!");
  });

  app.get("/login", (req, res) => {
    res.send("Bitte anmelden!");
  });


  // Testausgabe, um beim Start des Servers zu sehen, welche User in unserer Datenbank sind
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error("Fehler beim Abrufen der Daten:", err);
    } else {
      console.log("Daten aus der Tabelle 'users':", rows);
    }
  });

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
