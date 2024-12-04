const express = require('express');
const passport = require('passport');
const cors = require('cors');
const userService = require('./user-service.js');
const jwt = require('jsonwebtoken');
const passportJWT = require('passport-jwt');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000; // Default Render port is 10000
const HOST = '0.0.0.0'; // Required by Render to accept connections

app.use(express.json());
app.use(cors());

// Passport JWT Strategy
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
}, (jwtPayload, done) => {
    userService.getUserById(jwtPayload._id)
        .then(user => {
            if (user) {
                return done(null, user); // Attach user to req.user
            } else {
                return done(null, false);
            }
        })
        .catch(err => done(err, false));
}));

app.use(passport.initialize());

// Connect to MongoDB
userService.connect()
    .then(() => {
        app.listen(PORT, HOST, () => {
            console.log(`Server is running on http://${HOST}:${PORT}`);
        });
    })
    .catch((err) => {
        console.error('Unable to start the server:', err);
        process.exit();
    });

// Basic Route
app.get("/", (req, res) => {
    res.json({ message: "User API is running." });
});

app.get("/api/user", (req, res) => {
    res.json({ message: "api/user is running." });
});

// User Login
app.post('/api/user/login', (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            const payload = { _id: user._id, username: user.userName };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.json({ message: 'Login successful', token }); // Return JWT token
        })
        .catch(msg => {
            console.error('Login error:', msg);
            res.status(422).json({ message: msg });
        });
});

// User Registration
app.post('/api/user/register', (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({ message: msg }); // Return success message
        })
        .catch((err) => {
            console.error("Registration error:", err); // Log the error
            res.status(422).json({ message: err }); // Return error message
        });
});

// Secured Favourites Routes
app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getFavourites(req.user._id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Get favourites error:", err);
            res.status(422).json({ error: err });
        });
});

app.put('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Add favourite error:", err);
            res.status(422).json({ error: err });
        });
});

app.delete('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Remove favourite error:", err);
            res.status(422).json({ error: err });
        });
});

// Secured History Routes
app.get('/api/user/history', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getHistory(req.user._id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Get history error:", err);
            res.status(422).json({ error: err });
        });
});

app.put('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Add history error:", err);
            res.status(422).json({ error: err });
        });
});

app.delete('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Remove history error:", err);
            res.status(422).json({ error: err });
        });
});
