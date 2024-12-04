

const express = require('express');
const passport = require('passport');
const cors = require('cors');
const userService = require('./user-service.js');
const jwt = require('jsonwebtoken');
const passportJWT = require('passport-jwt');
require('dotenv').config();

const app = express();
const HTTP_PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());

// Passport JWT Strategy
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
}, (jwtPayload, done) => {
    return done(null, jwtPayload);
}));

// Connect to MongoDB
userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => {
            console.log(`API listening on port: ${HTTP_PORT}`);
        });
    })
    .catch((err) => {
        console.log('Unable to start the server:', err);
        process.exit();
    });

app.get("/", (req, res) => {
    res.json({ message: "User API is running." });
});

app.get("/api/user", (req, res) => {
    res.json({ message: "api/user is running." });
});

app.post('/api/user/login', (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            // Generate JWT payload
            const payload = { _id: user._id, username: user.userName };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.json({ message: 'Login successful', token });  // Return JWT token
        })
        .catch(msg => {
            res.status(422).json({ message: msg });
        });
});

app.post('/api/user/register', (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({ message: msg }); // Return success message
        })
        .catch((err) => {
            console.error("Registration error:", err); // Log the error for debugging
            res.status(422).json({ message: err }); // Return the error message
        });
});



app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getFavourites(req.user._id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

app.put('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

app.delete('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

app.get('/api/user/history', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getHistory(req.user._id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

app.put('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

app.delete('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});