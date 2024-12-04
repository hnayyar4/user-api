const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
dotenv.config();
const userService = require("./user-service.js");

const HTTP_PORT = process.env.PORT || 8080;

const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;

// JWT Strategy Configuration
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET || 'defaultSecret'
};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
    userService.getUserById(jwt_payload._id)
        .then(user => {
            if (user) {
                return done(null, user);
            } else {
                console.error("User not found for payload:", jwt_payload);
                return done(null, false);
            }
        })
        .catch(err => {
            console.error("Error in JWT verification:", err);
            return done(err, false);
        });
}));

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

// User Registration Route
app.post("/api/user/register", (req, res) => {
    console.log("Register request received:", req.body);
    userService.registerUser(req.body)
        .then((msg) => {
            console.log("User registered successfully:", msg);
            res.json({ "message": msg });
        }).catch((msg) => {
            console.error("Error in registration:", msg);
            res.status(422).json({ "message": msg });
        });
});

// User Login Route with JWT
app.post("/api/user/login", (req, res) => {
    console.log("Login request received:", req.body);
    userService.checkUser(req.body)
        .then(user => {
            const payload = { _id: user._id, userName: user.userName };
            const token = jwt.sign(payload, process.env.JWT_SECRET || 'defaultSecret', { expiresIn: '1h' });
            console.log("Login successful, token generated:", token);
            res.json({ message: "login successful", token: token });
        })
        .catch(msg => {
            console.error("Error in login:", msg);
            res.status(422).json({ message: msg });
        });
});

// Secured Routes with Logging
app.get("/api/user/favourites", passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log("Get favourites request for user:", req.user._id);
    userService.getFavourites(req.user._id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Error getting favourites:", err);
            res.status(422).json({ error: err });
        });
});

app.put("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log("Add favourite request for user:", req.user._id, "Favourite ID:", req.params.id);
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Error adding favourite:", err);
            res.status(422).json({ error: err });
        });
});

app.delete("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log("Remove favourite request for user:", req.user._id, "Favourite ID:", req.params.id);
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Error removing favourite:", err);
            res.status(422).json({ error: err });
        });
});

app.get("/api/user/history", passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log("Get history request for user:", req.user._id);
    userService.getHistory(req.user._id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Error getting history:", err);
            res.status(422).json({ error: err });
        });
});

app.put("/api/user/history/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log("Add history request for user:", req.user._id, "History ID:", req.params.id);
    userService.addHistory(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Error adding history:", err);
            res.status(422).json({ error: err });
        });
});

app.delete("/api/user/history/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log("Remove history request for user:", req.user._id, "History ID:", req.params.id);
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => res.json(data))
        .catch(err => {
            console.error("Error removing history:", err);
            res.status(422).json({ error: err });
        });
});

// Connect to Database and Start Server
userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => { console.log("API listening on: " + HTTP_PORT); });
    })
    .catch((err) => {
        console.error("Unable to start the server:", err);
        process.exit();
    });
