//jshint esversion:6

const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const passport = require('passport');
const session = require('express-session');
const passportLocalMongoose = require('passport-local-mongoose'); //will salt and hash passwords automatically
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({
    extended: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // cookie: {
    //     secure: true
    // }
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DB_LOCAL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: [{
        type: String
    }]
});

userSchema.plugin(passportLocalMongoose); //make sure you use the schema to plugin.
userSchema.plugin(findOrCreate); //db finds first, if user doesnt exist then, will be created.

const User = new mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            facebookId: profile.id
        }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render('home');
})

app.get("/auth/google",
    passport.authenticate('google', {
        scope: ["profile"]
    })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', {
        failureRedirect: "/login"
    }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get("/auth/facebook",
    passport.authenticate('facebook', {
        scope: 'public_profile'
    })
);

app.get("/auth/facebook/secrets",
    passport.authenticate('facebook', {
        failureRedirect: '/login'
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    })

app.route("/secrets")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            User.find({
                secret: {
                    $ne: null
                } //not equal to null
            }, function (err, foundUsers) {
                if (err) {
                    console.log(err);
                } else {
                    if (foundUsers) {
                        res.render('secrets', {
                            usersWithSecrets: foundUsers
                        });
                    }
                }
            });
        } else {
            res.redirect('/login');
        }
    })


app.route("/login")
    .get(function (req, res) {
        res.render('login');
    })
    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function (err) {
            passport.authenticate("local", {
                successRedirect: "/secrets",
                failureRedirect: "/login",
                failureFlash: true,
            })(req, res, function () {
                res.redirect("/secrets");
            });

        });
    })

app.route("/register")
    .get(function (req, res) {
        res.render('register');
    })
    .post(function (req, res) {
        User.register({
            username: req.body.username
        }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        });
    })

app.route("/submit")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            User.findById(req.user.id, function (err, foundUser) {
                if (!err) {
                    res.render("submit", {
                        secrets: foundUser.secret
                    });
                }
            })
        } else {
            res.redirect("/login");
        }
    })
    .post(function (req, res) {
        if (req.isAuthenticated()) {
            User.findById(req.user.id, function (err, user) {
                user.secret.push(req.body.secret);
                user.save(function () {
                    res.redirect("/secrets");
                });
            });

        } else {
            res.redirect("/login");
        }
    })

app.post("/submit/delete", function (req, res) {
    if (req.isAuthenticated()) {
        User.findById(req.user.id, function (err, foundUser) {
            foundUser.secret.splice(foundUser.secret.indexOf(req.body.secret), 1);
            foundUser.save(function (err) {
                if (!err) {
                    res.redirect("/secrets");
                }
            });
        });
    } else {
        res.redirect("/login");
    }
})

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect('/');
})

app.listen(3000, function () {
    console.log("server started on port 3000");
})