
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const timePassed = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

const images = [
    "bird1.jpg",
    "bird2.jpg",
    "bird3.jpg"
  ];

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("403", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        // User is not logged in
        res.render('unauthenticated');
    } else {
        // User is logged in
        console.log(req.session);
        res.render('authenticated', { username: req.session.username });
    }
});


app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.render('nosql');
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});


app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username) {
        res.render("signup_error", { error: "Name" });
    }
    if (!email) {
        res.render("signup_error", { error: "Email" });
    }
    if (!password) {
        res.render("signup_error", { error: "Password" });
    }
    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("signup_error", { error: `${validationResult.error.message}` });
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword, user_type: "user" });
    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    console.log("Inserted user");
    res.redirect("/members");
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("signup_error", { error: `${validationResult.error.message}` });
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, username: 1, user_type: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        res.render("signup_error", { error: "No such user found" });
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = timePassed;
        res.redirect('/members');
        return;
    }
    else {
        res.render("signup_error", { error: "Wrong password entered" });
        return;
    }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({username: 1, user_type:1, _id: 1}).toArray();
    res.render("admin", {users: result});
});

app.post('/promote', async (req, res) => {
    const {userId} = req.body;
    const myRole = req.body.role;
    console.log(userId);
    console.log(myRole);
    const ObjectId = require('mongodb').ObjectId;
    try {
      await userCollection.updateOne({  _id: new ObjectId(userId) }, { $set: { user_type: myRole } });
      res.redirect('/admin');
    } catch (err) {
      console.log(err);
      res.status(500).send('An error occurred when promoting the user.');
    }
  });

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }
    const email = req.session.email;
    const username = req.session.username;
    res.render("members", {email: email, username: username , images: images});
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 