
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

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

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
      res.send(`
        <h1>Sign up or login here!</h1>
        <button onclick="window.location.href='/signup'">Sign Up</button>
        <br>
        <br>
        <button onclick="window.location.href='/login'">Log In</button>
      `);
    } else {
      // User is logged in
      console.log(req.session);
      res.send(`
        <h1>Hello and welcome ${req.session.username}!</h1>
        <br>
        <a href="/members">Go to Members area</a>
        <br>
        <br>
        <a href="/logout">Log out</a>
      `);
    }
  });
  

  app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>User not provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});


app.get('/signup', (req, res) => {
    var html = `
    <p>Create a new user</p>
    <form action='/signupSubmit' method='post'>
    <label for="username">Username:</label>
    <input name='username' type='text' placeholder='name'>
    <br>
    <label for="email">Email:</label>
    <input type="email" id="email" name="email" placeholder='email'>
    <br>
    <label for="password">Password:</label>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if (!username || !email || !password) {
        var errorMsg = "Please provide ";
        if (!username) {
            errorMsg += "a username";
        } else if (!email) {
            errorMsg += "an email address";
        } else {
            errorMsg += "a password";
        }
        errorMsg += ".";
        res.send(`${errorMsg} <br> <a href="/signup">Try again please</a>`);
        return;
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
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
    req.session.authenticated = true;  // set the authentication flag to true
    req.session.email = email;  // set the email for the user in the session
    req.session.username = username;  // set the username for the user in the session
    console.log("Inserted user");
    res.redirect("/members");
});

app.get('/login', (req, res) => {
    var html = `
    <p style='font-size:1.2rem;'>Log in to your account please!</p>
    <form action='/loggingin' method='post'>
    <label for="email" style='font-size:1.2rem;'>Email:</label> 
    <input name='email' type='email' placeholder='email'>
    <br>
    <label for="password" style='font-size:1.2rem;'>Password:</label>
    <input name='password' type='password' placeholder='Password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`<p style='font-size:1.2rem;'> Email/Password combination is invalid. </p> <br> <a href="/login">Try again</a>`);
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1,username: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.send(`<p style='font-size:1.2rem;'> Email/Password combination is invalid.</p> <br> <a href="/login">Try again</a>`);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = timePassed;
        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.send(`Email/Password combination is invalid. <br> <a href="/login">Try again</a>`);
        return;
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
    var myNum = Math.round(Math.random() * 2) + 1;
    var html = `
    <h1>Hello and welcome ${req.session.username}.</h1>
    <br>
    <br>
    <img src='/bird${myNum}.jpg' style='width:500px;'>
    <br>
    <br>
    <a href="/logout">Log out</a>
    `;
    res.send(html);
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 