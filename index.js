//require("dotenv").config();

const fs = require("fs");
const express = require("express");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const bcrypt = require("bcrypt");

const Joi = require("joi");

const app = express();

const port = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000; //Expires after one hour

//SECRETS
const mongodb_host = process.env.MONGO_HOST;
const mongodb_user = process.env.MONGO_USERNAME;
const mongodb_password = process.env.MONGO_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongodb_session_database = process.env.MONGO_DATABASE;

const node_session_secret = process.env.NODE_SESSION_SECRET;
//END OF SECRETS

const MongoClient = require("mongodb").MongoClient;
const atlasURL = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
const database = new MongoClient(atlasURL, {});

const userCollection = database.db(mongodb_user_database).collection("users");

//This allows us to use req.body
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const atlasURLSession = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?${mongodb_session_database}`;

var mongoStore = MongoStore.create({
	mongoUrl: atlasURLSession,
	crypto: {
		secret: mongodb_session_secret,
	},
});

app.use(
	session({
		secret: node_session_secret,
		store: mongoStore,
		saveUninitialized: false,
		resave: true,
	}),
);

//Image Route
app.use("/img", express.static("./public/imgs"));

//Landing Page
app.get("/", (req, res) => {
	let html;

	if (req.session.authenticated) {
		html = `<html>
            <div>
                <h1>Tyson's Cool Website</h1>
                <a href="/member">Member's Only Page</a>
                <br/>
                <a href="/logout">Log out</a>
            </div>
        </html>`;
	} else {
		html = `<html>
            <div>
                <h1>Tyson's Cool Website</h1>
                <a href="/signup">Sign-up</a>
                <br/>
                <a href="/signin">Sign-in</a>
            </div>
        </html>`;
	}

	res.status(200).send(html);
});

//Members Page
app.get("/member", (req, res) => {
	let id = req.query.id;
	const maxImages = 4;

	if (!req.query.id || id < 0 || id > maxImages) {
		id = Math.floor(Math.random() * maxImages);
	} else {
		id = req.query.id;
	}

	res.send(
		`<p>Image #${id}</p>
    <img src='/img/${id}.png' style='width:250px;'/>`,
	);
});

//Authentications
app.get("/signup", (req, res) => {
	if (req.session.authenticated) {
		res.redirect("/loggedin");
	}

	let invalidCredsHTML = `Invalid Email or password.`;
	let accountExistHTML = `Account with that email already exist.`;

	let errorMsg = req.query.err;

	let html = `
  <h1>Sign-Up</h1>
  <form action='/submitSignup' method='post'>
  <p>${
		errorMsg == 1 ? invalidCredsHTML
		: errorMsg == 2 ? accountExistHTML
		: ""
	}</p>
    <input name='email' type='email' placeholder='Email' required/>
    <input name='password' type='password' placeholder='Password' required/>
    <button>Submit</button>
  </form>
  <a href="/signin">Already have an account? Sign in here.</a>
  `;

	res.status(200).send(html);
});

app.get("/signin", (req, res) => {
	if (req.session.authenticated) {
		res.redirect("/loggedin");
	}
	let accountPasswordWrong = `Wrong Password`;

	let errorMsg = req.query.err;

	let html = `
  <h1>Sign-in</h1>
  <form action='/loggingin' method='post'>
  <p>${errorMsg == 3 ? accountPasswordWrong : ""}</p>
    <input name='email' type='email' placeholder='Email' required/>
    <input name='password' type='password' placeholder='Password' required/>
    <button>Submit</button>
  </form>
  <a href="/signup">Don't have an account? Sign up here.</a>
  `;

	res.status(200).send(html);
});

app.post("/submitSignup", async (req, res) => {
	if (req.session.authenticated) {
		res.redirect("/");
	}

	let email = req.body.email;
	let password = req.body.password;

	const result = await userCollection
		.find({ email: email })
		.project({ username: 1, password: 1, _id: 1 })
		.toArray();

	if (result.length >= 1) {
		console.log("Email Already has an account");
		res.redirect("/signup?err=2");

		return;
	}

	const schema = Joi.object({
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required(),
	});

	if (schema.validate({ email, password }).error != null) {
		console.log("Invalid User credintials!");
		res.redirect("signup?err=1");
		return;
	}

	const saltRounds = bcrypt.genSaltSync(10);
	let hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({ email: email, password: hashedPassword });

	let html = `
  <p>You are now signed in! Email: ${email}</p>
  <a href='/'>Back to main page</a>
  `;

	res.status(200).send(html);
});

app.post("/loggingin", async (req, res) => {
	if (req.session.authenticated) {
		res.redirect("/");
	}

	let email = req.body.email;
	let password = req.body.password;

	const schema = Joi.string().email().required();
	if (schema.validate(email).error != null) {
		console.log("Invalid Email");
		res.redirect("/signin");

		return;
	}

	const result = await userCollection
		.find({ email: email })
		.project({ username: 1, password: 1, _id: 1 })
		.toArray();

	if (result.length != 1) {
		console.log("User Not Found");
		res.redirect("/signin");

		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		console.log("Correct password");
		req.session.authenticated = true;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;
		res.redirect("/loggedIn");

		return;
	} else {
		console.log("Incorrect Password");
		res.redirect("/signin?err=3");

		return;
	}
});

app.get("/loggedin", (req, res) => {
	if (!req.session.authenticated) {
		res.redirect("/signin");
	}

	let html = `
  <p>You are logged in</p>
  <a href='/'>Back to main page</a>`;

	res.send(html);
});

app.get("/logout", (req, res) => {
	req.session.destroy();

	let html = `
  <p>You are logged out</p>
  <a href='/'>Back to main page</a>
  `;

	res.send(html);
});

app.use((req, res) => {
	res.status(404).send("404 - Page not found");
});
//End of Authentication

if (require.main === module) {
	app.listen(port, () => {
		console.log(`Server listening on http://localhost:${port}`);
	});
}
