//require("dotenv").config();

const fs = require("fs");
const express = require("express");
const session = require("express-session");
const { MongoClient, ObjectId } = require("mongodb");
const { MongoStore } = require("connect-mongo");
const bcrypt = require("bcrypt");
const ejsLint = require("ejs-lint");
const Joi = require("joi");

const app = express();
const port = process.env.PORT || 3000;

const expireTime = 60 * 60 * 1000; //Expires after one hour
const saltRoundsCounts = 10;

//SECRETS
const mongodb_host = process.env.MONGO_HOST;
const mongodb_user = process.env.MONGO_USERNAME;
const mongodb_password = process.env.MONGO_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongodb_session_database = process.env.MONGO_DATABASE;

const node_session_secret = process.env.NODE_SESSION_SECRET;
//END OF SECRETS

const atlasURL = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
const database = new MongoClient(atlasURL, {});

const userCollection = database.db(mongodb_user_database).collection("users");

//This allows us to use req.body
app.set("view engine", "ejs");
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
	})
);

//Image Route
app.use("/img", express.static("./public/imgs"));

function isValidSession(req) {
	return req.session.authenticated;
}

function sessionValidation(req, res, next) {
	if (isValidSession(req)) next();
	else res.redirect("/authenticate?type=login");
}

function isAdmin(req) {
	return req.session.user_type == "admin";
}

function adminAuthorization(req, res, next) {
	if (isAdmin(req)) next();
	else res.status(403).render("error", { error: "403 - You do not have permission to access this page." });
}

//middleware to check if user is authenticated, used for setting local variables for ejs
app.use((req, res, next) => {
	if (req.session.authenticated) {
		res.locals.authenticated = true;
		res.locals.name = req.session.name;
		res.locals.userType = req.session.user_type;
		next();
	}
	else {
		res.locals.authenticated = false;
		res.locals.userType = null;
		next();
	}
});

app.get("/", (req, res) => res.status(200).render("index"));

app.get("/member", sessionValidation, (req, res) => {
	const maxImages = 3;
	res.render("member", { max: maxImages });
});

app.get("/authenticate", (req, res) => res.status(200).render("login", { islogin: (req.query.type == "login"), errMsg: req.query.errMsg }));

app.post("/submitSignup", async (req, res) => {
	if (req.session.authenticated) res.redirect("/");

	let name = req.body.name;
	let email = req.body.email;
	let password = req.body.password;

	const result = await userCollection
		.find({ email: email })
		.project({ name: 1, password: 1, _id: 1, user_type: 1 })
		.toArray();

	if (result.length >= 1) {
		console.log("Email Already has an account");
		res.redirect("/authenticate?type=signup&errMsg=Email already has an account");
		return;
	}

	const schema = Joi.object({
		name: Joi.string().min(2).max(100).required(),
		email: Joi.string().email().required(),
		password: Joi.string().max(20).required(),
	});

	if (schema.validate({ name, email, password }).error != null) {
		res.redirect("/authenticate?type=signup&errMsg=Invalid user credentials");
		return;
	}

	const saltRounds = bcrypt.genSaltSync(saltRoundsCounts);
	let hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user" });

	req.session.authenticated = true;
	req.session.name = name;
	req.session.email = email;
	req.session.user_type = "user";
	req.session.cookie.maxAge = expireTime;
	res.redirect("/member");
});

app.post("/loggingin", async (req, res) => {
	let email = req.body.email;
	let password = req.body.password;

	const schema = Joi.string().email().required();

	if (schema.validate(email).error != null) {
		res.redirect("/authenticate?type=login&errMsg=Detected Nop-SQL Injection or Invalid Email");
		return;
	}

	const result = await userCollection
		.find({ email: email })
		.project({ name: 1, password: 1, _id: 1, user_type: 1 })
		.toArray();

	if (result.length != 1) {
		res.redirect("/authenticate?type=login&errMsg=Incorrect password/email");
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		
		req.session.authenticated = true;
		req.session.name = result[0].name;
		req.session.email = email;
		req.session.user_type = result[0].user_type;

		req.session.cookie.maxAge = expireTime;
		res.redirect("/member");
		return;
	} else {
		res.redirect("/authenticate?type=login&errMsg=Incorrect password/email");
		return;
	}
});

app.get("/logout", sessionValidation, (req, res) => {
	req.session.destroy();
	res.render("logout");
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
	const users = await userCollection.find({}).project({ name: 1, _id: 1, user_type: 1 }).toArray();
	res.render("admin", { users: users });
});

app.post("/admin/update-user-type", sessionValidation, adminAuthorization, async (req, res) => {
	const { userId, userType } = req.body;

	if (!ObjectId.isValid(userId) || !["user", "admin"].includes(userType)) {
		res.status(400).render("error", { error: "400 - Invalid user update request." });
		return;
	}

	await userCollection.updateOne(
		{ _id: new ObjectId(userId) },
		{ $set: { user_type: userType } }
	);

	res.redirect("/admin");
});

app.use((req, res) => res.status(404).render("404"));

if (require.main === module) app.listen(port, () => console.log(`Server listening on http://localhost:${port}`));
