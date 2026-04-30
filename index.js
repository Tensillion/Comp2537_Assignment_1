const express = require("express");
const session = require("express-session");

const app = express();

const node_session_secret = process.env.NODE_SESSION_SECRET;

app.use(
  session({
    secret: node_session_secret,
    resave: false,
    saveUninitialized: false,
  }),
);

const port = process.env.PORT || 3000;

// app.use(express.json());
// app.use(express.urlencoded({ extended: false }));

//Image Route
app.use("/img", express.static("./public/imgs"));

app.get("/", (req, res) => {
  res.status(200).send(
    `<html>
        <div>
            <h1>Tyson's Cool Website</h1>
            <a href="/login">Sign-up</a>
            <br/>
            <a href="/login">Sign-in</a>
        </div>
    </html>`,
  );
});

app.get("/login", (req, res) => {
  res.status(200).send("<html><h1>Title</h1></html>");
});

app.use((req, res) => {
  res.status(404).send("Not found");
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
