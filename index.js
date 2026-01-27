import express from "express";
import axios from "axios";
import pg from "pg";
import bodyParser from "body-parser";
import env from "dotenv";
import passport from "passport";
import session from "express-session";

env.config();

const app = express();
const port = 3000;

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  }),
);

app.use(passport.session());
app.use(passport.initialize());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

const db = new pg.Client({
  user: "postgres",
  host: process.env.HOST_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: "SwiftBite",
});

db.connect();

app.get("/", async (req, res) => {
  const result = await db.query("SELECT user_name, user_role FROM users");
  res.render("index.ejs");
});

app.post("/login", async (req, res) => {
  const {email, password} = req.body;

  console.log(email, password);
});

app.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
