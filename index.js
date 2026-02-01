import express from "express";
import axios from "axios";
import pg from "pg";
import bodyParser from "body-parser";
import env from "dotenv";
import bcrypt, { hash } from "bcrypt";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth2";
import { Strategy } from "passport-local";
import session from "express-session";
import flash from "connect-flash";

env.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRound = 10;

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  }),
);

app.use(flash());

app.use(passport.session());
app.use(passport.initialize());

app.use((req, res, next) => {
  const message = req.flash("error");
  console.log("Flash Message caught in middleware:", message);
  res.locals.error = message;
  next();
});

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
  // const result = await db.query("SELECT user_name, user_role FROM users");
  res.render("landing.ejs");
});

app.get("/getstarted", (req, res) => {
  res.render("index.ejs");
});

app.get("/singup", (req, res) => {
  res.render("singup.ejs");
});

app.get("/login", (req, res) => {
  res.render("index.ejs");
});

app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [
      req.user.id,
    ]);

    if (!req.user.role) {
      return res.redirect("/choose-role");
    }
    const role = result.rows[0].role;
    console.log(role);

    if (role === "customer") {
      res.send("<h1>Welcome to customer dashboard</h1>");
    } else {
      res.send(`<h1>Welcome to ${role} dashboard</h1>`);
    }
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/google/auth",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  }),
);

app.get(
  "/swiftbite",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  }),
);

app.get("/choose-role", async (req, res) => {
  // console.log(req.user.rows[0].full_name);
  if (req.isAuthenticated()) {
    res.render("choose-role.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/set-role", async (req, res) => {
  const { role } = req.body;
  console.log(role);
  try {
    await db.query("UPDATE users SET role = $1 WHERE id = $2", [
      role,
      req.user.id,
    ]);
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.redirect("/choose-role");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
    failureFlash: true,
  }),
);

app.post("/register", async (req, res) => {
  const { fullname, email, password, role } = req.body;
  console.log(fullname, email, password, role);

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    console.log(result.rows);
    if (result.rows.length > 0) {
      console.log("User already exists");
      res.render("index.ejs", {
        message: "The user you want to register already exist.",
      });
    } else {
      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          console.log(`Error occurred when hashing password ${err}`);
          res.status(500).send("Error creating account");
        } else {
          try {
            const newUser = await db.query(
              "INSERT INTO users(full_name, email, password_hash, role) VALUES($1, $2, $3, $4) RETURNING *",
              [fullname, email, hash, null],
            );

            const user = newUser.rows[0];
            console.log(user);

            req.login(user, (err) => {
              if (err) {
                console.log("Error logging in user:", err);
                res.redirect("/login");
              } else {
                res.redirect("/dashboard");
              }
            });
          } catch (dbErr) {
            console.log("Database error:", dbErr);
            res.status(500).send("Error creating account");
          }
        }
      });
    }
  } catch (err) {
    console.log("Error checking existing user:", err);
    res.status(500).send("Error processing request");
  }
});

passport.use(
  "local",
  new Strategy({ usernameField: "email" }, async function verify(
    email,
    password,
    cb,
  ) {
    console.log(email, password);
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    console.log(email);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storePassword = user.password_hash;
      bcrypt.compare(password, storePassword, (err, valid) => {
        if (err) {
          console.log(`Error occure when compareing password ${err}`);
          return cb(err);
        } else {
          if (valid) {
            return cb(null, user);
          } else {
            return cb(null, false, { message: "Incorrect password." });
          }
        }
      });
    } else {
      console.log("User not found, Please Sign Up");
      return cb(null, false, { message: "User not found, please sign up." });
    }
  }),
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENTID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/swiftbite",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile.displayName);

      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        profile.email,
      ]);
      console.log(result);

      if (result.rows.length > 0) {
        cb(null, result.rows[0]);
      } else {
        console.log("log");
        const newUser = await db.query(
          "INSERT INTO users(full_name, email, password_hash, role) VALUES($1, $2, $3, $4) RETURNING *",
          [profile.displayName, profile.email, "google", null],
        );

        return cb(null, newUser);
      }
    },
  ),
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
