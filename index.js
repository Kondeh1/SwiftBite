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
import { Server } from "socket.io";
import http from "http";
import crypto from "crypto";
import nodemailer from "nodemailer";

env.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRound = 10;
const server = http.createServer(app);
const io = new Server(server);

io.on("connection", (socket) => {
  console.log("Admin connected to live dashboard");
});

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: process.env.EMAIL_USER,
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

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

app.get("/forget", async (req, res) => {
  res.render("forgetPassword.ejs");
});

app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [
      req.user.id,
    ]);
    const user = result.rows[0];

    if (!user.role) {
      return res.redirect("/choose-role");
    }
    const role = user.role.toLowerCase();
    console.log(role);

    if (role === "admin") {
      // res.render("admin/home.ejs");
      res.redirect("/admin/dashboard");
    } else if (role === "customer") {
      res.render("customers/home.ejs");
    } else {
      res.render("manager/home.ejs");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/dashboard", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    try {
      const userRes = await db.query("SELECT COUNT(*) FROM users");
      const restRes = await db.query(
        "SELECT COUNT(*) FROM users WHERE role = 'manager'",
      );

      const activityRes = await db.query(
        "SELECT full_name, role, created_at FROM users ORDER BY created_at DESC LIMIT 5",
      );

      res.render("admin/home.ejs", {
        currentPage: "dashboard",
        user: req.user,
        stats: {
          users: userRes.rows[0].count,
          restaurants: restRes.rows[0].count,
          orders: 0,
        },
        activities: activityRes.rows,
      });
    } catch (err) {
      console.error(err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/verification", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    res.render("admin/verification.ejs", {
      currentPage: "verification",
      user: req.user,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/accounts", async (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    // const result = await db.query(
    //   "SELECT * FROM users ORDER BY created_at DESC",
    // );
    res.render("admin/accounts.ejs", {
      currentPage: "accounts",
      users: ["result.rows", "result.rows", "result.rows", "result.rows"],
      user: req.user,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/monitoring", (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    res.render("admin/monitoring.ejs", {
      currentPage: "monitoring",
      user: req.user,
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/admin/settings", (req, res) => {
  if (req.isAuthenticated() && req.user.role?.toLowerCase() === "admin") {
    res.render("admin/settings.ejs", {
      currentPage: "settings",
      user: req.user,
    });
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
  console.log("user new: ", req.user.full_name);
  // await db.query("SELECT full_name FROM users WHERE id = $1")
  const googleUser = req.user.full_name;
  if (req.isAuthenticated()) {
    res.render("choose-role.ejs", { name: googleUser });
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logOut((err) => {
    res.render("landing.ejs");
  });
});

app.get("/resetPassword/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const result = await db.query(
      "SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()",
      [token],
    );

    if (result.rows.length > 0) {
      res.render("resetPassword.ejs", { token: token });
    } else {
      res.status(400).render("forgetPassword.ejs", {
        message:
          "The reset link is invalid or has expired. Please request a new one.",
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const userCheck = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (userCheck.rows.length === 0) {
      return res.render("forgetPassword.ejs", { message: "Email not found." });
    }

    const token = crypto.randomBytes(20).toString("hex");
    const expires = new Date(Date.now() + 3600000);

    await db.query(
      "UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3",
      [token, expires, email],
    );

    const resetLink = `http://localhost:3000/resetPassword/${token}`;

    console.log("RESET LINK:", resetLink);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "SwiftBite Password Reset",
      html: `
  <p>Hello,</p>
  <p>We received a request to reset the password for your SwiftBite account.</p>
  <p>Please click the link below to set a new password:</p>
  <p><a href="${resetLink}" style="color: #e67e22; font-weight: bold;">Reset My Password</a></p>
  <p>If you did not request this, you can safely ignore this email.</p>
`,
    };

    await transporter.sendMail(mailOptions);
    res.render("index.ejs", {
      message: "Check your email for the reset link.",
    });
  } catch (err) {
    console.error(err);
    res.render("forgetPassword.ejs", {
      message: "Error sending email. Try again later.",
    });
  }
});

app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.render("resetPassword.ejs", {
      token,
      message: "Passwords do not match.",
    });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    const result = await db.query(
      "UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = $2 AND reset_token_expires > NOW() RETURNING *",
      [hash, token],
    );

    if (result.rows.length > 0) {
      res.render("index.ejs", {
        message: "Password updated successfully. You can now log in.",
      });
    } else {
      res.status(400).render("forgotPassword.ejs", {
        message:
          "This link is invalid or has expired. Please request a new one.",
      });
    }
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).send("Internal Server Error.");
  }
});

app.post("/set-role", async (req, res) => {
  const role = req.body.role.toLowerCase();
  // console.log("User: ", role);
  // console.log("id:", req.user.id);
  try {
    await db.query("UPDATE users SET role = $1 WHERE id = $2", [
      role,
      req.user.id,
    ]);
    req.user.role = role;
    res.redirect("/dashboard");
  } catch (err) {
    console.error("this", err);
    console.log("This", err);
    res.redirect("/dashboard");
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

    // console.log(result.rows);
    if (result.rows.length > 0) {
      // console.log("User already exists");
      res.render("index.ejs", {
        message: "The user you want to register already exist.",
      });
    } else {
      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          // console.log(`Error occurred when hashing password ${err}`);
          res.status(500).send("Error creating account");
        } else {
          try {
            const newUser = await db.query(
              "INSERT INTO users(full_name, email, password_hash, role) VALUES($1, $2, $3, $4) RETURNING *",
              [fullname, email, hash, role],
            );

            const countRes = await db.query("SELECT COUNT(*) FROM users");
            const totalUsers = countRes.rows[0].count;

            io.emit("update-user-count", {
              total: totalUsers,
              name: fullname,
            });

            const user = newUser.rows[0];
            console.log(user);

            req.login(user, (err) => {
              if (err) {
                // console.log("Error logging in user:", err);
                res.redirect("/login");
              } else {
                res.redirect("/dashboard");
              }
            });
          } catch (dbErr) {
            // console.log("Database error:", dbErr);
            res.status(500).send("Error creating account");
          }
        }
      });
    }
  } catch (err) {
    // console.log("Error checking existing user:", err);
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
    // console.log(email, password);
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    // console.log(email);
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
      // console.log("User not found, Please Sign Up");
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
      // console.log(profile.displayName);

      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        profile.email,
      ]);
      // console.log(result);

      if (result.rows.length > 0) {
        cb(null, result.rows[0]);
      } else {
        // console.log("log");
        const newUser = await db.query(
          "INSERT INTO users(full_name, email, password_hash, role) VALUES($1, $2, $3, $4) RETURNING *",
          [profile.displayName, profile.email, "google", null],
        );

        // const newUserCount = await db.query("SELECT COUNT(*) FROM users");
        const countRes = await db.query("SELECT COUNT(*) FROM users");
        const totalUsers = countRes.rows[0].count;

        io.emit("update-user-count", {
          total: totalUsers,
          name: profile.displayName,
        });

        return cb(null, newUser.rows[0]);
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

server.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
