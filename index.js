import express from "express";
import axios from "axios";
import pg from "pg";
import bodyParser from "body-parser";
import env from "dotenv";

env.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send("<h1>Welcome to SwiftBite</h1>");
});

app.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
