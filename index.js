const mysql = require("mysql");
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const emailValidator = require("email-validator");
const bcrypt = require("bcrypt");
const {OAuth2Client} = require("google-auth-library");

const ALLOWED_ORIGINS = ["http://localhost:3001", "http://localhost:3000", "https://unrequitedhumor.com"];
const GOOGLE_CLIENT_ID = "453835501464-dho2cqor3l58bjqukplg64iviqjjajit.apps.googleusercontent.com";

const oauthClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const dbPool = mysql.createPool({
  connectionLimit: 10,
  host: "localhost",
  user: "unrequitedhumor",
  password: "password",
  database: "unrequitedhumor"
});

async function query(sql, values) {
  return new Promise((resolve, reject) => {
    if (!dbPool) return reject(new Error("Database not initialized!"));
    dbPool.query(sql, values, (err, res) => {
      if (err) {
        console.warn("Failed to execute query:", sql, err);
        return reject("MySQL Error");
      }
      resolve(res);
    });
  });
}

function makeHash(length) {
  let result = "";
  let hexChars = "0123456789abcdefghijklmnopqrstuvwxyz";
  for (let i = 0; i < length; i += 1) {
    result += hexChars[Math.floor(Math.random() * hexChars.length)];
  }
  return result;
}

async function createLoginToken(userId) {
  let token = makeHash(8);
  await query(`INSERT INTO logins (userId, token) VALUES (?, ?)`, [userId, token]);
  return userId + ":" + token;
}

async function validateToken(req, res) {
  let token = req.cookies.token;
  if (!token) {
    res.json({loggedIn: false});
    return false;
  }

  const clearToken = (req, res) => {
    res.clearCookie("token");
    res.json({loggedIn: false, error: "Invalid token"});
    return false;
  };

  token = token.split(":");
  if (token.length !== 2) return clearToken(req, res);

  let userId = token[0];
  token = token[1];

  let queryResult = await query(`SELECT userId FROM logins WHERE userId = ? AND token = ?`, [userId, token]);
  if (queryResult.length === 0) return clearToken(req, res);

  return userId;
}

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

app.get("/status", (req, res) => {
  res.json({status: "OK"});
});

app.post("/login", async (req, res) => {
  try {
    let email = req.body.email;
    let password = req.body.password;

    if (!email) return res.json({error: "Your email address cannot be left blank"});
    else if (!password) return res.json({error: "Your password cannot be left blank"});

    let queryResult = await query("SELECT * FROM users WHERE email = ?", [email]);

    if (queryResult.length === 0) {
      return res.json({error: "There is no account registered for that email"});
    }

    let userData = queryResult[0];

    // The user has already signed up using a google account
    if (userData["googleUserId"]) return res.json({error: "Please sign in with Google"});

    const passwordsMatch = await bcrypt.compare(password, userData["passwordHash"]);
    if (!passwordsMatch) return res.json({error: "Invalid password"});

    let userId = userData["userId"];
    let loginToken = await createLoginToken(userId);

    console.info("token: ", loginToken);
    res.cookie("token", loginToken, {httpOnly: true, path: "/"});
    return res.json({
      success: true,
      token: loginToken,
      user: {
        id: userId,
        email: userData["email"],
        emailVerified: !!userData["emailVerified"],
        firstName: userData["firstName"],
        lastName: userData["lastName"]
      }
    });
  } catch (e) {
    console.error("Email login caused error: ", e);
    return res.json({error: "An unexpected error occurred. Please try again"});
  }
});

app.post("/register", async (req, res) => {
  try {
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let email = req.body.email;
    let password = req.body.password;

    if (!firstName || !lastName) return res.json({error: "A name is required"});
    else if (!email) return res.json({error: "An email address is required"});
    else if (!password) return res.json({error: "A password is required"});

    if (!emailValidator.validate(email)) return res.json({error: "Your email address is invalid"});
    else if (password.length < 8) return res.json({error: "Your password must be at least 8 characters long"});

    let queryResult = await query("SELECT * FROM users WHERE email = ?", [email]);

    // An account already exists with the given email
    if (queryResult.length > 0) {
      if (queryResult[0]["googleUserId"]) return res.json({error: "Please sign in with Google"});
      return res.json({error: "You've already registered an account with that email"});
    }

    let passwordHash = await bcrypt.hash(password, 10);
    let insertResult = await query(
      `INSERT INTO users (email, firstName, lastName, passwordHash) VALUES (?, ?, ?, ?)`,
      [email, firstName, lastName, passwordHash]
    );

    let userId = insertResult.insertId;
    let loginToken = await createLoginToken(userId);

    res.cookie("token", loginToken, {httpOnly: true, path: "/"});
    return res.json({
      success: true,
      token: loginToken,
      user: {
        id: userId,
        email: email,
        emailVerified: false,
        firstName: firstName,
        lastName: lastName
      }
    });
  } catch (e) {
    console.error("Email registration caused error: ", e);
    return res.json({
      error: "An unexpected error occurred. Please try again"
    });
  }
});

app.post("/google-login", async (req, res) => {
  try {
    let token = req.body.token;

    if (!token) return res.json({error: "Missing authentication token"});

    const ticket = await oauthClient.verifyIdToken({
      idToken: token,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    const googleUserId = payload["sub"];
    const email = payload["email"];

    let queryRes = await query(`SELECT * FROM users WHERE googleUserId = ? OR email = ?`, [googleUserId, email]);
    if (queryRes.length > 0) {
      let userData = queryRes[0];

      // The email is already registered for another account
      if (userData["googleUserId"].toString() !== googleUserId.toString()) {
        return res.json({error: "Please log in using your password"});
      }

      // Return the existing matching google account
      return res.json({
        success: true,
        user: {
          id: userData["userId"],
          email: userData["email"],
          emailVerified: !!userData["emailVerified"],
          firstName: userData["firstName"],
          lastName: userData["lastName"]
        }
      });
    }

    const emailVerified = payload["email_verified"];
    const firstName = payload["given_name"];
    const lastName = payload["family_name"];

    let insertRes = await query(
      `INSERT INTO users (email, emailVerified, firstName, lastName, googleUserId) VALUES (?, ?, ?, ?, ?)`,
      [email, emailVerified, firstName, lastName, googleUserId]
    );

    let userId = insertRes.insertId;
    let loginToken = await createLoginToken(userId);

    res.cookie("token", loginToken, {httpOnly: true, path: "/"});
    return res.json({
      success: true,
      token: loginToken,
      user: {
        id: userId,
        email: email,
        emailVerified: emailVerified,
        firstName: firstName,
        lastName: lastName
      }
    });
  } catch (e) {
    console.error("Google login caused error: ", e);
    return res.json({error: "An unexpected error occurred. Please try again"});
  }
});

app.get("/user", async (req, res) => {
  let userId = await validateToken(req, res);
  if (!userId) return;

  let queryResults = await query("SELECT * from users WHERE userId = ?", [userId]);
  if (queryResults.length === 0) return res.json({error: "Invalid User ID"});

  let userData = queryResults[0];

  res.json({
    loggedIn: true,
    user: {
      id: userData["userId"],
      email: userData["email"],
      emailVerified: !!userData["emailVerified"],
      firstName: userData["firstName"],
      lastName: userData["lastName"]
    }
  });
})

app.listen(3001, () => {
  console.info("Server running on port 3001");
});