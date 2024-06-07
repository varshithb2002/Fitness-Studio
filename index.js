import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import Razorpay from "razorpay";
import { GoogleGenerativeAI } from "@google/generative-ai";

const app = express();
const port = 3000;
const saltRounds = 10;

app.set("view engine", "ejs");

env.config();

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_ID_KEY,
  key_secret: process.env.RAZORPAY_SECRET_KEY,
});

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,  
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: process.env.PORT,
});

db.connect();

// Routes
app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/login", (req, res)=>{
    res.render("login.ejs");
});

app.get('/sign_in', (req, res)=>{
    res.render("sign_in.ejs");
});

let chatHistory = [];

app.get('/chatbot', (req, res)=>{
  res.render("chatbot.ejs", {
    chatHistory: chatHistory 
  });
});


app.get("/join", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
      const razorpayKey = process.env.RAZORPAY_ID_KEY; // Fetch your Razorpay key from environment variables or database
      const responseData = {}; // Initialize with necessary data
      res.render("join.ejs", { razorpayKey, responseData });
  } else {
      res.redirect("/login");
  }
});

// User signup route
app.post("/signup", async (req, res) => {
    const newEmail = req.body.username;
    const newPassword = req.body.password;
  
    try {
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
        newEmail,
      ]);
  
      if (checkResult.rows.length > 0) {
        res.send("Email already exists. Try logging in.");
      } else {
        // Hashing the password and saving it in the database
        bcrypt.hash(newPassword, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            console.log("Hashed Password:", hash);
            const result = await db.query(
              "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
              [newEmail, hash]
            );
            const user = result.rows[0];
            console.log(user)
            req.login(user, (err) =>{
              console.log("Success");
              res.redirect("/");
            });
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
});

// User login route
app.post("/login", passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login"
}));

// Passport local strategy configuration
passport.use(new Strategy(async function verify(username, password, cb){
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false)
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
}));

// Serialize and deserialize user
passport.serializeUser((user, cb) =>{
    cb(null, user);
});
  
passport.deserializeUser((user, cb) =>{
    cb(null, user);
});

// Contact form submission route
app.post("/contact", (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const message = req.body.message;
    
    db.query("INSERT INTO queries(name, email, msg) VALUES($1, $2, $3)", [name, email, message], (err, result) => {
      if (err) {
        console.error('Error inserting message into database:', err);
        res.status(500).send('Internal Server Error');
      } else {
        res.send('<script>alert("Message sent successfully"); window.location.href = "/";</script>');
      }
    });
});

app.post('/razorpay/checkout', async (req, res) => {
  console.log(req.body); 

  const amount = req.body.amount;
  const currency = req.body.currency;

  // Process the data as needed, for example, you can log it
  console.log(`Received amount: ${amount}, currency: ${currency}`);
  const amountInRupees = parseInt(amount);
  
  // Check if amount is a valid number
  if (isNaN(amountInRupees) || amountInRupees < 1) {
    return res.status(400).json({
      error: {
        code: 'BAD_REQUEST_ERROR',
        description: 'Invalid amount. Amount should be a valid integer greater than or equal to 1.',
        source: 'business',
        step: 'payment_initiation',
        reason: 'input_validation_failed',
        metadata: {},
        field: 'amount'
      }
    });
  }

  // Multiply amount by 100 to convert it to paise
  const amountInPaise = amountInRupees * 100;

  const options = {
      amount: amountInPaise,
      currency,
      receipt: 'receipt_order_74394', // Add an appropriate receipt number here
      payment_capture: 1,
  };

  try {
      const response = await razorpay.orders.create(options);
      const razorpayKey = process.env.RAZORPAY_ID_KEY; // Fetch your Razorpay key from environment variables or database
      console.log(process.env.RAZORPAY_ID_KEY);

      res.render('join', { razorpayKey, responseData: response });
  } catch (error) {
      console.log(error);
      res.status(500).send('Payment failed');
  }
});

const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

app.post("/new", async (req, res) => {
  const model = genAI.getGenerativeModel({ model: "gemini-pro" });
  const userInput = req.body.userInput;

  // Generating response from the AI model
  try {
    const result = await model.generateContent(userInput);
    const response = await result.response;
    const text = response.text();

    // Add user input and AI response to chat history
    chatHistory.push({ role: "user", text: userInput });
    chatHistory.push({ role: "assistant", text: text });
  } catch (error) {
    console.error("Error generating response:", error);
    chatHistory.push({ role: "assistant", text: "Oops! Something went wrong." });
  }


  res.render("chatbot", {
    chatHistory: chatHistory
  });
  console.log(chatHistory)
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
