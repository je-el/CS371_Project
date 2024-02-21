const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));

// Special characters
const specialChar = /[!@#$%^&*(),.?":{}|<>]/;

// Dummy database for demo
const users = {};

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

const saltRounds = 10;

app.use(express.static('public'));

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if the password meets requirements
  if (!password || password.length < 8) {
    return res.send('Password must be at least 8 characters long.');
  }

  // Check for special character
  if(!specialChar.test(password)){
    return res.send('Must include at least 1 special character: !@#$%^&*(),.?":{}|<>');
  }

  if (users[username]) {
    // User exists, check password
    const match = await bcrypt.compare(password, users[username]);
    if (match) {
      req.session.user = username;
      res.send('Logged in successfully!');
    } else {
      res.send('Incorrect password.');
    }
  } else {
    // No user found, create a new one
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    users[username] = hashedPassword;
    req.session.user = username;
    res.send('Account created successfully!');
  }
});

// Serve the login page for the root URL
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
  });
  // Serve static files from the 'public' directory
app.use(express.static('public'));

