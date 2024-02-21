const fs = require('fs'); // Add this line to include the fs module
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = 3000;
const USERS_FILE = './users.json'; // Specify the file path for storing users

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));

// Special characters
const specialChar = /[!@#$%^&*(),.?":{}|<>]/;

// Failed attempts
const maxFailedAttempts = 5;
const failedAttempts = {};

// Dummy database for demo
// const users = {};

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

const saltRounds = 10;

app.use(express.static('public'));

app.post('/login', async (req, res) => {
  const users = readUsersFromFile(); // Read users from file at the beginning of the route handler
  const { username, password } = req.body;
  
  if (failedAttempts[username] >= maxFailedAttempts) {
    delete users[username]; // Delete the user from the database
    delete failedAttempts[username]; // Reset the failed attempts counter
    return res.send('Your account has been deleted due to multiple failed login attempts.');
  }
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
      // Reset failed attempts counter upon successful login
      delete failedAttempts[username];
      res.send('Logged in successfully!');
    } else {
      // increment failed attempts counter
      failedAttempts[username] = (failedAttempts[username] || 0) + 1;
      res.send('Incorrect password.');
    }
  } else {
    // No user found, create a new one
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    users[username] = hashedPassword;
    req.session.user = username;
    res.send('Account created successfully!');
  }

  writeUsersToFile(users); // Write users to file after modifying the users object
});

// Serve the login page for the root URL
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
  });
  // Serve static files from the 'public' directory
app.use(express.static('public'));

// Function to read users from the file
function readUsersFromFile() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error(err);
    return {};
  }
}

// Function to write users to the file
function writeUsersToFile(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error(err);
  }
}
