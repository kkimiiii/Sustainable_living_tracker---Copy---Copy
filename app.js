const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const session = require('express-session');
const bcrypt = require('bcrypt');
const app = express();

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images'); // Directory to save uploaded files
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname); // Keep original filename
    }
});

const upload = multer({ storage: storage });

// Create MySQL connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Republic_C207',
    database: 'c237_miniproject1'
});

connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Set up session middleware
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));

// Middleware to set user in locals
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    next();
});

// Middleware to protect routes
const requireLogin = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

// Set up view engine
app.set('view engine', 'ejs');

// Enable static files
app.use(express.static('public'));

// Enable form processing
app.use(express.urlencoded({ extended: false }));

// Define routes
app.get('/', requireLogin, (req, res) => {
    const sql = 'SELECT * FROM goals WHERE userId = ?';
    connection.query(sql, [req.session.user.userId], (error, results) => {
        if (error) {
            console.error('Database query error:', error.message);
            return res.status(500).send('Error retrieving goals');
        }
        res.render('index', { goals: results });
    });
});

app.get('/addgoal', requireLogin, (req, res) => {
    res.render('addGoal');
});

app.post('/addgoal', requireLogin, (req, res) => {
    const { Description, StartDate, TargetDate } = req.body;
    const sql = 'INSERT INTO goals (Description, StartDate, TargetDate, userId) VALUES (?, ?, ?, ?)';
    connection.query(sql, [Description, StartDate, TargetDate, req.session.user.userId], (error, results) => {
        if (error) {
            console.error("Error adding goal:", error);
            res.status(500).send('Error adding goal');
        } else {
            res.redirect('/');
        }
    });
});

app.get('/editgoal/:id', requireLogin, (req, res) => {
    const goalId = req.params.id;
    const sql = 'SELECT * FROM goals WHERE goalId = ? AND userId = ?';
    connection.query(sql, [goalId, req.session.user.userId], (error, results) => {
        if (error) {
            console.error('Database query error:', error.message);
            return res.status(500).send('Error retrieving goal by ID');
        }
        if (results.length > 0) {
            res.render('editGoal', { goal: results[0] });
        } else {
            res.status(404).send('Goal not found');
        }
    });
});

app.post('/editgoal/:id', requireLogin, (req, res) => {
    const goalId = req.params.id;
    const { Description, StartDate, TargetDate } = req.body;
    const sql = 'UPDATE goals SET Description = ?, StartDate = ?, TargetDate = ? WHERE goalId = ? AND userId = ?';
    connection.query(sql, [Description, StartDate, TargetDate, goalId, req.session.user.userId], (error, results) => {
        if (error) {
            console.error("Error updating goal:", error);
            res.status(500).send('Error updating goal');
        } else {
            res.redirect('/');
        }
    });
});

app.get('/deletegoal/:id', requireLogin, (req, res) => {
    const goalId = req.params.id;
    const sql = 'DELETE FROM goals WHERE goalId = ? AND userId = ?';
    connection.query(sql, [goalId, req.session.user.userId], (error, results) => {
        if (error) {
            console.error("Error deleting goal:", error);
            res.status(500).send('Error deleting goal');
        } else {
            res.redirect('/');
        }
    });
});

// Registration route
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { first_name, last_name, email, username, password } = req.body;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Check if email or username already exists
        const checkSql = 'SELECT * FROM users WHERE email = ? OR username = ?';
        connection.query(checkSql, [email, username], (error, results) => {
            if (error) {
                console.error('Error checking existing user:', error);
                return res.status(500).send('Error checking existing user');
            }

            if (results.length > 0) {
                return res.status(400).send('Email or username already exists');
            }

            // Insert the new user
            const sql = 'INSERT INTO users (first_name, last_name, email, username, password) VALUES (?, ?, ?, ?, ?)';
            connection.query(sql, [first_name, last_name, email, username, hashedPassword], (error, results) => {
                if (error) {
                    console.error('Error registering user:', error);
                    return res.status(500).send('Error registering user');
                }

                // Set the user session
                req.session.user = { userId: results.insertId, username, email };
                res.redirect('/questionnaire');
            });
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        res.status(500).send('Error registering user');
    }
});


// Questionnaire route
app.get('/questionnaire', requireLogin, (req, res) => {
    res.render('questionnaire');
});

app.post('/submit-questionnaire', requireLogin, (req, res) => {
    const { plastic_bags, recycle, public_transport, garden } = req.body;
    const suggestions = [];

    if (plastic_bags === 'always' || plastic_bags === 'sometimes') {
        suggestions.push('Reduce plastic waste');
    }
    if (recycle === 'never' || recycle === 'sometimes') {
        suggestions.push('Increase recycling');
    }
    if (public_transport === 'never') {
        suggestions.push('Use public transport more often');
    }
    if (garden === 'yes') {
        suggestions.push('Plant trees');
    }

    res.render('suggestions', { suggestions });
});

// Suggestions route
app.get('/suggestions', requireLogin, (req, res) => {
    res.render('suggestions');
});

// Login route
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ? OR email = ?';
    connection.query(sql, [username, username], async (error, results) => {
        if (error) {
            console.error('Database query error:', error.message);
            return res.status(500).send('Error retrieving user');
        }
        if (results.length > 0 && await bcrypt.compare(password, results[0].password)) {
            req.session.user = results[0];
            res.redirect('/');
        } else {
            res.status(401).send('Invalid username or password');
        }
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Profile route
app.get('/profile', requireLogin, (req, res) => {
    res.render('profile', { user: req.session.user });
});

// Handle profile update
app.post('/profile', requireLogin, (req, res) => {
    const { first_name, last_name, email, username } = req.body;
    const sql = 'UPDATE users SET first_name = ?, last_name = ?, email = ?, username = ? WHERE userId = ?';
    connection.query(sql, [first_name, last_name, email, username, req.session.user.userId], (error, results) => {
        if (error) {
            console.error('Error updating profile:', error);
            res.status(500).send('Error updating profile');
        } else {
            req.session.user.first_name = first_name;
            req.session.user.last_name = last_name;
            req.session.user.email = email;
            req.session.user.username = username;
            res.redirect('/profile');
        }
    });
});

// Articles route
app.get('/articles', requireLogin, (req, res) => {
    res.render('articles');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
