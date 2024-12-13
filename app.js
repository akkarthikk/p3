const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Pool } = require('pg');
const session = require('express-session');
const app = express();

// Set EJS as the view engine
app.set('view engine', 'ejs');

// PostgreSQL client setup
const connectionString = 'postgres://dpqbjroj:NxL9B1jhyXmFhuqXTYPcTULId1RxP1gL@satao.db.elephantsql.com/dpqbjroj';

const pool = new Pool({
    connectionString: connectionString
});

// Passport session setup
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
            const user = result.rows[0];

            if (!user) return done(null, false, { message: 'Invalid username or password' });

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user); // Successful authentication
            } else {
                return done(null, false, { message: 'Invalid username or password' });
            }
        } catch (error) {
            return done(error);
        }
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        done(null, result.rows[0]);
    } catch (error) {
        done(error);
    }
});

// Set up middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set up session handling
app.use(session({
    secret: 'your-secret-key',  // change this to a secure secret
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

// Use multer for file uploads
const upload = multer({ storage: multer.memoryStorage() }); // Store files in memory for database upload

// Render the signup page
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Handle signup requests
app.post('/signup', async (req, res) => {
    const { username, email, password, password2 } = req.body;

    // Hash the password before saving to the DB
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await pool.query('INSERT INTO users (username, email, password,password2) VALUES ($1, $2, $3,$4)', [username, email, hashedPassword, password2]);
        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error signing up');
    }
});

// Render the login page
app.get('/login', (req, res) => {
    res.render('login');
});

// Handle login requests
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));

// Logout the user and redirect to home page
app.get('/logout', (req, res) => {
    req.logout((err) => {
        res.redirect('/');
    });
});

// Render the image upload page
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('index', { user: req.user });
    } else {
        res.redirect('/login');
    }
});

// PostgreSQL client setup


// Serve static files
app.use(express.static('public'));

// Use multer for file uploads


// Render the image upload page
app.get('/', (req, res) => {
    res.render('index');
});

// Upload route
// app.post('/upload', upload.single('image'), async (req, res) => {
//     const { file } = req;

//     if (!file) {
//         return res.status(400).send('No image uploaded');
//     }

//     // Validate file type
//     const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
//     const fileExtension = file.originalname.split('.').pop().toLowerCase();
//     if (!allowedExtensions.includes(fileExtension)) {
//         return res.status(400).send('Invalid file type. Please upload an image');
//     }

//     // Store the file in the PostgreSQL database
//     const imageBuffer = file.buffer; // Image data as a Buffer

//     // Get the logged-in user's ID
//     const userId = req.user.id;

//     try {
//         const result = await pool.query(
//             'INSERT INTO photos (user_id, image_data, file_name, file_type) VALUES ($1, $2, $3, $4) RETURNING id',
//             [userId, imageBuffer, file.originalname, file.mimetype]
//         );
//         res.redirect("/gallery");
//     } catch (error) {
//         console.error(error);
//         res.status(500).send('Failed to upload image');
//     }
// });
app.get('/adminak', (req, res) => {
    const q = 'SELECT * FROM users';

    // Query the database
    pool.query(q, (err, result) => {
        if (err) {
            // Handle query error
            return res.status(500).send('Database query error');
        }

        // The result.rows will contain the query result
        const resultUsers = result.rows;

        // Render the ejs template and pass the resultUsers
        res.render('user', { users: resultUsers });
    });
});
app.get('/adminak/pics/s', (req, res) => {
    const q = 'SELECT * FROM photos';

    // Query the database
    pool.query(q, (err, result) => {
        if (err) {
            // Handle query error
            console.error('Database query error:', err);
            return res.status(500).send('Database query error');
        }

        // Get rows from the result
        const images = result.rows;
        res.render('gallery', { images });
    });
});


app.post('/upload', upload.single('image'), async (req, res) => {
    const { file } = req;
    const { capturedImage } = req.body;  // Captured base64 image from the camera

    // Check if a file is uploaded via the file input
    if (file) {
        // Validate file type
        const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
        const fileExtension = file.originalname.split('.').pop().toLowerCase();
        if (!allowedExtensions.includes(fileExtension)) {
            return res.status(400).send('Invalid file type. Please upload an image');
        }

        // Store the file in PostgreSQL database as Buffer
        const imageBuffer = file.buffer; // Image data as a Buffer
        const userId = req.user.id;

        try {
            const result = await pool.query(
                'INSERT INTO photos (user_id, image_data, file_name, file_type) VALUES ($1, $2, $3, $4) RETURNING id',
                [userId, imageBuffer, file.originalname, file.mimetype]
            );
            res.redirect("/gallery");
        } catch (error) {
            console.error(error);
            res.status(500).send('Failed to upload image');
        }
    }
    // Check if a base64 image is captured
    else if (capturedImage) {
        // Validate base64 image data
        if (!capturedImage.startsWith('data:image/')) {
            return res.status(400).send('Invalid base64 image data');
        }

        // Decode the base64 image and store it in PostgreSQL database as Buffer
        const base64Data = capturedImage.replace(/^data:image\/\w+;base64,/, '');
        const imageBuffer = Buffer.from(base64Data, 'base64');
        const userId = req.user.id;

        try {
            const result = await pool.query(
                'INSERT INTO photos (user_id, image_data, file_name, file_type) VALUES ($1, $2, $3, $4) RETURNING id',
                [userId, imageBuffer, 'captured_image.png', 'image/png']
            );
            res.redirect("/gallery");
        } catch (error) {
            console.error(error);
            res.status(500).send('Failed to upload base64 image');
        }
    } else {
        return res.status(400).send('No image found');
    }
});

// Gallery route
app.get('/gallery', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login'); // Redirect if the user is not authenticated
    }

    const userId = req.user.id; // Get the logged-in user's ID

    try {
        // Get the photos uploaded by the logged-in user using their user_id
        const photosResult = await pool.query(
            `SELECT photos.id, photos.file_name, photos.file_type
             FROM photos
             WHERE photos.user_id = $1`, [userId]
        );

        const images = photosResult.rows;
        console.log('Images:', images); // Log the images to check the query results

        // Render the gallery page with the user's images
        res.render('gallery', { images });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to load gallery');
    }
});







// Route to serve image from DB
app.get('/image/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query('SELECT image_data, file_type FROM photos WHERE id = $1', [id]);
        const image = result.rows[0];

        if (!image) {
            return res.status(404).send('Image not found');
        }

        // Set the appropriate content type for the image
        res.setHeader('Content-Type', image.file_type);
        res.send(image.image_data);
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to retrieve image');
    }
});

// Start the server
app.listen(3000, () => console.log('Server listening on port 3000'));
