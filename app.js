const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const multer = require('multer');
const mongoose = require('mongoose');
const session = require('express-session');
const app = express();
require('dotenv').config();

// Set EJS as the view engine
app.set('view engine', 'ejs');

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const PORT = process.env.PORT || 3000;
const db = mongoose.connection;
require('dotenv').config();

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Photo Schema
const photoSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    image_data: { type: Buffer, required: true },
    file_name: { type: String, required: true },
    file_type: { type: String, required: true },
    created_at: { type: Date, default: Date.now },
});

const Photo = mongoose.model('Photo', photoSchema);

// Passport session setup
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            const user = await User.findOne({ username });
            if (!user) return done(null, false, { message: 'Invalid username or password' });

            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return done(null, user);
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
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Set up middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Set up session handling
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

// Use multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// Render the signup page
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Handle signup requests
app.post('/signup', async (req, res) => {
    const { username, email, password, password2 } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
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
    failureFlash: false
}));

// Logout route
app.get('/logout', (req, res) => {
    req.logout((err) => {
        res.redirect('/');
    });
});

// Render the home/upload page
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('index', { user: req.user });
    } else {
        res.redirect('/login');
    }
});

// Upload route
app.post('/upload', upload.single('image'), async (req, res) => {
    const { file } = req;
    const { capturedImage } = req.body; // Camera-captured base64 image

    try {
        // Handle file upload (Multer)
        if (file) {
            const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
            const fileExtension = file.originalname.split('.').pop().toLowerCase();

            if (!allowedExtensions.includes(fileExtension)) {
                return res.status(400).send('Invalid file type. Please upload an image');
            }

            const newPhoto = new Photo({
                user_id: req.user.id,
                image_data: file.buffer,
                file_name: file.originalname,
                file_type: file.mimetype,
            });

            await newPhoto.save();
            return res.redirect('/gallery');
        }

        // Handle base64-encoded camera-captured image
        if (capturedImage) {
            if (!capturedImage.startsWith('data:image/')) {
                return res.status(400).send('Invalid base64 image data');
            }

            const base64Data = capturedImage.replace(/^data:image\/\w+;base64,/, '');
            const imageBuffer = Buffer.from(base64Data, 'base64');

            const newPhoto = new Photo({
                user_id: req.user.id,
                image_data: imageBuffer,
                file_name: 'camera_capture.png',
                file_type: 'image/png',
            });

            await newPhoto.save();
            return res.redirect('/gallery');
        }

        // If no image data was found
        res.status(400).send('No image uploaded or captured');
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to upload image');
    }
});


// Gallery route
app.get('/gallery', async (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/login');

    try {
        const photos = await Photo.find({ user_id: req.user.id });
        res.render('gallery', { images: photos });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to load gallery');
    }
});

// Serve images
app.get('/image/:id', async (req, res) => {
    try {
        const photo = await Photo.findById(req.params.id);
        if (!photo) return res.status(404).send('Image not found');

        res.setHeader('Content-Type', photo.file_type);
        res.send(photo.image_data);
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to retrieve image');
    }
});

// Admin route to list users
app.get('/adminak', async (req, res) => {
    try {
        const users = await User.find();
        res.render('user', { users });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to load users');
    }
});

// Admin route to list photos
app.get('/adminak/pics/s', async (req, res) => {
    try {
        const images = await Photo.find();
        res.render('gallery', { images });
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to load photos');
    }
});
app.post('/delete-image/:id', async (req, res) => {
    try {
        const photo = await Photo.findById(req.params.id);
        if (!photo) return res.status(404).send('Image not found');

        await Photo.findByIdAndDelete(req.params.id);
        res.redirect('/gallery');
    } catch (error) {
        console.error(error);
        res.status(500).send('Failed to delete image');
    }
});



// Start the server


app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));

