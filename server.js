require('dotenv').config({ path: './config.env' }); // Load secrets from config.env

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // CORS middleware for security

const app = express();
const PORT = process.env.PORT || 5000; // Use Render's assigned port

// --- CORS Configuration ---
const allowedOrigins = process.env.ALLOWED_ORIGIN.split(',');
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like Postman or server-to-server)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true // Allow cookies/authorization headers
}));
// --- End CORS ---


// Middleware
app.use(express.json()); // Allows server to read JSON data from requests

// 1. DATABASE CONNECTION
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected Successfully.'))
    .catch(err => console.error('MongoDB Connection Error:', err));


// 2. MONGOOSE SCHEMAS (MODELS)
// Admin Model (for login)
const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const Admin = mongoose.model('Admin', AdminSchema);

// Account Inventory Model
const AccountSchema = new mongoose.Schema({
    snapUsername: { type: String, required: true },
    snapPasswordEncrypted: { type: String, required: true }, // Highly sensitive data
    price: { type: Number, default: 0 },
    score: { type: String },
    status: { type: String, default: 'Available' }
});
const Account = mongoose.model('Account', AccountSchema);


// 3. AUTHENTICATION MIDDLEWARE
const protectAdminRoute = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) return res.status(401).json({ message: 'Access Denied: No Token Provided.' });
    
    const token = authHeader.split(' ')[1]; 
    if (!token) return res.status(401).json({ message: 'Access Denied: Invalid Token Format.' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.adminId = verified.id;
        next();
    } catch (err) {
        res.status(400).json({ message: 'Invalid Token or Token Expired.' });
    }
};


// ... (Previous imports and setup remain the same)

// 4. API ROUTES

// A. LOGIN ROUTE (Public)
app.post('/api/admin/login', async (req, res) => {
    // ... (Existing login code remains same)
    const { username, password } = req.body;
    try {
        const admin = await Admin.findOne({ username });
        if (!admin) return res.status(400).json({ message: 'Invalid Credentials.' });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid Credentials.' });

        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ message: 'Login successful!', token });
    } catch (error) {
        res.status(500).json({ message: 'Server error.' });
    }
});

// B. ADD NEW ACCOUNT (Protected - Admin Only)
app.post('/api/admin/accounts/add', protectAdminRoute, async (req, res) => {
    const { snapUsername, snapPassword, price, score } = req.body;
    try {
        const newAccount = new Account({
            snapUsername,
            snapPasswordEncrypted: snapPassword, 
            price,
            score,
            status: 'Available'
        });
        await newAccount.save();
        res.status(201).json({ message: 'Account added successfully!', account: newAccount });
    } catch (error) {
        res.status(500).json({ message: 'Failed to add account.', error: error.message });
    }
});

// C. GET ALL ACCOUNTS (Protected - For Admin Dashboard)
app.get('/api/admin/accounts', protectAdminRoute, async (req, res) => {
    try {
        const accounts = await Account.find(); // Admin sees everything
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch accounts.' });
    }
});

// *** NEW: PUBLIC ROUTE FOR WEBSITE (No Password Required) ***
// This allows product.html to show available accounts securely
app.get('/api/public/accounts', async (req, res) => {
    try {
        // Only fetch accounts that are "Available" and hide the password
        const accounts = await Account.find({ status: 'Available' }).select('-snapPasswordEncrypted -__v');
        res.json(accounts);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch public accounts.' });
    }
});

// D. UPDATE/DELETE ROUTES (Protected)
// ... (Keep your update/delete routes here if you have them)

// ... (Server listen code remains same)


// 5. SERVER START
app.listen(PORT, () => {
    console.log(Server is running on port ${PORT});
    
    // You must run a script to create your first admin user in MongoDB Atlas manually
    // or by running a script like this (but only once):
    // createInitialAdminUser(); 
});

// Helper function to create initial admin (Run ONLY ONCE locally or via a manual script)
/*
async function createInitialAdminUser() {
    const initialUsername = "superadmin";
    const initialPassword = "your_strong_default_password_123"; 
    
    try {
        const count = await Admin.countDocuments();
        if (count === 0) {
            const hashedPassword = await bcrypt.hash(initialPassword, 10);
            await new Admin({ username: initialUsername, password: hashedPassword }).save();
            console.log(\n!!! Initial Admin User created: ${initialUsername} / ${initialPassword} !!!\n);
        }
    } catch (e) {
        console.error("Error creating initial admin:", e);
    }
}
*/
