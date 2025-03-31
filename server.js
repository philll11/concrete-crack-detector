// server.js
require('dotenv').config(); // Load .env file variables into process.env
const express = require('express');
const axios = require('axios');   // For making HTTP requests to Azure
const multer = require('multer'); // For handling file uploads
const path = require('path');     // For working with file paths
const session = require('express-session'); // For session management (needed for flash)
const flash = require('connect-flash');   // For flash messages

// --- Configuration ---
const app = express();
const PORT = process.env.PORT || 3000; // Use port from env or default to 3000

// Get Azure Credentials (securely from environment variables)
const PREDICTION_ENDPOINT_URL = process.env.PREDICTION_ENDPOINT_URL;
const AZURE_API_KEY = process.env.AZURE_API_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET) {
    console.error("FATAL ERROR: SESSION_SECRET is not set in the .env file.");
    process.exit(1); // Exit if session secret is missing
}

// --- Middleware Setup ---

// Serve static files (CSS, client-side JS) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Tell Express where to find view files

// Session middleware configuration
app.use(session({
    secret: SESSION_SECRET, // Secret used to sign the session ID cookie
    resave: false,          // Don't save session if unmodified
    saveUninitialized: false // Don't create session until something stored
    // Add cookie settings here if needed (e.g., secure: true for HTTPS)
}));

// Flash message middleware (depends on session)
app.use(flash());

// Middleware to make flash messages available in all templates
app.use((req, res, next) => {
    res.locals.flashMessages = req.flash(); // Makes messages available in views as 'flashMessages'
    next();
});

// Multer configuration for handling file uploads
// We'll store the file in memory as a buffer, as we don't need to save it to disk
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 16 * 1024 * 1024 }, // Optional: Limit file size (e.g., 16MB)
    fileFilter: (req, file, cb) => {
        // Accept only specific image types
        const allowedTypes = /jpeg|jpg|png/;
        const mimetype = allowedTypes.test(file.mimetype);
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Error: File upload only supports the following filetypes - ' + allowedTypes));
        }
    }
// The key 'imageFile' matches the 'name' attribute of the file input in the form
}).single('imageFile');

// --- Helper Function for Azure API Call ---
async function callAzurePredictionAPI(imageBuffer) {
    if (!PREDICTION_ENDPOINT_URL || !AZURE_API_KEY) {
        console.error("Azure endpoint URL or API Key is not configured.");
        // Throw an error that the route handler can catch
        throw new Error("Server configuration error: Azure credentials missing.");
    }

    // --- Prepare the request for Azure ---
    // IMPORTANT: Adjust headers based on YOUR Azure endpoint's requirements!
    const headers = {
        // This content type is common for sending raw image data
        'Content-Type': 'application/octet-stream',
        // Common header for Azure ML Service key, might be different (e.g., 'Prediction-Key')
        'Authorization': `Bearer ${AZURE_API_KEY}`
        // OR if your key doesn't need 'Bearer ':
        // 'Ocp-Apim-Subscription-Key': AZURE_API_KEY // Example for some Azure services
        // Add any other required headers here
    };

    console.log(`Sending prediction request to: ${PREDICTION_ENDPOINT_URL}`);
    try {
        const response = await axios.post(PREDICTION_ENDPOINT_URL, imageBuffer, {
             headers: headers,
             timeout: 60000 // 60 second timeout
        });

        console.log(`Azure Response Status Code: ${response.status}`);
        console.log(`Azure Response Data:`, response.data); // Log the response data

        // --- Process the Azure response ---
        // Axios automatically parses JSON responses by default
        // IMPORTANT: Adjust how you access the prediction based on YOUR Azure endpoint's output!
        if (response.data && (response.data.prediction || response.data.predicted_label || Object.keys(response.data).length > 0)) {
             // Attempt to standardize the output slightly if possible
            if (response.data.predicted_label && !response.data.prediction) {
                 response.data.prediction = response.data.predicted_label;
            }
            return response.data; // Return the parsed JSON data
        } else {
            console.error("Prediction key not found or unexpected response structure:", response.data);
            throw new Error("Received an unexpected response structure from Azure AI service.");
        }

    } catch (error) {
        console.error("Error calling Azure AI service:");
        if (error.response) {
            // The request was made and the server responded with a status code
            // that falls out of the range of 2xx
            console.error('Status:', error.response.status);
            console.error('Headers:', error.response.headers);
            console.error('Data:', error.response.data);
            // Provide a more specific error message
            throw new Error(`Azure API Error: ${error.response.status} - ${error.response.data?.message || error.response.data || 'Unknown error'}`);
        } else if (error.request) {
            // The request was made but no response was received
            console.error('Request Error:', error.request);
            throw new Error("Network error: No response received from Azure AI service.");
        } else if (error.message.startsWith('Error: File upload only supports')) {
             // Handle the specific multer file type error
             throw error; // Re-throw the specific error
        }
         else {
            // Something happened in setting up the request that triggered an Error
            console.error('Error:', error.message);
            throw new Error(`An unexpected error occurred: ${error.message}`);
        }
    }
}

// --- Routes ---

// GET Route for the homepage (display upload form)
app.get('/', (req, res) => {
    // Render index.ejs, passing any flash messages if they exist
    res.render('index');
});

// POST Route to handle the file upload and prediction
app.post('/predict', (req, res) => {
    // Use multer middleware to handle the upload
    upload(req, res, async (err) => {
        // Handle Multer errors (e.g., file size, file type)
        if (err instanceof multer.MulterError) {
            console.error("Multer error:", err);
            req.flash('error', `File Upload Error: ${err.message}`);
            return res.redirect('/');
        } else if (err) {
             // Handle other errors during upload (e.g., our custom file filter error)
            console.error("Upload error:", err);
            req.flash('error', err.message || 'An unexpected error occurred during file upload.');
            return res.redirect('/');
        }

        // Check if a file was actually uploaded
        if (!req.file) {
            req.flash('error', 'No file selected for upload.');
            return res.redirect('/');
        }

        // File uploaded successfully, proceed to call Azure
        try {
            const imageBuffer = req.file.buffer; // Get the image data from memory
            const originalFilename = req.file.originalname; // Get the original filename

            const predictionResult = await callAzurePredictionAPI(imageBuffer);

            // Render the result page with the prediction data
            res.render('result', {
                prediction: predictionResult,
                filename: originalFilename
            });

        } catch (apiError) {
            // Handle errors from the callAzurePredictionAPI function
            console.error("API call failed:", apiError);
            req.flash('error', `Prediction Failed: ${apiError.message}`);
            res.redirect('/');
        }
    });
});

// --- Global Error Handler (Optional but recommended) ---
// Catches errors not handled in specific routes
app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.stack || err);
    req.flash('error', 'An unexpected server error occurred.');
    // Avoid redirect loops, maybe render an error page or just redirect to home
    if (!res.headersSent) {
       res.redirect('/');
    } else {
       next(err); // Pass to default Express error handler if headers already sent
    }
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
    // Startup check for Azure credentials
    if (!PREDICTION_ENDPOINT_URL || !AZURE_API_KEY) {
        console.warn("\n*** WARNING: PREDICTION_ENDPOINT_URL or AZURE_API_KEY not found in .env file. ***");
        console.warn("*** The application will run, but predictions WILL FAIL.        ***\n");
    } else {
        console.log("Azure credentials loaded successfully.");
    }
});