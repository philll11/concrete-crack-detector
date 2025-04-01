// server.js
require('dotenv').config(); // Load .env file variables into process.env
const express = require('express');
const axios = require('axios');   // For making HTTP requests to Azure
const multer = require('multer'); // For handling file uploads
const path = require('path');     // For working with file paths
const session = require('express-session'); // For session management (needed for flash)
const flash = require('connect-flash');   // For flash messages
const crypto = require('crypto'); // Import crypto for generating unique IDs


// ################################################ Configuration ###########################################################\
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

// ################################################ Middleware Setup ###########################################################\

// Serve static files (CSS, client-side JS) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse JSON request bodies (needed for API calls)
app.use(express.json({ limit: '20mb' })); // Note: The limit is set to 20mb to accommodate larger base64 image data
// Middleware to parse URL-encoded bodies (needed for forms, though not strictly for the Kwisp call)
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
// Parse incoming request bodies (form data)
app.set('view engine', 'ejs');
// Set EJS as the templating engine
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
}).array('imageFiles', 10); // Allow up to 10 files at once


// ################################################ Routes ###########################################################

// GET Route for the homepage (display upload form)
app.get('/', (req, res) => { res.render('index'); });

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
        if (!req.files || req.files.length === 0) {
            req.flash('error', 'No files selected for upload.');
            return res.redirect('/');
        }

        // Files uploaded successfully, proceed to call Azure
        try {
            const predictionPromises = req.files.map(async (file) => {
                console.log(`Processing file: ${file.originalname}`);
                const imageBuffer = file.buffer;
                const originalFilename = file.originalname;
                const mimeType = file.mimetype;

                const predictionResult = await callAzurePredictionAPI(imageBuffer);

                // Convert buffer to Data URL
                const base64Image = imageBuffer.toString('base64');
                const imageDataUrl = `data:${mimeType};base64,${base64Image}`;

                // Generate a unique ID for this result object
                const resultId = crypto.randomUUID();

                // Return an object containing all data for this file
                return {
                    id: resultId, // Unique ID for linking in frontend
                    filename: originalFilename,
                    prediction: predictionResult,
                    imageDataUrl: imageDataUrl
                };
            });
            
            // Wait for all prediction calls to complete
            // Promise.all rejects if *any* promise rejects
            const results = await Promise.all(predictionPromises);

            // Render the results page with the array of results
            res.render('result', { results: results }); // Pass the array

        } catch (apiError) {
            // Handle errors from the callAzurePredictionAPI function
            console.error("API call failed:", apiError);
            req.flash('error', `Prediction Failed: ${apiError.message}`);
            res.redirect('/');
        }
    });
});


// POST /send-to-kwisp
app.post('/send-to-kwisp', async (req, res) => {
    // Extract data sent from the frontend JavaScript
    const { imageDataUrl, filename, predictionObj } = req.body;

    if (!imageDataUrl || !filename) {
        return res.status(400).json({ success: false, message: "Missing image data or filename." });
    }

    try {
        // Extract Base64 data and image type from Data URL
        const base64Marker = ';base64,';
        const base64Data = imageDataUrl.substring(imageDataUrl.indexOf(base64Marker) + base64Marker.length);
        const imageType = imageDataUrl.substring(imageDataUrl.indexOf(':') + 1, imageDataUrl.indexOf(';')); // e.g., "image/jpeg"
        const fileExtension = `.${imageType.split('/')[1]}`; // e.g., ".jpeg", png

        // Generate the payload for Kwisp API
        const kwispPayload = createKwispPayload(filename, fileExtension, predictionObj, base64Data);

        // Call the function to send data to Kwisp
        await sendToKwisp(kwispPayload);
        res.json({ success: true, message: "Data sent to Kwisp successfully." });
    } catch (error) {
        console.error("Error sending data to Kwisp:", error);
        res.status(500).json({ success: false, message: error.message || 'Failed to send data to Kwisp.' });
    }
});


// ################################################ Error Handler ###########################################################

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


// ################################################ Helper Functions ###########################################################
/**
 * Call Azure Prediction API
 * @param {Buffer} imageBuffer - The image buffer to be sent to Azure
 * @returns {Promise<Object>} - The prediction result from Azure
 * @description This function sends the image buffer to the Azure Prediction API and returns the prediction result.
 * It handles errors and logs the response for debugging.
 * @throws {Error} - Throws an error if the API call fails or if the response structure is unexpected.
 * @throws {Error} - Throws an error if the Azure endpoint URL is not configured.
 */
async function callAzurePredictionAPI(imageBuffer) {
    if (!PREDICTION_ENDPOINT_URL) {
        console.error("Azure endpoint URL is not configured.");
        throw new Error("Server configuration error: Azure credentials missing.");
    }

    // --- Prepare the request for Azure ---
    const headers = {
        'Content-Type': 'application/octet-stream'
        // 'Authorization': `Bearer ${AZURE_API_KEY}`
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

/**
 * Send data to Kwisp API
 * @param {Object} payload - The payload object to be sent to the Kwisp API
 * @description This function sends the payload to the Kwisp API using Axios.
 * It handles the response and errors appropriately.
 * @throws {Error} - Throws an error if the API call fails or if the response structure is unexpected.
 * @throws {Error} - Throws an error if the Kwisp API URL is not configured.
 * @throws {Error} - Throws an error if the payload is not valid.
 */
async function sendToKwisp(payload) {
    try {
        // Make the POST request to the Kwisp API
        console.log(`Sending request to Kwisp API: ${HEIJMANS_KWISP_API_URL}`);

        const kwispResponse = await axios.post(HEIJMANS_KWISP_API_URL, payload, {
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 30000 // 30 second timeout
        });

        // Check for 202 Accepted response (or other success codes if applicable)
        if (kwispResponse.status === 202) {
            console.log("Kwisp API accepted the request (Status 202).");
            res.json({ success: true, message: "Data sent to Kwisp successfully." });
        } else {
            // Handle unexpected success codes if necessary
            console.warn(`Kwisp API returned unexpected success status: ${kwispResponse.status}`);
            res.status(kwispResponse.status).json({ success: false, message: `Kwisp API returned status ${kwispResponse.status}` });
        }

    } catch (error) {
        console.error("Error calling Kwisp API:");
        let errorMessage = "Failed to send data to Kwisp.";
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Headers:', error.response.headers);
            console.error('Data:', error.response.data);
            errorMessage = `Kwisp API Error: ${error.response.status} - ${JSON.stringify(error.response.data)}`;
            res.status(error.response.status).json({ success: false, message: errorMessage });
        } else if (error.request) {
            console.error('Request Error:', error.request);
            errorMessage = "Network error: No response received from Kwisp API.";
            res.status(504).json({ success: false, message: errorMessage }); // Gateway Timeout
        } else {
            console.error('Error:', error.message);
            errorMessage = `An unexpected error occurred: ${error.message}`;
            res.status(500).json({ success: false, message: errorMessage }); // Internal Server Error
        }
    }
}

/**
 * Create the payload for Kwisp API
 * @param {*} filename - The name of the file uploaded
 * @param {*} fileExtension - The file extension (e.g., .jpeg, .png)
 * @param {*} predictionObj - The prediction object returned from Azure
 * @param {*} predictionObj.prediction - The prediction result (e.g., "crack", "no crack")
 * @param {*} predictionObj.confidence - The confidence score of the prediction
 * @param {*} base64Data - The base64 encoded string of the image data
 * @returns {Object} - The payload object to be sent to Kwisp API
 * @description This function constructs the payload for the Kwisp API based on the provided parameters.
 */
function createKwispPayload(filename, fileExtension, predictionObj, base64Data) {
    
    // Construct the complex JSON payload
    const kwispPayload = {
        "sender": "CI",
        "receiver": "Heijmans",
        "instigator": "concrete-innovation",
        "case": {
            "type": "Bridge",
            "id": "fbfb54a7-d918-4768-9991-0bb3374efb7c",
            "agreement": {
                "type": "Test-Agreement",
                "designation": "HEIJ123"
            },
            "commentDescriptionShort": `Prediction Result: ${predictionObj?.prediction || 'N/A'}. File: ${filename}`,
            "commentDescriptionExtensive": `Crack detection analysis performed on image ${filename}. Result: ${predictionObj?.prediction || 'N/A'}. Confidence: ${predictionObj?.confidence?.toFixed(3) || 'N/A'}`,
            "attachments": [{
                "type": fileExtension, // Dynamic based on upload
                "class": "file",
                "designation": filename, // Dynamic based on upload
                "base64String": base64Data, // Dynamic based on upload
                "description": `Image uploaded for crack detection. Result: ${predictionObj?.prediction || 'N/A'}` // Dynamic
            }]
        }
    };

    return kwispPayload;
}
