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
const CLASSIFICATION_ENDPOINT_URL = process.env.CLASSIFICATION_ENDPOINT_URL;
const CLIENT_ID = process.env.CLIENT_ID; // Client ID for Azure
const CLIENT_SECRET = process.env.CLIENT_SECRET; // Client Secret for Azure
const AZURE_API_KEY = process.env.AZURE_API_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Get Incident API URL from environment variables
const INCIDENT_API_URL = process.env.INCIDENT_API_URL; // Incident API URL
const INCIDENT_API_KEY = process.env.INCIDENT_API_KEY; // Incident API Key (if needed)

if (!SESSION_SECRET) {
    console.error("FATAL ERROR: SESSION_SECRET is not set in the .env file.");
    process.exit(1); // Exit if session secret is missing
}

// ################################################ Middleware Setup ###########################################################\

// Serve static files (CSS, client-side JS) from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse JSON request bodies (needed for API calls)
app.use(express.json({ limit: '20mb' })); // Note: The limit is set to 20mb to accommodate larger base64 image data
// Middleware to parse URL-encoded bodies (needed for forms, though not strictly for the Incident call)
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

// POST Route to handle the file upload and classify
app.post('/classify', (req, res) => {
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
        
        try {
            const classificationPromises = req.files.map(async (file) => {
                console.log(`Processing file: ${file.originalname}`);
                const imageBuffer = file.buffer;
                const originalFilename = file.originalname;
                const mimeType = file.mimetype;

                // Call classification API
                let classificationResult = await callAzureClassificationAPI(imageBuffer);

                // Convert original image buffer to Data URL
                const originalBase64Image = imageBuffer.toString('base64');
                const originalImageDataUrl = `data:${mimeType};base64,${originalBase64Image}`;

                // classificationResult.crackDetected is expected to be a string of "True" or "False"
                // Convert to boolean for easier handling in the frontend
                if (classificationResult && classificationResult.crackDetected) {
                    classificationResult.crackDetected = classificationResult.crackDetected.toLowerCase() === 'true';
                }

                // classificationResult.confidence is expected to be a string of a number (e.g., "0.85")
                // Convert to a number for easier handling in the frontend
                if (classificationResult && classificationResult.confidence) {
                    classificationResult.confidence = parseFloat(classificationResult.confidence);
                }

                // *** Process the classified image from the response ***
                let classifiedImageDataUrl = null;
                if (classificationResult && typeof classificationResult.classifiedImage === 'string') {
                    const classifiedBase64 = classificationResult.classifiedImage;
                    classifiedImageDataUrl = `data:image/jpg;base64,${classifiedBase64}`;
                    console.log(`Processed classified image for ${originalFilename}`);
                    // Remove the classified image from the classification result to avoid sending it back to the client
                    delete classificationResult.classifiedImage;
                } else {
                    console.log(`No classified image returned for ${originalFilename}`);
                }

                // Generate a unique ID for each result (UUID)
                const resultId = crypto.randomUUID();

                // Return an object containing all data for this file
                return {
                    id: resultId,
                    filename: originalFilename,
                    classification: classificationResult, // Contains { crackDetected, confidence }
                    originalImageDataUrl: originalImageDataUrl, // Pass original image too
                    classifiedImageDataUrl: classifiedImageDataUrl // Pass classified image if available
                };
            });

            // Wait for all classification calls to complete
            const results = await Promise.all(classificationPromises);

            // Render the results page with the array of results
            res.render('result', { results: results });

        } catch (apiOrTokenError) {
             console.error("Classification process failed for one or more files:", apiOrTokenError);
             req.flash('error', `Classification Failed: ${apiOrTokenError.message}`);
             res.redirect('/');
        }
    });
});


// POST /send-batch-to-incident-api route to send batch data to Incident
app.post('/send-batch-to-incident-api', async (req, res) => {
    const { selectedItems } = req.body; // Expect an array named 'selectedItems'

    console.log(`Received request to send batch report for ${selectedItems?.length} items.`);

    // --- Basic Validation ---
    if (!selectedItems || !Array.isArray(selectedItems) || selectedItems.length === 0) {
        return res.status(400).json({ success: false, message: "No selected items received or data is invalid." });
    }

    try {
        // --- Create the Base Incident Payload ---
        const caseId = `batch-${Date.now()}`; // Example dynamic ID
        const agreementDesignation = "HEIJ123-BATCH"; // Example designation

        const incidentPayload = {
            "sender": "SRC1",
            "receiver": "Heijmans",
            "instigator": "concrete-innovation",
            "case": {
                "type": "Bridge",
                "id": caseId,
                "agreement": {
                    "type": "TestAgreement",
                    "designation": agreementDesignation
                },
                // Generalized comments for batch
                "commentDescriptionShort": `Batch crack detection report for ${selectedItems.length} images.`,
                "commentDescriptionExtensive": `Crack detection analysis performed on ${selectedItems.length} selected images. See attachments for details. Files: ${selectedItems.map(item => item.filename).join(', ')}`,
                "attachments": [] // Initialize attachments array
            }
        };

        // --- Process and Add Attachments ---
        for (const item of selectedItems) {
            const { imageDataUrl, filename, classificationObj } = item;

            if (!imageDataUrl || !filename || !classificationObj) {
                 console.warn(`Skipping item due to missing data: ${filename || 'Unknown'}`);
                 continue; // Skip this item if data is incomplete
            }

            // Extract Base64 data and determine file extension (Refactored into helper)
            const { base64Data, fileExtension } = extractBase64AndExtension(imageDataUrl);

            // Create the attachment object for this item (Refactored into helper)
            const attachment = createIncidentAttachment(filename, fileExtension, classificationObj, base64Data);
            incidentPayload.case.attachments.push(attachment);
        }

         // Check if any valid attachments were actually added
         if (incidentPayload.case.attachments.length === 0) {
            throw new Error("No valid items could be processed for the batch.");
         }


        // --- Send the Combined Payload to Incident API ---
        console.log(`Sending batch payload with ${incidentPayload.case.attachments.length} attachments to Incident.`);
        await sendToIncident(incidentPayload); // Use the existing sender function

        // --- Send Success Response ---
        res.json({ success: true, message: `Batch report for ${incidentPayload.case.attachments.length} items sent successfully.` });

    } catch (error) {
        console.error(`Error processing /send-batch-to-incident-api:`, error);
        res.status(500).json({
            success: false,
            message: error.message || 'Failed to send batch data to Incident API due to an internal error.'
        });
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
    if (!CLASSIFICATION_ENDPOINT_URL || !AZURE_API_KEY) {
        console.warn("\n*** WARNING: CLASSIFICATION_ENDPOINT_URL or AZURE_API_KEY not found in .env file. ***");
        console.warn("*** The application will run, but classifications WILL FAIL.        ***\n");
    } else {
        console.log("Azure credentials loaded successfully.");
    }
});


// ################################################ Helper Functions ###########################################################
/**
 * Call Azure Classification API
 * @param {Buffer} imageBuffer - The image buffer to be sent to Azure
 * @returns {Promise<Object>} - The classification result from Azure
 * @description This function sends the image buffer to the Azure Classification API and returns the classification result.
 * It handles errors and logs the response for debugging.
 * @throws {Error} - Throws an error if the API call fails or if the response structure is unexpected.
 * @throws {Error} - Throws an error if the Azure endpoint URL is not configured.
 */
async function callAzureClassificationAPI(imageBuffer) {
    if (!CLASSIFICATION_ENDPOINT_URL) {
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

    console.log(`Sending classification request to: ${CLASSIFICATION_ENDPOINT_URL}`);
    try {
        const response = await axios.post(CLASSIFICATION_ENDPOINT_URL, imageBuffer, {
             headers: headers,
             timeout: 60000 // 60 second timeout
        });

        console.log(`Azure Response Status Code: ${response.status}`);

        // Axios automatically parses JSON responses, so we can directly access response.data
        if (response.data && Object.keys(response.data).length > 0) {
            return response.data; 
        } else {
            console.error("Classification key not found or unexpected response structure:", response.data);
            throw new Error("Received an unexpected response structure from Azure AI service.");
        }

    } catch (error) {
        console.error("Error calling Azure AI service:");
        if (error.response) {
            // The request was made and the server responded with a status code that falls out of the range of 2xx
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

// --- NEW/REFACTORED: Helper to extract Base64 and Extension ---
function extractBase64AndExtension(imageDataUrl) {
    const base64Marker = ';base64,';
    const markerIndex = imageDataUrl.indexOf(base64Marker);
    if (markerIndex === -1) {
        throw new Error("Invalid image data format received.");
    }
    const base64Data = imageDataUrl.substring(markerIndex + base64Marker.length);
    const mimeTypeString = imageDataUrl.substring(imageDataUrl.indexOf(':') + 1, imageDataUrl.indexOf(';'));
    // Provide a default extension if mime type parsing fails
    let fileExtension = '.jpg';
    if (mimeTypeString && mimeTypeString.includes('/')) {
        const extensionPart = mimeTypeString.split('/')[1];
        if (extensionPart) {
            fileExtension = `.${extensionPart.toLowerCase()}`;
        }
    }
    return { base64Data, fileExtension };
}

// --- NEW/REFACTORED: Helper to create a single Incident API Attachment object ---
function createIncidentAttachment(filename, fileExtension, classificationObj, base64Data) {
    // Convert boolean classification back to string if needed, or adjust based on API expectation
    const classificationText = typeof classificationObj?.crackDetected === 'boolean' ? (classificationObj.crackDetected ? 'Cracks Detected' : 'No Cracks Detected') : (classificationObj?.crackDetected || 'N/A');
    const confidenceText = classificationObj?.confidence?.toFixed(3) || 'N/A';

    return {
        "type": fileExtension.startsWith('.') ? fileExtension.substring(1) : fileExtension, // Incident API might want "jpeg" not ".jpeg"
        "class": "file",
        "designation": filename,
        "base64String": base64Data,
        "description": `Image: ${filename}. Result: ${classificationText}. Confidence: ${confidenceText}.` // Dynamic description per image
    };
}


/**
 * Send data to Incident API
 * @param {Object} payload - The payload object to be sent to the Incident API
 * @returns {Promise<boolean>} - Returns true if the API call is accepted (status 202)
 * @description This function sends the payload to the Incident API using Axios.
 * It handles the response and throws detailed errors on failure.
 * @throws {Error} - Throws an error if the API call fails, receives an unexpected status,
 *                   or if the Incident API URL is not configured (implicit check needed).
 * @throws {Error} - Throws an error if the payload is not valid (implicit).
 */
async function sendToIncident(payload) {
    if (!INCIDENT_API_URL || !INCIDENT_API_URL) {
        console.error("FATAL ERROR: Required environment variables for Incident API are not set.");
        throw new Error("FATAL ERROR: Required environment variables for Incident API are not set.");
    }

    console.log(`Sending request to Incident API: ${INCIDENT_API_URL}`);
    try {
        const incidentResponse = await axios.post(INCIDENT_API_URL, payload, {
            headers: {
                'Content-Type': 'application/json',
                'Ocp-Apim-Subscription-Key': INCIDENT_API_KEY, // Incident API Key (if needed)
                // Add other necessary Incident API headers here if needed
            },
            timeout: 30000 // 30 second timeout
        });

        // Check specifically for 202 Accepted response
        if (incidentResponse.status === 202) {
            console.log("Incident API accepted the request (Status 202).");
            return true; // Signal success back to the route handler
        } else {
            console.warn(`Incident API returned unexpected success status: ${incidentResponse.status}`);
            throw new Error(`Incident API returned unexpected status ${incidentResponse.status}`);
        }

    } catch (error) {
        console.error("Error calling Incident API:");
        let errorMessage = "Failed to send data to Incident API.";
        // Check if it's an Axios error with a response from the server
        if (error.response) {
            console.error('Status:', error.response.status);
            console.error('Headers:', error.response.headers);
            console.error('Data:', error.response.data);
            errorMessage = `Incident API Error: ${error.response.status} - ${JSON.stringify(error.response.data)}`;
        } else if (error.request) {
            // The request was made but no response was received
            console.error('Request Error:', error.request);
            errorMessage = "Network error: No response received from Incident API.";
            // error.statusCode = 504; // Gateway Timeout (optional)
        } else {
            // Something happened in setting up the request or a non-Axios error
            console.error('Error:', error.message);
            // Use the original error message if it's not an Axios issue
            errorMessage = error.message || errorMessage;
            error.statusCode = 500; // Internal Server Error
        }
        throw new Error(errorMessage);
    }
}