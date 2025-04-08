# Concrete Crack Detection Web Application

## Overview

This is a Node.js web application built with Express.js that allows users to upload multiple images of concrete surfaces. The application sends these images to an external AI classification service (specifically configured for an Azure endpoint) to classify whether they contain cracks.

The results, including the original image and the processed image (potentially with annotations like bounding boxes around cracks), are displayed side-by-side for comparison. Users can then select multiple results and send a consolidated report, including the original images and classification details, to the Incident API integration endpoint.

## Key Features

*   **Multiple Image Upload:** Allows users to select and upload multiple image files (`.jpg`, `.jpeg`, `.png`) simultaneously.
*   **File Validation:** Basic validation for allowed file types and size limits.
*   **AI Crack Detection:** Integrates with an external Azure AI prediction endpoint to classify images for cracks.
*   **Side-by-Side Results:** Displays the original uploaded image alongside the processed/classified image received from the AI service.
*   **Result Selection:** Checkboxes (styled as toggle buttons) allow users to select individual classification results.
*   **Scrollable Results:** Displays results within a scrollable container to manage page length when many images are processed.
*   **Batch Reporting:** Sends data (original image, filename, prediction details) for *all selected* results in a single batch request to the Incident API.
*   **User Feedback:** Uses flash messages for upload errors and provides status updates during the Incident API reporting process.
*   **Responsive Layout:** The main container adjusts its width for better viewing on different screen sizes.

## Screenshots

![index.ejs](/README%20Images/index-page.png)
![result.ejs](/README%20Images/result-page-crack-detected.png)
![result.ejs](/README%20Images/result-page-crack-not-detected.png)

## Technology Stack

*   **Backend:** Node.js, Express.js
*   **Frontend:** EJS (Embedded JavaScript templates), HTML5, CSS3 (including Flexbox)
*   **JavaScript:** Vanilla JavaScript (Client-side Fetch API)
*   **File Uploads:** Multer
*   **HTTP Requests:** Axios (for calling Azure & Incident APIs)
*   **Environment Variables:** dotenv
*   **Session Management & Flash Messages:** express-session, connect-flash
*   **External APIs:**
    *   Azure AI Prediction Service (for image classification)
    *   Incident API (for reporting)

## Prerequisites

Before you begin, ensure you have the following installed:

*   [Node.js](https://nodejs.org/) (which includes npm) - Version 14.x or higher recommended.
*   [Git](https://git-scm.com/) (for cloning the repository).
*   Access credentials and endpoint URLs for:
    *   The Azure AI Prediction service.
    *   The Incident API.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory-name>
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    # or if you use yarn:
    # yarn install
    ```

## Configuration

This application requires environment variables for sensitive information like API keys and endpoints.

1.  **Create a `.env` file** in the root directory of the project.
2.  **Copy the contents** of `.env.example` (if provided) or add the following variables, replacing the placeholder values with your actual credentials:

    ```dotenv
    # Server Configuration
    PORT=3000

    # Azure AI Prediction Service Credentials
    # Replace with your actual Azure prediction endpoint URL
    PREDICTION_ENDPOINT_URL=YOUR_AZURE_PREDICTION_ENDPOINT_URL
    # Add any necessary API key or authentication headers variable if required by your specific Azure setup
    # AZURE_API_KEY=YOUR_AZURE_API_KEY # Example - currently not used directly in headers in provided code snippet

    # Incident API Configuration
    # Replace with the actual Incident API endpoint URL
    INCIDENT_API_URL=YOUR_INCIDENT_API_ENDPOINT_URL

    # Session Configuration
    # Generate a strong, random string for the session secret
    SESSION_SECRET=YOUR_STRONG_RANDOM_SESSION_SECRET
    ```

**Important:**
*   Never commit your `.env` file to version control. Add `.env` to your `.gitignore` file.
*   The `SESSION_SECRET` should be a long, random, and unpredictable string for security.

## Running the Application

1.  **Start the server:**
    ```bash
    npm start
    # Or directly using node:
    # node server.js
    ```

2.  **Open your web browser** and navigate to `http://localhost:PORT`, where `PORT` is the port number specified in your `.env` file (default is 3000).
    `http://localhost:3000`

## API Endpoints (Internal)

The application defines the following main routes:

*   `GET /`: Displays the main image upload page (`index.ejs`).
*   `POST /classify`: Handles the image file uploads, calls the Azure prediction API for each image, and renders the results page (`result.ejs`).
*   `POST /send-batch-to-incident-api`: Receives data for selected results from the client-side JavaScript, formats a single batch payload, and sends it to the Incident API.
