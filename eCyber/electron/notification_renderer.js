const messageDiv = document.getElementById('message');

if (window.electronAPI && window.electronAPI.receiveBackendEvent) {
    window.electronAPI.receiveBackendEvent((eventData) => {
        console.log('Notification window received event:', eventData);
        let displayMessage = 'An event occurred.';
        if (typeof eventData === 'string') {
            displayMessage = eventData;
        } else if (typeof eventData === 'object' && eventData !== null) {
            // Try to find a meaningful message field, customize as needed
            if (eventData.message) {
                displayMessage = eventData.message;
            } else if (eventData.detail) {
                displayMessage = eventData.detail;
            } else {
                try {
                    displayMessage = JSON.stringify(eventData, null, 2);
                } catch (e) {
                    displayMessage = 'Received complex event object.';
                }
            }
        }
        messageDiv.textContent = displayMessage;

        // Optional: Auto-resize window based on content (requires more setup in main.js)
        // Or, if you want the window to close on click:
        // window.addEventListener('click', () => {
        //    window.electronAPI.closeNotificationWindow(); // This API would need to be exposed
        // });
    });
    messageDiv.textContent = 'Listening for backend events...';
} else {
    messageDiv.textContent = 'Error: electronAPI not found. Preload script might not be configured correctly for this window.';
    console.error('electronAPI or receiveBackendEvent not found on window.');
}
