document.addEventListener('DOMContentLoaded', function() {
    const chatForm = document.getElementById('chatForm');
    const messageInput = document.getElementById('messageInput');
    const chatMessages = document.getElementById('chatMessages');
    const typingIndicator = document.getElementById('typingIndicator');
    
    // Initialize cache
    const responseCache = new Map();
    const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds

    const messagesContainer = document.getElementById('messagesContainer');

    function addMessage(content, type) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = content;
        messagesContainer.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function displayAccessDecision(decision) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message access-decision ${decision.allowed ? 'allowed' : 'denied'}`;
        messageDiv.textContent = decision.reason;
        messagesContainer.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function showTypingIndicator() {
        typingIndicator.style.display = 'block';
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function hideTypingIndicator() {
        typingIndicator.style.display = 'none';
    }

    function getCachedResponse(message) {
        const cached = responseCache.get(message);
        if (!cached) return null;
        
        // Check if cache is still valid
        if (Date.now() - cached.timestamp > CACHE_DURATION) {
            responseCache.delete(message);
            return null;
        }
        
        return cached.data;
    }

    function cacheResponse(message, data) {
        responseCache.set(message, {
            data: data,
            timestamp: Date.now()
        });
    }

    // Handle Enter key in textarea
    messageInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            chatForm.dispatchEvent(new Event('submit'));
        }
    });

    chatForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const message = messageInput.value.trim();
        if (!message) return;

        // Add user message to chat
        addMessage(message, 'user');
        messageInput.value = '';

        try {
            // Check cache first
            const cachedResponse = getCachedResponse(message);
            if (cachedResponse) {
                if (cachedResponse.message) {
                    addMessage(cachedResponse.message, 'bot');
                }
                if (cachedResponse.access_decision) {
                    displayAccessDecision(cachedResponse.access_decision);
                }
                return;
            }

            // Show typing indicator before fetch
            showTypingIndicator();

            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message })
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            
            // Hide typing indicator after receiving response
            hideTypingIndicator();
            
            // Cache the response
            cacheResponse(message, data);
            
            // Add bot response to chat
            if (data.message) {
                addMessage(data.message, 'bot');
            }

            // Display access decision if present
            if (data.access_decision) {
                displayAccessDecision(data.access_decision);
            }

        } catch (error) {
            hideTypingIndicator();
            addMessage('Sorry, there was an error processing your request.', 'error');
        }
    });

    // Hide typing indicator initially
    hideTypingIndicator();
});
