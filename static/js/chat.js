document.addEventListener('DOMContentLoaded', function() {
    const chatForm = document.getElementById('chatForm');
    const messageInput = document.getElementById('messageInput');
    const chatMessages = document.getElementById('chatMessages');

    function addMessage(content, type) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = content;
        
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }rr

    function displayAccessDecision(decision) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message access-decision ${decision.allowed ? 'allowed' : 'denied'}`;
        messageDiv.textContent = decision.reason;
        chatMessages.appendChild(messageDiv);
    }

    chatForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const message = messageInput.value.trim();
        if (!message) return;

        // Add user message to chat
        addMessage(message, 'user');
        messageInput.value = '';

        try {
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
            
            // Add bot response to chat
            if (data.message) {
                addMessage(data.message, 'bot');
            }

            // Display access decision if present
            if (data.access_decision) {
                displayAccessDecision(data.access_decision);
            }

        } catch (error) {
            addMessage('Sorry, there was an error processing your request.', 'error');
        }
    });
});
