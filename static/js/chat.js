document.addEventListener('DOMContentLoaded', function() {
    const chatForm = document.getElementById('chatForm');
    const messageInput = document.getElementById('messageInput');
    const chatMessages = document.getElementById('chatMessages');

    function addMessage(content, type) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = content;
        
        // Add typing indicator for bot messages
        if (type === 'bot') {
            const typingDiv = document.createElement('div');
            typingDiv.className = 'message bot typing-indicator';
            typingDiv.innerHTML = '<span></span><span></span><span></span>';
            chatMessages.appendChild(typingDiv);
            
            // Simulate typing delay
            setTimeout(() => {
                typingDiv.remove();
                chatMessages.appendChild(messageDiv);
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }, 1500);
        } else {
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
    }

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
            
            // Handle error responses
            if (data.error) {
                addMessage(data.error, 'error');
                return;
            }
            
            // Add bot response to chat
            if (data.message) {
                addMessage(data.message, 'bot');
            }

            // Display access decision if present
            if (data.access_decision) {
                setTimeout(() => {
                    displayAccessDecision(data.access_decision);
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                }, 1000); // Delay to show after bot message
            }

        } catch (error) {
            console.error('Chat error:', error);
            addMessage('Sorry, there was an error processing your request. Please try again.', 'error');
        } finally {
            // Re-enable input after processing
            messageInput.disabled = false;
            messageInput.focus();
        }
    });
});
