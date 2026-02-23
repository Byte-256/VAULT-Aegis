# VAULT Aegis - Example Applications

This folder contains example applications demonstrating the VAULT security framework.

## Secure Chatbot

A chatbot UI that showcases all VAULT security features:

### Features Demonstrated

- **Prompt Injection Defense**: Detects and blocks jailbreak attempts
- **Intent Analysis**: Classifies user intent (chat, summarize, tool, admin)
- **Policy Engine**: Role-based access control with configurable policies
- **PII Sanitization**: Detects and masks sensitive data (emails, credit cards, etc.)
- **Audit Logging**: Tamper-resistant event trail
- **Response Guard**: Filters secrets from AI responses

### Running the Chatbot

```bash
cd /opt/Projects/college_projects/HACKATHON/VAULT-aegis
source .venv/bin/activate
streamlit run examples/secure_chatbot.py
```

Then open http://localhost:8501 in your browser.

### Testing Security Features

Use the built-in test buttons to try different attack vectors:

1. **Jailbreak Test** - Try prompt injection
2. **PII Test** - Test with sensitive data  
3. **Admin Test** - Test role-based restrictions
