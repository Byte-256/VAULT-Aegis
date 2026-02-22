# 🛡️ VAULT Aegis Dashboard - Complete Setup Guide

## 📋 Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Running the Dashboard](#running-the-dashboard)
4. [Project Structure](#project-structure)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Troubleshooting](#troubleshooting)

---

## 🖥️ System Requirements

### Minimum Requirements
- **Python:** 3.8 or higher
- **RAM:** 4GB minimum, 8GB recommended
- **Disk Space:** 500MB for dependencies
- **Browser:** Chrome 120+, Firefox 120+, Edge 120+, or Safari 17+
- **Internet:** Required for initial package installation

### Recommended Setup
- **OS:** Windows 10/11, macOS 11+, or Ubuntu 20.04+
- **Python:** 3.9 or 3.10 (most stable)
- **RAM:** 16GB for smooth performance
- **Monitor:** 1920x1080 or higher resolution

---

## 📦 Installation

### Step 1: Verify Python Installation

```bash
# Check Python version
python --version

# Or
python3 --version
```

**Expected Output:** `Python 3.8.x` or higher

### Step 2: Download/Extract Project

```bash
# If you have a zip file
unzip vault_dashboard.zip
cd vault_dashboard

# Or navigate to the project directory
cd /path/to/vault_dashboard
```

### Step 3: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS/Linux
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# If you encounter issues, try upgrading pip first
pip install --upgrade pip
pip install -r requirements.txt
```

**Expected Installation Time:** 2-5 minutes depending on internet speed

### Step 5: Verify Installation

```bash
# Check if Streamlit is installed
streamlit --version

# Test Python syntax
python -m py_compile app.py
```

---

## 🚀 Running the Dashboard

### Method 1: Quick Start Script (Recommended)

```bash
# Make script executable (macOS/Linux only)
chmod +x start.sh

# Run the script
./start.sh
```

### Method 2: Direct Streamlit Command

```bash
# Basic command
streamlit run app.py

# With custom port
streamlit run app.py --server.port 8080

# With auto-reload
streamlit run app.py --server.runOnSave true

# With specific address
streamlit run app.py --server.address 0.0.0.0
```

### Method 3: Python Module

```bash
python -m streamlit run app.py
```

### Accessing the Dashboard

Once running, the dashboard will be available at:
- **Local:** http://localhost:8501
- **Network:** http://YOUR_IP:8501 (if using --server.address 0.0.0.0)

The browser should open automatically. If not, copy the URL from the terminal.

---

## 📁 Project Structure

```
vault_dashboard/
│
├── app.py                    # Main application file (29KB)
├── demo.py                   # Demo/preview page (8KB)
├── requirements.txt          # Python dependencies
├── start.sh                  # Startup script
├── README.md                 # Main documentation
├── QUICK_REFERENCE.md        # Quick reference guide
└── INSTALLATION.md           # This file
```

### File Descriptions

- **app.py**: Complete Streamlit application with all dashboard pages
- **demo.py**: Simplified demo version for quick previews
- **requirements.txt**: Lists all Python package dependencies
- **start.sh**: Automated startup script for easy launching

---

## ⚙️ Configuration

### Streamlit Configuration

Create `.streamlit/config.toml` for custom settings:

```toml
[theme]
primaryColor = "#4852F5"
backgroundColor = "#0a0a0a"
secondaryBackgroundColor = "#1a1a2e"
textColor = "#ffffff"
font = "sans serif"

[server]
port = 8501
enableCORS = false
enableXsrfProtection = true

[browser]
gatherUsageStats = false
```

### Environment Variables

Create `.env` file for sensitive configurations:

```env
# Server Settings
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=localhost

# Feature Flags
ENABLE_ANALYTICS=false
DEBUG_MODE=false
```

### Customizing the Dashboard

Edit these sections in `app.py`:

1. **Colors**: Modify CSS in `inject_custom_css()`
2. **Data**: Adjust `generate_dummy_data()` function
3. **Layout**: Change column configurations
4. **Navigation**: Update `render_sidebar()` items

---

## 🌐 Deployment

### Option 1: Local Network Deployment

```bash
# Allow access from other devices on your network
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

Access from other devices: `http://YOUR_LOCAL_IP:8501`

### Option 2: Streamlit Community Cloud (Free)

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin YOUR_GITHUB_REPO_URL
   git push -u origin main
   ```

2. **Deploy:**
   - Visit https://share.streamlit.io
   - Sign in with GitHub
   - Click "New app"
   - Select your repository
   - Set main file: `app.py`
   - Click "Deploy"

3. **Access:** Your app will be at `https://YOUR_APP_NAME.streamlit.app`

### Option 3: Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

Build and run:

```bash
# Build image
docker build -t vault-dashboard .

# Run container
docker run -p 8501:8501 vault-dashboard
```

### Option 4: Cloud VM Deployment

**For AWS EC2, Google Cloud, Azure, etc:**

```bash
# Install Python and pip
sudo apt update
sudo apt install python3-pip python3-venv

# Clone your repository
git clone YOUR_REPO_URL
cd vault_dashboard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run with nohup (keeps running after logout)
nohup streamlit run app.py --server.address 0.0.0.0 &

# Or use screen/tmux for persistent sessions
screen -S dashboard
streamlit run app.py --server.address 0.0.0.0
# Press Ctrl+A, then D to detach
```

**Configure Firewall:**
- Open port 8501 in security group/firewall
- Access via: `http://YOUR_VM_IP:8501`

### Option 5: Production with Nginx

**Install Nginx:**
```bash
sudo apt install nginx
```

**Configure reverse proxy** (`/etc/nginx/sites-available/vault`):
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

**Enable and restart:**
```bash
sudo ln -s /etc/nginx/sites-available/vault /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🐛 Troubleshooting

### Issue 1: Port Already in Use

**Error:** `Address already in use`

**Solution:**
```bash
# Find process using port 8501
lsof -i :8501

# Kill the process
kill -9 <PID>

# Or use different port
streamlit run app.py --server.port 8502
```

### Issue 2: Module Not Found

**Error:** `ModuleNotFoundError: No module named 'streamlit'`

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue 3: CSS Not Loading

**Symptoms:** Dashboard looks unstyled

**Solution:**
1. Hard refresh: `Ctrl + Shift + R` (Windows/Linux) or `Cmd + Shift + R` (Mac)
2. Clear Streamlit cache: `streamlit cache clear`
3. Check browser console for errors
4. Ensure `unsafe_allow_html=True` in markdown components

### Issue 4: Charts Not Displaying

**Error:** Blank chart areas

**Solution:**
```bash
# Reinstall Plotly
pip uninstall plotly
pip install plotly==5.18.0

# Clear browser cache
# Restart the app
```

### Issue 5: Slow Performance

**Solution:**
1. **Add caching:**
   ```python
   @st.cache_data
   def generate_dummy_data():
       # Your data generation code
   ```

2. **Reduce data size:**
   - Decrease chart data points
   - Limit table rows

3. **Optimize charts:**
   - Use `config={'displayModeBar': False}`
   - Reduce animation complexity

### Issue 6: Permission Denied (start.sh)

**Error:** `Permission denied: ./start.sh`

**Solution:**
```bash
# Make script executable
chmod +x start.sh

# Or run directly with bash
bash start.sh
```

### Issue 7: Windows Path Issues

**Error:** Path-related errors on Windows

**Solution:**
- Use forward slashes `/` instead of backslashes `\`
- Or use raw strings: `r"C:\path\to\folder"`
- Or double backslashes: `"C:\\path\\to\\folder"`

### Issue 8: Broken Pipe Error

**Error:** `Broken pipe` or connection errors

**Solution:**
```bash
# Increase server timeout
streamlit run app.py --server.maxUploadSize=200
```

---

## 📊 Performance Optimization

### 1. Enable Caching

Add to frequently called functions:
```python
@st.cache_data(ttl=3600)  # Cache for 1 hour
def expensive_computation():
    return data
```

### 2. Lazy Loading

Load data only when needed:
```python
if st.session_state.get('show_details'):
    data = load_detailed_data()
```

### 3. Optimize Imports

Move heavy imports inside functions if only used occasionally.

### 4. Reduce Chart Complexity

```python
# Limit data points
data_subset = data[-100:]  # Last 100 points only

# Simplify chart config
fig.update_layout(
    showlegend=False,
    hovermode=False
)
```

---

## 🔒 Security Considerations

### Production Checklist

- [ ] Change default ports
- [ ] Implement authentication (if needed)
- [ ] Use HTTPS with SSL certificates
- [ ] Set up firewall rules
- [ ] Disable debug mode
- [ ] Validate all user inputs
- [ ] Keep dependencies updated
- [ ] Use environment variables for secrets
- [ ] Enable CORS only for trusted domains
- [ ] Regular security audits

### Adding Authentication

Use `streamlit-authenticator`:
```bash
pip install streamlit-authenticator
```

Basic implementation:
```python
import streamlit_authenticator as stauth

authenticator = stauth.Authenticate(
    credentials,
    'cookie_name',
    'signature_key',
    cookie_expiry_days=30
)

name, authentication_status = authenticator.login('Login', 'main')
```

---

## 📞 Support & Resources

### Documentation
- **Streamlit Docs:** https://docs.streamlit.io
- **Plotly Docs:** https://plotly.com/python/
- **Pandas Docs:** https://pandas.pydata.org/docs/

### Community
- **Streamlit Forum:** https://discuss.streamlit.io
- **GitHub Issues:** Report bugs and feature requests

### Useful Commands

```bash
# Check installed package versions
pip list

# Update all packages
pip install --upgrade -r requirements.txt

# Freeze current environment
pip freeze > requirements_frozen.txt

# Check for security vulnerabilities
pip-audit

# Profile performance
streamlit run app.py --server.enableProfiler=true
```

---

## ✅ Post-Installation Checklist

After successful installation:

- [ ] Dashboard loads at http://localhost:8501
- [ ] All navigation items work
- [ ] Charts display correctly
- [ ] Tables are visible
- [ ] Hover effects work
- [ ] Metrics display properly
- [ ] No console errors in browser
- [ ] Responsive to window resizing
- [ ] Sidebar navigation functional
- [ ] Colors match design specifications

---

## 🎓 Next Steps

1. **Customize the dashboard** - Edit colors, metrics, and layouts
2. **Connect real data** - Replace dummy data with actual sources
3. **Add authentication** - Implement user login if needed
4. **Deploy to production** - Choose deployment method
5. **Monitor performance** - Set up analytics and logging
6. **Regular updates** - Keep dependencies current

---

**Last Updated:** 2026-02-19
**Version:** 1.0.0

🛡️ **VAULT Aegis Dashboard** - Securing AI Systems

For additional help, refer to QUICK_REFERENCE.md and README.md
