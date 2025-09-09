# Setup Guide

## Prerequisites
- Python 3.8 or higher
- Git

## Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/busyclasher/phishing-detect.git
   cd phishing-detect
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   ```

3. **Activate the virtual environment:**

   **Windows:**
   ```bash
   .venv\Scripts\activate
   ```

   **Linux/macOS:**
   ```bash
   source .venv/bin/activate
   ```

   **Note:** On Windows, you may need to use the full path if the command doesn't work:
   ```bash
   C:\Users\your-username\path\to\project\.venv\Scripts\activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Start the backend development server:**
   ```bash
   uvicorn backend.api.index:app --reload --port 8000
   ```

6. **Start the frontend development server (in a new terminal):**
   ```bash
   npm run dev
   ```

## Managing Dependencies

### Freezing Packages into requirements.txt

To make your environment reproducible, freeze the installed packages into `requirements.txt`.

1. **Activate your virtual environment:**

   **Windows:**
   ```bash
   .venv\Scripts\activate
   ```

   **Linux/macOS:**
   ```bash
   source .venv/bin/activate
   ```

2. **Freeze packages:**
   ```bash
   pip freeze > requirements.txt
   ```

   This will overwrite `requirements.txt` with the exact versions currently installed.

3. **Add to Git:**
   ```bash
   git add requirements.txt
   git commit -m "chore: update requirements.txt with current venv packages"
   ```

4. **Recreate environment later:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

**Pro tip:** For minimal requirements (only top-level packages), use `pipreqs`:

```bash
pip install pipreqs
pipreqs . --force
```

## Verification

Once the server is running, you can verify it's working by visiting:
- **API Health Check:** `http://localhost:8000/api/py/health`
- **API Documentation:** `http://localhost:8000/api/py/docs` (FastAPI auto-generated docs)

The server will run with auto-reload enabled for development, so changes to the code will automatically restart the server.
