# AccuKnox MCP Server - User Guide

This guide provides step-by-step instructions for setting up and using the AccuKnox MCP Server with your favorite AI tools.

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10 or higher installed.
- An AccuKnox API Token (get it from your CSPM dashboard).

### 2. Installation
Clone the repository and install dependencies:

```bash
git clone <repository-url>
cd MCP_server_Poc
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configuration
**Important:** Currently, the server relies on a `.env` file for configuration. Please do not configure environment variables directly in `mcp.json` at this time, although this may change in future updates.

Create a `.env` file in the project root:

```env
ACCUKNOX_BASE_URL=https://cspm.demo.accuknox.com
ACCUKNOX_API_TOKEN=your_token_here
```

---

## 🛠️ Client Configuration

### 1. VS Code (GitHub Copilot)

**Prerequisites:**
- [GitHub Copilot Extension](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) installed.

**Setup:**
1.  Create a folder named `.vscode` in your project root (if it doesn't exist).
2.  Create a file named `mcp.json` inside `.vscode/`.
3.  Add the following configuration (replace `/absolute/path/to` with your actual path):

```json
{
  "mcpServers": {
    "accuknox": {
      "command": "/absolute/path/to/MCP_server_Poc/venv/bin/python",
      "args": ["/absolute/path/to/MCP_server_Poc/MCP_server.py"]
    }
  }
}
```
4.  Restart VS Code or reload the window.
5.  Open Copilot Chat and look for the "Tools" icon to verify `accuknox` is enabled.

### 2. Cursor

Cursor supports MCP servers via a configuration file similar to VS Code, but in a different location.

**Setup:**
1.  Create a folder named `.cursor` in your project root (if it doesn't exist).
2.  Create a file named `mcp.json` inside `.cursor/`.
3.  Add the following configuration:

```json
{
  "mcpServers": {
    "accuknox": {
      "command": "/absolute/path/to/MCP_server_Poc/venv/bin/python",
      "args": ["/absolute/path/to/MCP_server_Poc/MCP_server.py"]
    }
  }
}
```
4.  **Important:** Ensure the `.env` file is in the project root. Cursor should pick up the environment variables from the `.env` file if opened in the project root. If you encounter issues, you can use the wrapper script approach mentioned below.

**Wrapper Script Approach (Optional):**
If Cursor fails to load the environment variables, create a `start_server.sh` script:
```bash
#!/bin/bash
# Navigate to the project directory to ensure .env is loaded
cd /absolute/path/to/MCP_server_Poc
source .env
./venv/bin/python MCP_server.py
```
Make it executable (`chmod +x start_server.sh`) and update `mcp.json` to point to this script.

### 3. Claude Desktop App

**Setup:**
1.  Locate your Claude Desktop configuration file:
    *   **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
    *   **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
2.  Edit the file to include the AccuKnox server:

```json
{
  "mcpServers": {
    "accuknox": {
      "command": "/absolute/path/to/MCP_server_Poc/venv/bin/python",
      "args": ["/absolute/path/to/MCP_server_Poc/MCP_server.py"]
    }
  }
}
```
3.  Restart the Claude Desktop App.
4.  Look for the 🔌 icon to verify the server is connected.

### 4. Gemini CLI

**Setup:**
1.  Install the Gemini CLI tools (if not already installed).
2.  Add the MCP server using the `gemini` command:

```bash
gemini mcp add accuknox \
  /absolute/path/to/MCP_server_Poc/venv/bin/python \
  /absolute/path/to/MCP_server_Poc/MCP_server.py
```

**Note:** Ensure you run the `gemini` command from the project directory where `.env` is located, or that the environment variables are exported in your shell.

### 5. HTTP Server Configuration (Advanced)

To use the `fastmcp` server in HTTP mode (SSE):

1.  **Activate Virtual Environment:**
    ```bash
    cd /absolute/path/to/MCP_server_Poc
    source venv/bin/activate
    ```

2.  **Start the Server:**
    ```bash
    python3 fastmcp_server.py
    ```
    The server will start on `http://0.0.0.0:8000`.

3.  **Configure Client (e.g., VS Code/Cursor):**
    Update your `mcp.json` to use the SSE endpoint:

    ```json
    {
      "mcpServers": {
        "accuknox-http": {
          "url": "http://localhost:8000/mcp",
          "type": "sse"
        }
      }
    }
    ```

---

## 💡 Usage Examples

Once connected, you can ask questions like:

*   "How many cloud assets do I have?"
*   "Show me all AWS S3 buckets in us-east-1."
*   "What are the critical vulnerabilities in my AI models?"
*   "List deployed AI models discovered in the last 24 hours."

## ❓ Troubleshooting

*   **Server not starting?** Check the logs or try running the command manually in your terminal to see errors.
*   **Authentication failed?** Verify your `ACCUKNOX_API_TOKEN` is correct in the `.env` file.
*   **Path issues?** Always use **absolute paths** in configuration files.
