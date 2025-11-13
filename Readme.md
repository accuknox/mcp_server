# AccuKnox MCP Server - Testing Guide

Complete guide for testing MCP servers with stdio client, Gemini CLI, HTTP client, and VSCode Copilot.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Testing stdio Server](#testing-stdio-server)
  - [With Test Client](#with-test-client)
  - [With Gemini CLI](#with-gemini-cli)
  - [With VSCode Copilot (stdio)](#with-vscode-copilot-stdio)
- [Testing HTTP Server](#testing-http-server)
  - [With Test Client](#with-http-test-client)
  - [With VSCode Copilot (HTTP)](#with-vscode-copilot-http)

***

## Prerequisites

- Python 3.10 or higher
- pip package manager
- Gemini CLI (optional, for AI integration)
- VSCode or Cursor (optional, for IDE integration)

---

## Project Structure

```
MCP_server/
├── MCP_server.py              # stdio server (for Gemini CLI)
├── MCP_server_http.py         # HTTP server (for web/remote)
├── clients/
│   ├── __init__.py
│   ├── stdio_client.py        # Test client for stdio
│   └── http_client.py         # Test client for HTTP
├── shared/
│   ├── __init__.py
│   ├── tools.py               # Tool implementations
│   └── api.py          # AccuKnox API client
├── .vscode/
│   └── mcp.json               # VSCode Copilot configuration
├── .env                       # Environment variables (create your own)
├── requirements.txt
└── README.md
```

***

## Installation

### 1. Clone/Setup Project

```bash
cd MCP_server
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

Create `.env` file:

```env
ACCUKNOX_BASE_URL=https://cspm.demo.accuknox.com
ACCUKNOX_API_TOKEN=your_token_here
```

***

## Testing stdio Server

The stdio server uses standard input/output for communication, designed for local CLI integration.

### With Test Client

**Terminal 1: Start server (automatically started by client)**

**Terminal 2: Run test client**

```bash
python3 clients/stdio_client.py
```

**Interactive Menu:**
```
Options:
  1 - Count assets
  2 - List 5 assets
  3 - Search by category
  4 - Get vulnerabilities
  exit - Quit

Select: 1
```

**Example Output:**
```
Total assets: 1247
```

***

### With Gemini CLI

Gemini CLI provides AI-powered natural language interactions with your MCP server.

#### 1. Install Gemini CLI

```bash
pip install google-generativeai
```

#### 2. Configure MCP Server

```bash
# Add server to Gemini CLI (use absolute path)
gemini mcp add accuknox python3 /absolute/path/to/MCP_server.py
```

#### 3. Verify Configuration

```bash
gemini mcp list

# Output:
# accuknox: python3 /path/to/MCP_server.py
```

#### 4. Start Gemini CLI

```bash
gemini
```

#### 5. Test with Natural Language Queries

**Example 1: Count Assets**
```
You: How many cloud assets do I have?

Gemini: You have 1,247 cloud assets in your inventory.
```

**Example 2: Search by Category**
```
You: Show me 5 Container assets

Gemini: Here are 5 Container assets:
1. nginx-prod (Container) - Region: us-east-1
2. redis-cache (Container) - Region: us-west-2
3. postgres-db (Container) - Region: eu-west-1
4. kafka-broker (Container) - Region: us-east-1
5. redis-sentinel (Container) - Region: ap-south-1
```

**Example 3: Security Vulnerabilities**
```
You: What security vulnerabilities do my AI models have?

Gemini: Your AI models have 147 security issues:
• ML Models: 5 issues (1 Critical, 4 Medium)
• LLM Models: 136 issues (136 Critical)
• Datasets: 6 issues (6 High)

Immediate action required for 137 critical vulnerabilities.
```

#### 6. Remove Server (Optional)

```bash
gemini mcp remove accuknox
```

***

### With VSCode Copilot (stdio)

#### 1. Create Configuration File

Create `.vscode/mcp.json` in your project root:

```bash
mkdir -p .vscode
nano .vscode/mcp.json
```

#### 2. Add stdio Server Configuration

```json
{
  "mcpServers": {
    "accuknox-stdio": {
      "command": "python3",
      "args": ["${workspaceFolder}/MCP_server.py"],
      "env": {
        "ACCUKNOX_BASE_URL": "https://cspm.demo.accuknox.com",
        "ACCUKNOX_API_TOKEN": "your_token_here"
      }
    }
  }
}
```

**Note:** Using `${workspaceFolder}` makes the configuration portable across machines.

#### 3. Activate in VSCode

1. Open your project in VSCode
2. VSCode automatically detects `.vscode/mcp.json`
3. Click **"Start"** when prompted
4. Open Copilot Chat: `Ctrl+Shift+I` (Windows/Linux) or `Cmd+Shift+I` (Mac)
5. Enable **Agent Mode** (click brain icon )
6. Click **tools icon** () → Enable `accuknox-stdio`

#### 4. Test with Copilot

```
@agent How many cloud assets do I have?
@agent Show me Container assets in AWS
@agent What are my model vulnerabilities?
```

***

## Testing HTTP Server

The HTTP server provides REST API access for web clients and remote integrations.

### With HTTP Test Client

**Terminal 1: Start HTTP server**

```bash
python3 MCP_server_http.py
```

**Output:**
```
======================================================================
AccuKnox MCP Server - HTTP
======================================================================
Server: http://localhost:8000
Tools: search_assets, get_model_vulnerabilities
Press Ctrl+C to shutdown
======================================================================
INFO:     Uvicorn running on http://0.0.0.0:8000
```

**Terminal 2: Run test client**

```bash
python3 clients/http_client.py
```

**Interactive Menu:**
```
Options:
  1 - Count assets
  2 - List 5 assets
  3 - Search by category
  4 - Get vulnerabilities
  exit - Quit

Select: 4
```

***

### With VSCode Copilot (HTTP)

VSCode Copilot supports HTTP MCP servers starting from version 1.102+.

#### Prerequisites

- VSCode 1.102 or higher
- GitHub Copilot extension installed
- HTTP MCP server running on `http://localhost:8000`

***

#### Step 1: Verify HTTP Server

```bash
# Start HTTP server
python3 MCP_server_http.py

# In another terminal, verify it's running
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

***

#### Step 2: Configure VSCode

**Option A: Project-Level Configuration (Recommended)**

Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "accuknox-http": {
      "type": "http",
      "url": "http://localhost:8000"
    }
  },
  "inputs": []
}
```

**Option B: Remote Server Configuration**

For deployed servers:

```json
{
  "servers": {
    "accuknox-http": {
      "type": "http",
      "url": "https://your-server.com:8000",
      "headers": {
        "Authorization": "Bearer ${input:api-token}"
      }
    }
  },
  "inputs": [
    {
      "type": "promptString",
      "id": "api-token",
      "description": "AccuKnox API Token",
      "password": true
    }
  ]
}
```

**Option C: Global Configuration**

For all workspaces, create `~/.vscode/mcp.json`:

```json
{
  "servers": {
    "accuknox-http": {
      "type": "http",
      "url": "http://localhost:8000"
    }
  },
  "inputs": []
}
```

***

#### Step 3: Activate Server

**Method 1: Automatic Detection**

1. Open project in VSCode
2. VSCode detects `.vscode/mcp.json`
3. Click **"Start"** button in the file
4. Server status shows "running" in status bar

**Method 2: Command Palette**

1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
2. Type: **"MCP: Add Server"**
3. Select **"HTTP/SSE"**
4. Enter Server ID: `accuknox-http`
5. Enter URL: `http://localhost:8000`
6. Choose **Workspace** or **Global**
7. Click **Save**

**Method 3: Manual Configuration**

1. Create `.vscode/mcp.json` with above content
2. Save file
3. VSCode auto-detects and shows **Start** button

***

#### Step 4: Enable Copilot Agent Mode

1. **Open Copilot Chat:**
   - Press `Ctrl+Shift+I` (Windows/Linux)
   - Press `Cmd+Shift+I` (Mac)
   - Or click Copilot icon in Activity Bar

2. **Enable Agent Mode:**
   - Click the **brain icon** () at top
   - Or type `@agent` in chat

3. **Configure Tools:**
   - Click **tools icon** () at bottom
   - Find `accuknox-http` in list
   - Toggle **ON** to enable

***

#### Step 5: Test with Copilot

**Example 1: Asset Inventory**
```
@agent How many cloud assets do I have?

Copilot: You have 1,247 cloud assets in your inventory.
```

**Example 2: Category Search**
```
@agent Show me 5 Container assets

Copilot: Here are 5 Container assets:
1. nginx-prod (Container) - Region: us-east-1
2. redis-cache (Container) - Region: us-west-2
3. postgres-db (Container) - Region: eu-west-1
4. kafka-broker (Container) - Region: us-east-1
5. redis-sentinel (Container) - Region: ap-south-1
```

**Example 3: Security Analysis**
```
@agent What security vulnerabilities do my AI models have?

Copilot: Your AI models have 147 security issues:
• ML Models: 5 issues (1 Critical, 4 Medium)
• LLM Models: 136 issues (136 Critical)
• Datasets: 6 issues (6 High)

Critical attention required for 137 vulnerabilities.
```

**Example 4: Cloud Provider Filter**
```
@agent List AWS assets in us-east-1 region

Copilot: Found 234 AWS assets in us-east-1 region...
```

***

## Quick Reference

### Server Commands

| Action | Command |
|--------|---------|
| **stdio server** | `python3 MCP_server.py` |
| **HTTP server** | `python3 MCP_server_http.py` |
| **stdio client** | `python3 clients/stdio_client.py` |
| **HTTP client** | `python3 clients/http_client.py` |

### Configuration Paths

| Tool | Config Location |
|------|----------------|
| **VSCode Copilot** | `.vscode/mcp.json` or `~/.vscode/mcp.json` |
| **Gemini CLI** | Managed by `gemini mcp` commands |
