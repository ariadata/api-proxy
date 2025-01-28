# API Proxy Service

A lightweight API proxy service written in Go that supports multiple endpoints, rate limiting, and proxy rotation.

## Features

- Multiple site/endpoint support
- API key rotation
- Rate limiting
- SOCKS5 and HTTP proxy support
- Detailed logging system
- Docker support
- CORS enabled
- Customizable base path

## Quick Start

### Using Docker Compose

1. Clone the repository
2. Configure your settings:
   - Copy `.env.example` to `.env`
   - Copy `config.json.example` to `config.json`
3. Run the service:
   ```bash
   docker-compose up -d
   ```

### Manual Setup

1. Install Go 1.22 or later
2. Configure your settings in `config.json`
3. Run the service:
   ```bash
   go run main.go
   ```

## Configuration

### Environment Variables

- `PORT`: Server port (default: 3003)
- `LOG_LEVEL`: Logging level (debug, info, warn, error)
- `COMPOSE_PROJECT_NAME`: Docker compose project name
- `UID`: User ID for Docker
- `GID`: Group ID for Docker
- `DC_HTTP_PORT`: Docker container HTTP port

### Config.json Structure

```json
{
  "GLOBAL_SETTINGS": {
    "DIRECT_ACCESS": false,
    "BASE_PATH": "/proxy",
    "PROXIES": [
      "socks5://user:pass@host:port",
      "http://user:pass@host:port"
    ]
  },
  "SITES": {
    "site-name": {
      "domain": "https://api.example.com",
      "PROXY_TYPE": "header|query|path|direct",
      "KEY": "X-Api-Key",
      "VALUES": [
        {"key1": 3},
        {"key2": 3}
      ]
    }
  }
}
```

#### Configuration Fields

- `BASE_PATH`: Base URL path for all proxy endpoints (default: "/proxy")
- `PROXY_TYPE`: How the proxy should handle requests
  - Supported types: `header`, `query`, `path`, or `direct`
  - For `direct` type, `VALUES` should contain full target URLs
- `KEY`: API key header name or query parameter name
- `VALUES`: API keys with their rate limits

## Usage

### Making Requests

The proxy service accepts requests in the following format:

```
http://localhost:{PORT}{BASE_PATH}/{site-name}/{endpoint}
```

Examples:
```bash
# Default configuration
curl http://localhost:3003/proxy/myip4/

# Custom base path configuration
curl http://localhost:3003/api/myip4/
```

### Logs

Logs are written to both console and `proxy.log` file. View Docker container logs using:

```bash
docker-compose logs api-proxy
```

## Development

### Prerequisites

- Go 1.22+
- Docker and Docker Compose (for containerized deployment)

### Building

```bash
# Build locally
go build -o api-proxy

# Build Docker image
docker-compose build
```

## License

MIT License