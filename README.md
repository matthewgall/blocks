# Blocks - Building Block Collection Manager

A self-hostable web application for cataloging personal building block collections (LEGO, Block Tech, and generic clone brands). Built with Go, SQLite, and server-rendered HTML templates.

## Features

- 🧱 **Collection Management**: Track sets, brands, and collection items
- 📱 **Mobile-First**: Responsive design optimized for desktop and mobile
- 🖼️ **Collection Photos**: Upload multiple photos per collection item
- 🔍 **External Data**: Optional metadata enrichment from Brickset & Rebrickable
- 💰 **Valuation (TBD)**: Resale valuation (provider not finalized)
- 🏠 **Self-Hosted**: Single binary deployment with SQLite database
- 🔒 **Secure**: JWT authentication with secure cookie sessions
- 📊 **Dashboard**: Statistics and overview of your collection

## Quick Start

### From Source

```bash
# Clone and build
git clone https://github.com/matthewgall/blocks.git
cd blocks
go mod tidy
go build ./cmd/blocks

# Create data directory
mkdir -p data/uploads

# Run
./blocks
```

On first launch, visit `/setup` to create the initial admin account.

## Configuration

Create a `config.yaml` file:

```yaml
server:
  address: ":8080"
  read_timeout: 10s
  write_timeout: 10s
  idle_timeout: 60s

database:
  path: "data/blocks.db"

auth:
  session_secret: "your-secret-key-here"
  bcrypt_cost: 12

uploads:
  method: "local" # local or s3
  max_size: 10485760  # 10MB
  local:
    directory: "data/uploads"
  s3:
    bucket: ""
    region: ""
    endpoint: "" # Optional for S3-compatible services
    public_url: "" # Optional hostname/base URL for serving uploads
    access_key_id: ""
    secret_access_key: ""
    session_token: ""
    prefix: ""
    path_style: false

app:
  name: "Blocks"
  version: "1.0.0"
  default_currency: "GBP"
  embed_assets: true

# Optional external providers
providers:
  brickset:
    api_key: "your-brickset-api-key"
    daily_limit: 100
  rebrickable:
    api_key: "your-rebrickable-api-key"

cache:
  provider: "sqlite" # sqlite or redis
  ttl:
    default: 24h
    remote: 720h # 30 days
  redis:
    url: "" # Optional: redis://user:pass@host:6379/0 or rediss://host:6379/0
    addr: "" # e.g. "localhost:6379"
    password: ""
    db: 0
    tls: false
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login with username/password
- `POST /api/auth/logout` - Logout

### Brands
- `GET /api/brands` - List all brands
- `POST /api/brands` - Create new brand
- `GET /api/brands/{id}` - Get brand details
- `PUT /api/brands/{id}` - Update brand
- `DELETE /api/brands/{id}` - Delete brand

### Sets
- `GET /api/sets` - List all sets (with search/filter)
- `POST /api/sets` - Create new set
- `GET /api/sets/{id}` - Get set details
- `PUT /api/sets/{id}` - Update set
- `DELETE /api/sets/{id}` - Delete set

### Collection Items
- `GET /api/collection` - List collection items
- `POST /api/collection` - Add collection item
- `PUT /api/collection/{id}` - Update collection item
- `DELETE /api/collection/{id}` - Delete collection item

### Valuations (TBD)
- Valuation provider is not finalized yet.

### Providers
- `GET /api/providers/sets/{setNum}` - Fetch set metadata (Brickset → Rebrickable)

## External API Integration

### Brickset API
- **Purpose**: Set metadata and images
- **Rate Limit**: ~100 calls/day (configurable)
- **Cache TTL**: 30 days
- **Required**: API key from [brickset.com](https://brickset.com/api/v3.asmx/getSets)

### Rebrickable API
- **Purpose**: Alternative metadata source
- **Rate Limit**: 1 rps, burst 3
- **Cache TTL**: 30 days
- **Required**: API key from [rebrickable.com](https://rebrickable.com/api/v3/)

### Valuation Providers (TBD)
- Provider selection is in progress.

## Database Schema

The application uses SQLite with the following main tables:

- `brands` - LEGO/clone brand information
- `sets` - Building set catalog
- `collection_items` - Personal collection tracking
- `valuations` - Price valuation history
- `external_cache` - API response caching
- `users` - Authentication (single-user)

## Development

### Building

```bash
go build ./cmd/blocks
```

### Testing

```bash
go test ./...
```

### Linting

```bash
golangci-lint run
```

### Project Structure

```
cmd/blocks/           # Main application entry point
internal/
  config/            # Configuration management
  db/                # Database layer and migrations
  models/            # Data models and types
  auth/              # Authentication and sessions
  cache/             # External API caching
  providers/         # External API clients
    brickset/        # Brickset API client
    rebrickable/     # Rebrickable API client
  http/              # HTTP server and handlers
  templates/         # HTML templates
static/              # Static assets (CSS, JS, images)
data/                # Runtime data directory
```

## Security

- **Authentication**: JWT tokens with secure HttpOnly cookies
- **CSRF Protection**: Built into POST routes
- **Input Validation**: All user input validated and sanitized
- **SQL Injection**: Prepared statements used throughout
- **Rate Limiting**: Configurable limits on auth endpoints
- **File Uploads**: Size-limited and validated uploads

## Backup and Restore

### Import & Export

- Import your collection via `/import` using Brickset or Rebrickable CSV exports.
- Export your collection via `/export` in Brickset CSV, Rebrickable CSV, or Blocks formats.
- For a full backup, use the Blocks SQLite export (`/export/blocks?format=sqlite`) or copy `data/blocks.db`.

### Backup

```bash
# Backup database
cp data/blocks.db backup/blocks-$(date +%Y%m%d).db

# Backup uploads
tar -czf backup/uploads-$(date +%Y%m%d).tar.gz data/uploads/
```

### Restore

```bash
# Stop the application
pkill blocks

# Restore database
cp backup/blocks-20231201.db data/blocks.db

# Restore uploads
tar -xzf backup/uploads-20231201.tar.gz

# Start the application
./blocks
```

## Deployment

### Docker

```bash
# Build image
docker build -t blocks .

# Run container
docker run -d \
  --name blocks \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  blocks
```

### Systemd Service

Create `/etc/systemd/system/blocks.service`:

```ini
[Unit]
Description=Blocks Building Block Collection Manager
After=network.target

[Service]
Type=simple
User=blocks
WorkingDirectory=/opt/blocks
ExecStart=/opt/blocks/blocks
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable blocks
sudo systemctl start blocks
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: See the `/docs` directory for detailed guides
- **Community**: Join discussions in GitHub Issues

## Changelog

### v1.0.0 (2024-01-25)

- Initial release
- Complete collection management
- External API integration
- Mobile-responsive UI
- Docker deployment support
