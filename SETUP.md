# Icinga2 MCP Server Setup Guide

This guide walks you through setting up the Icinga2 MCP server, including Icinga2 API configuration.

## Prerequisites

- Python 3.10 or higher
- Access to an Icinga2 instance (version 2.8+)
- Icinga2 API enabled (default in modern installations)

## Step 1: Install the MCP Server

### Option A: Install from source

```bash
git clone <repository-url>
cd icinga2-mcp
pip install -e .
```

### Option B: Install from PyPI (when published)

```bash
pip install icinga2-mcp
```

## Step 2: Configure Icinga2 API Access

### Enable the Icinga2 API (if not already enabled)

On your Icinga2 server:

```bash
icinga2 api setup
systemctl restart icinga2
```

This creates a CA, generates certificates, and enables the API feature.

### Create an API User

Create a new API user configuration file on your Icinga2 server:

**File:** `/etc/icinga2/conf.d/api-users.conf`

```icinga2
object ApiUser "mcp-user" {
  password = "your-secure-password"
  permissions = [ "*" ]
}
```

For production use, restrict permissions to only what's needed:

```icinga2
object ApiUser "mcp-user" {
  password = "your-secure-password"
  permissions = [
    {
      permission = "objects/query/Host"
      filter = {{ regex("^web.*", host.name) }}
    },
    {
      permission = "objects/query/Service"
    },
    {
      permission = "actions/schedule-downtime"
    },
    {
      permission = "actions/acknowledge-problem"
    }
  ]
}
```

After adding the user, reload Icinga2:

```bash
systemctl reload icinga2
```

### Verify API Access

Test the API access using curl:

```bash
curl -k -s -u mcp-user:your-secure-password \
  https://your-icinga-host:5665/v1/objects/hosts | jq .
```

You should see a JSON response with your hosts.

## Step 3: Configure the MCP Server

Create a `.env` file (copy from `.env.example`):

```bash
cp .env.example .env
```

Edit `.env` with your values:

```
ICINGA2_API_URL=https://your-icinga-host:5665
ICINGA2_API_USER=mcp-user
ICINGA2_API_PASSWORD=your-secure-password
```

## Step 4: Configure Claude Desktop (or your MCP client)

### For Claude Desktop

1. Locate your Claude Desktop config file:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

2. Add the Icinga2 MCP server configuration:

```json
{
  "mcpServers": {
    "icinga2": {
      "command": "python",
      "args": ["-m", "icinga2_mcp"],
      "env": {
        "ICINGA2_API_URL": "https://your-icinga-host:5665",
        "ICINGA2_API_USER": "mcp-user",
        "ICINGA2_API_PASSWORD": "your-secure-password"
      }
    }
  }
}
```

3. Restart Claude Desktop

### For other MCP clients

Refer to your client's documentation for adding MCP servers. The basic requirements are:

- Command: `python -m icinga2_mcp`
- Environment variables: `ICINGA2_API_URL`, `ICINGA2_API_USER`, `ICINGA2_API_PASSWORD`

## Step 5: Test the Integration

In Claude Desktop (or your MCP client), try:

```
"Show me all hosts"
```

You should see a list of your Icinga2 monitored hosts.

## Troubleshooting

### "Connection error" or "API request failed"

**Check:**
1. Icinga2 API is accessible: `curl https://your-icinga-host:5665`
2. Firewall allows access to port 5665
3. API credentials are correct
4. Environment variables are set correctly

### "Missing required environment variables"

Ensure all three environment variables are set:
- `ICINGA2_API_URL`
- `ICINGA2_API_USER`
- `ICINGA2_API_PASSWORD`

### SSL Certificate Errors

If you're using self-signed certificates, you may need to configure certificate verification. The client currently verifies SSL by default. For testing with self-signed certs, you could modify the client initialization in `server.py`.

For production, use proper certificates from Let's Encrypt or your organization's CA.

### Permission Denied Errors

Check your API user permissions in `/etc/icinga2/conf.d/api-users.conf`. The user needs:
- `objects/query/Host` - for listing hosts
- `objects/query/Service` - for listing services
- `actions/schedule-downtime` - for scheduling downtimes
- `actions/acknowledge-problem` - for acknowledging problems

### No Hosts/Services Returned

Verify that:
1. Your Icinga2 instance has hosts/services configured
2. The API user has permission to view them
3. Filters aren't excluding all results

## Security Best Practices

1. **Use strong passwords** for API users
2. **Restrict permissions** to only what's needed
3. **Use HTTPS** (enforced by Icinga2)
4. **Rotate credentials** regularly
5. **Monitor API access** via Icinga2 logs
6. **Use certificate-based auth** for production (future enhancement)

## Advanced Configuration

### Using Environment Files

Instead of embedding credentials in the MCP client config, you can use environment files:

```json
{
  "mcpServers": {
    "icinga2": {
      "command": "bash",
      "args": ["-c", "source /path/to/.env && python -m icinga2_mcp"]
    }
  }
}
```

### Filtering by Host Groups

Restrict the API user to specific host groups:

```icinga2
object ApiUser "mcp-user" {
  password = "your-password"
  permissions = [
    {
      permission = "objects/query/Host"
      filter = {{ "production" in host.groups }}
    }
  ]
}
```

## Next Steps

- Review [Usage Examples](examples/usage_examples.md) for practical scenarios
- Check the [README](README.md) for feature documentation
- Explore Icinga2 API documentation for advanced filtering options

## Support

For issues specific to:
- **Icinga2 API**: See [Icinga2 API Documentation](https://icinga.com/docs/icinga-2/latest/doc/12-icinga2-api/)
- **MCP Server**: Open an issue in this repository
- **Claude Desktop**: Refer to Anthropic's documentation
