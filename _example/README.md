# Spaceship DNS Example

This example demonstrates how to use the libdns spaceship provider to manage DNS records.

## Prerequisites

1. A Spaceship account with API access
2. API Key and Secret from Spaceship API Manager
3. A domain zone configured in Spaceship

## Environment Variables

You can set the required environment variables in two ways:

### Option 1: Using a .env file (Recommended)

1. Copy the example environment file:
   ```bash
   cp env.example .env
   ```

2. Edit the `.env` file with your actual values:
   ```
   SPACESHIP_API_KEY=your_api_key_here
   SPACESHIP_API_SECRET=your_api_secret_here
   SPACESHIP_ZONE=your-domain.com
   ```

### Option 2: Setting environment variables directly

```bash
export SPACESHIP_API_KEY="your_api_key_here"
export SPACESHIP_API_SECRET="your_api_secret_here"
export SPACESHIP_ZONE="your-domain.com"
```

## Running the Example

```bash
go run main.go
```

## What the Example Does

1. **Connects to Spaceship API** using your credentials
2. **Lists existing records** in the specified zone
3. **Creates or updates a test record** named `libdns-test` with a timestamp
4. **Verifies the operation** by retrieving the record again

## Expected Output

```
Found X existing records in zone your-domain.com:
  @: A, 1.2.3.4
  www: CNAME, your-domain.com
  ...

Creating new entry for libdns-test
Successfully created test record

Verifying record...
Found test record: libdns-test: TXT, This is a test entry created by libdns 2024-01-15 10:30:45
```

## API Permissions Required

Make sure your Spaceship API key has the following permissions:
- `dnsrecords:read` - Read DNS resource records
- `dnsrecords:write` - Write DNS resource records
