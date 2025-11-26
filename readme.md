# Sway Remote Control

A simple web interface to control your Sway window manager from your phone. Basically lets you use your phone as a remote control for your linux desktop.

## What is this

I got tired of reaching for my keyboard when watching videos or browsing on my couch. Intend for this to allow me to control MPV, switch workspaces, move windows around, and generally control my sway setup from my phone's browser.

## Features

- Control MPV (play, pause, seek, volume)
- Virtual trackpad for mouse control 
- Switch between workspaces
- Move windows around and change layouts 
- Some system stuff like network switching 

## How it works

The app runs a web server on your laptop that your phone connects to. It uses a simple pairing system similar to bluetooth - you get a 6 digit code on your laptop, type it into your phone, and your paired for an hour. After that it auto-refreshes as long as your using it.

## Running it

You need Go 1.24 or later.

```bash
# Build it
make build

# Run the server
./bin/server
```

The server listens on port 8080. Just open `http://your-laptop-ip:8080` on your phone.

If you have avahi/mdns setup you can use `http://rocinante.local:8080` instead (change rocinante to whatever your hostname is).

## Pairing

1. Open the app on your phone
2. You'll see a pairing code form
3. Look at your laptop terminal for the 6-digit code
4. Type it in and hit pair
5. Your good to go for an hour, and it auto-extends while your using it

## Development

```bash
# Run tests
make test

# Run a specific test
go test ./internal/api -run TestName

# Build
make build
```

Tests use gotestsum if you have it installed, otherwise falls back to regular go test. 

## Project structure 

```
cmd/server/- Main entry point
internal/api/- HTTP handlers and routing
internal/security/ - KeyStore for managing API keys
internal/middleware/ - Request middleware (pairing refresh)
internal/components/ - Templ components
templates/ - Page templates
```

## Tech stack

- Go with Gin framework
- Templ for type-safe HTML templates
- HTMX for dynamic updates without page reloads
- bbolt for persistent key storage
- Unix sockets for MPV IPC

## TODO

- Print pairing codes to terminal (currently not showing)
- Add actual MPV control endpoints 
- Virtual trackpad implementation
- Workspace switching
- Better error handling

## License

Do whatever you want with it.
