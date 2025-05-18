// server.js
const fs = require('fs');
const path = require('path');
const express = require('express');
const https = require('https');
const expressWs = require('express-ws');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { Client } = require('ssh2');

// Create the Express application
const app = express();

// Set secure HTTP headers
app.use(helmet());

// Set up logging for HTTP requests
app.use(morgan('combined'));

// Rate limiting (adjust values as needed)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 100, // limit each IP per minute
  message: 'Too many requests from this IP, please try again after a minute.'
});
app.use(limiter);

// Serve static assets from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// ------------------------------------------------------------------------
// Create an HTTPS server using TLS certificates.
// In production, use valid certificates (or terminate TLS at a proxy).
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'privkey.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem'))
};

const PORT = process.env.PORT || 3000;
const httpsServer = https.createServer(httpsOptions, app);

// Set up express-ws using the HTTPS server so the WebSocket connections are secure.
expressWs(app, httpsServer);

// ------------------------------------------------------------------------
// WebSocket endpoint for SSH connections
app.ws('/ssh', (ws, req) => {
  ws._socket.setTimeout(2 * 60 * 1000); // Set a timeout (2 minutes)

  const sshConn = new Client();
  let shellStream = null;
  let connected = false;

  // If desired, set up a whitelist for allowed hosts:
  const ALLOWED_HOSTS = process.env.ALLOWED_HOSTS
    ? process.env.ALLOWED_HOSTS.split(',')
    : null;

  // Validate the configuration. In our case, either a password or privateKey must be provided.
  function validateConfig(config) {
    if (!config.host || typeof config.host !== 'string') return false;
    if (!config.username || typeof config.username !== 'string') return false;
    if ((!config.password || typeof config.password !== 'string') &&
        (!config.privateKey || typeof config.privateKey !== 'string')) {
      return false;
    }
    if (config.port && isNaN(parseInt(config.port, 10))) return false;
    return true;
  }

  ws.on('message', (msg) => {
    if (!connected) {
      let config;
      try {
        config = JSON.parse(msg);
      } catch (err) {
        ws.send('Invalid configuration format. Expected JSON.');
        ws.close();
        return;
      }

      if (!validateConfig(config)) {
        ws.send('Invalid configuration fields.');
        ws.close();
        return;
      }

      // If a whitelist is defined, ensure the host is allowed.
      if (ALLOWED_HOSTS && !ALLOWED_HOSTS.includes(config.host)) {
        ws.send('Connection to this host is not allowed.');
        ws.close();
        return;
      }

      // Default the port to 22 if not provided.
      config.port = parseInt(config.port, 10) || 22;

      // Build the connection options.
      const connectionOptions = {
        host: config.host,
        port: config.port,
        username: config.username,
        tryKeyboard: true,
        readyTimeout: 20000 // 20-second timeout
      };

      // Prefer key-based authentication if provided; otherwise, use a password.
      if (config.privateKey && config.privateKey.trim() !== '') {
        connectionOptions.privateKey = config.privateKey;
      } else {
        connectionOptions.password = config.password;
      }

      // Establish the SSH connection.
      sshConn.on('ready', () => {
        connected = true;
        ws.send('\r\n*** SSH CONNECTION ESTABLISHED ***\r\n');
        sshConn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err, stream) => {
          if (err) {
            ws.send('SSH shell error: ' + err.message);
            ws.close();
            return;
          }
          shellStream = stream;
          stream.on('data', (data) => {
            if (ws.readyState === ws.OPEN) {
              ws.send(data.toString());
            }
          });
          stream.stderr.on('data', (data) => {
            if (ws.readyState === ws.OPEN) {
              ws.send(data.toString());
            }
          });
          stream.on('close', () => {
            ws.send('\r\n*** SSH CONNECTION CLOSED ***\r\n');
            sshConn.end();
            ws.close();
          });
        });
      }).on('error', (err) => {
        if (ws.readyState === ws.OPEN) {
          ws.send('SSH Connection Error: ' + err.message);
          ws.close();
        }
      }).connect(connectionOptions);

    } else if (shellStream) {
      try {
        shellStream.write(msg);
      } catch (error) {
        ws.send('Error writing to SSH stream: ' + error.message);
      }
    }
  });

  ws.on('close', () => {
    if (sshConn) sshConn.end();
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
    ws.close();
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Express error:', err.stack);
  res.status(500).send('Something went wrong!');
});

// Start the HTTPS server
httpsServer.listen(PORT, () => {
  console.log(`WebSSH Server | Running on ${PORT}`);
});