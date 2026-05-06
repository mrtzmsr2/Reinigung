module.exports = {
  apps: [{
    name: 'reinigungsmanagement',
    script: 'server.js',
    cwd: __dirname,
    env: {
      NODE_ENV: 'production',
      PORT: 6122
    },
    max_restarts: 10,
    autorestart: true,
    watch: false
  }]
};
