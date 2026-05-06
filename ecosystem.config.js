module.exports = {
  apps: [{
    name: 'reinigungsmanagement',
    script: 'server.js',
    interpreter: 'C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\MSBuild\\Microsoft\\VisualStudio\\NodeJs\\node.exe',
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
