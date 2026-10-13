import fs from 'node:fs';

const files = [
  ['package', 'package.json'],
  ['index', 'index.html'],
  ['styles', 'styles.css'],
  ['app', 'app.js'],
  ['server', 'server.js'],
  ['manifest', 'manifest.webmanifest']
];

const indent = value => value.split('\n').map(line => `      ${line}`).join('\n');
let compose = `services:
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: training_fighter
      POSTGRES_USER: training_fighter
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
    volumes:
      - training_fighter_postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U training_fighter -d training_fighter"]
      interval: 5s
      timeout: 5s
      retries: 20
  app:
    image: node:22-alpine
    restart: unless-stopped
    working_dir: /app
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8787:8787"
    configs:
      - source: package
        target: /app/package.json
      - source: index
        target: /app/index.html
      - source: styles
        target: /app/styles.css
      - source: app
        target: /app/app.js
      - source: server
        target: /app/server.js
      - source: manifest
        target: /app/manifest.webmanifest
    environment:
      NODE_ENV: production
      PORT: 8787
      DATABASE_URL: postgresql://training_fighter:\${POSTGRES_PASSWORD}@db:5432/training_fighter
      JWT_SECRET: \${JWT_SECRET}
      APP_ENCRYPTION_KEY: \${APP_ENCRYPTION_KEY}
      OPENAI_API_KEY: \${OPENAI_API_KEY}
      OPENAI_MODEL: \${OPENAI_MODEL:-gpt-4.1-mini}
      GOOGLE_CLIENT_ID: \${GOOGLE_CLIENT_ID}
      GOOGLE_CLIENT_SECRET: \${GOOGLE_CLIENT_SECRET}
      GOOGLE_REDIRECT_URI: \${GOOGLE_REDIRECT_URI}
      APP_ORIGIN: \${APP_ORIGIN:-http://179.197.231.128:8787}
    command: sh -c "npm install --omit=dev --no-audit --no-fund && node server.js"
configs:
`;

for (const [key, file] of files) compose += `  ${key}:
    content: |
${indent(fs.readFileSync(file, 'utf8'))}
`;

compose += `volumes:
  training_fighter_postgres:
`;
process.stdout.write(compose);
