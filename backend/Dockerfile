# Dockerfile - Backend (dev)
FROM node:20 AS base
WORKDIR /src/app

# Installa client PostgreSQL solo se serve
RUN apt-get update && \
    apt-get install -y wget gnupg2 lsb-release && \
    sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list' && \
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add - && \
    apt-get update && \
    apt-get install -y postgresql-client-17 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --legacy-peer-deps --include=optional --silent

# Sviluppo
FROM base AS development
RUN npm install -g @nestjs/cli ts-node --silent
COPY . .
EXPOSE 3000
CMD ["npm", "run", "start:dev"]

# Build produzione
FROM base AS build
COPY . .
RUN npm run build

# Serve produzione
FROM node:20 AS production
WORKDIR /src/app
COPY --from=build /src/app/dist ./dist
COPY package*.json ./
RUN npm ci --only=production --include=optional --silent
EXPOSE 3000
CMD ["node", "dist/main.js"]