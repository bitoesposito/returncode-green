# frontend/Dockerfile
# Base
FROM node:20 AS base
WORKDIR /frontend
COPY package*.json ./
RUN npm ci --silent

# Sviluppo
FROM base AS development
RUN npm install -g @angular/cli@19.2.10 --silent
COPY . .
EXPOSE 4200
CMD ["ng", "serve", "--host", "0.0.0.0", "--poll", "2000"]

# Build produzione
FROM base AS build
RUN npm install -g @angular/cli@19.2.10 --silent
COPY . .
RUN npm run build:prod

# Serve statico
FROM nginx:alpine AS serve
COPY --from=build /frontend/dist/frontend /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]