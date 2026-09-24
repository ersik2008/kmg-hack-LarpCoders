FROM node:20-alpine AS build

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy project files
COPY . .

# Build the project for production
RUN npm run build

# Use Nginx to serve the static files
FROM nginx:alpine

# Copy the built assets to Nginx html directory
COPY --from=build /app/dist /usr/share/nginx/html

# Replace the default Nginx configuration to support SPA routing
RUN echo "server { \
    listen 80; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html index.htm; \
        try_files \$uri \$uri/ /index.html; \
    } \
}" > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
