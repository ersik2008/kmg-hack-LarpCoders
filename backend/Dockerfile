FROM node:22-alpine

WORKDIR /app

# git is required by RepositoryService to clone the repository under scan, and
# openssl/ca-certificates are needed for Prisma and for HTTPS clones. Without
# git in the image every scan died at the clone stage with "git: not found".
RUN apk add --no-cache git openssl ca-certificates

# Copy package.json and install dependencies.
# npm ci (reproducible): the prisma CLI is pinned to 7.10.0 to match
# @prisma/client. Re-resolving the previous ^8.0.0-rc.15 range pulled a v8 CLI
# without a `generate` command, which broke this build entirely.
COPY package*.json ./
RUN npm ci

# Copy the rest of the application
COPY . .

# Generate Prisma Client
RUN npx prisma generate

# Build the application
RUN npm run build

EXPOSE 3000

# Apply pending migrations before serving: nothing else in the stack creates the
# schema, so a fresh database used to leave the backend running against no tables.
CMD ["sh", "-c", "npx prisma migrate deploy && npm run start:prod"]
