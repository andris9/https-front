FROM node:24-alpine

ENV NODE_ENV=production

WORKDIR /app

# Install dependencies first so the layer is cached while only sources change.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

EXPOSE 80 443

# Exec form, so the Node process is PID 1 and receives SIGTERM/SIGINT directly.
CMD ["node", "server.js"]
