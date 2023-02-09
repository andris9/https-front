FROM node:16-alpine
WORKDIR /app
COPY . .
RUN npm ci --only=production
EXPOSE 80
ENTRYPOINT npm run start
