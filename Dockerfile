FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src/ ./src/
COPY site/ ./site/

EXPOSE 8080

CMD ["node", "src/server.js"]
