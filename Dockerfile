FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src/ ./src/
COPY site/ ./site/

EXPOSE 8080

CMD ["node", "src/server.js"]
