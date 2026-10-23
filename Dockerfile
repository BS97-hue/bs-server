FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY server.js ./server.js
COPY README.md ./README.md

USER node
EXPOSE 10000
CMD ["npm", "start"]
