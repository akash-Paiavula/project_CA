FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js .
RUN mkdir -p /data/files && chown -R node:node /data /app
USER node
EXPOSE 3000
CMD ["node", "server.js"]
