FROM node:18-slim
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN mkdir -p attachments
EXPOSE 3000 2525
CMD ["node", "index.js"]
