FROM node:18-bookworm-slim

# Install lua5.1 (needed at runtime: server.js shells out to `lua5.1`)
RUN apt-get update \
    && apt-get install -y --no-install-recommends lua5.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 3000
CMD ["npm", "start"]
