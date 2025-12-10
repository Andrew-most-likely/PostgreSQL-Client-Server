FROM node:18-alpine
WORKDIR /app

# Copy package files and install dependencies
COPY package.json ./
RUN npm install

# Copy application code
COPY index.js ./

# Copy the data directory
COPY data/ ./data/

EXPOSE 3000
CMD ["node", "index.js"]