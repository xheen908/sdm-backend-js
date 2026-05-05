# Use the official lightweight Node.js 22 slim image as the base
FROM node:22-slim

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker caching
COPY package*.json ./

# Install dependencies (only production dependencies for a lightweight image)
RUN npm ci --only=production

# Copy the rest of the application files
COPY . .

# Expose the port the server listens on
EXPOSE 3000

# Set environment to production
ENV NODE_ENV=production

# Start the application
CMD ["node", "app.js"]
