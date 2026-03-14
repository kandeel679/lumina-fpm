# Use Node.js as the base image
FROM node:22-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package files and install dependencies
# (This requires that you actually have content in your package.json first!)
COPY package*.json ./
RUN npm install

# Copy the rest of your app's source code
COPY . .

# Expose the port your app runs on (e.g., 5173 for Vite, 3000 for React)
EXPOSE 5173

# The command to start your application
CMD ["npm", "run", "dev"]
