# Generated by https://smithery.ai. See: https://smithery.ai/docs/config#dockerfile
FROM node:lts-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package.json package-lock.json* ./

# Install dependencies ignoring scripts
RUN npm install --ignore-scripts

# Bundle app source
COPY . .

# Build the project
RUN npm run build

# Expose necessary port if needed. Here MCP uses stdio so not needed

# Command to run the MCP server
CMD [ "node", "build/index.js" ]
