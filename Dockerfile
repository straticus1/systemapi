# Stage 1: Build the React Frontend
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# Stage 2: Build the Node.js Backend
FROM node:18-alpine
WORKDIR /app

# Install curl for health checks
RUN apk add --no-cache curl

# Copy backend package files
COPY package*.json ./
RUN npm ci --only=production

# Copy backend application code
COPY . .

# Copy the built React UI from the frontend-builder stage into a public folder
COPY --from=frontend-builder /app/frontend/dist ./public

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Change ownership
RUN chown -R nodejs:nodejs /app
USER nodejs

# Expose port
EXPOSE 3003

# Health check (matches standard fleet.js health ping)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3003/health || exit 1

# Start the Node.js backend
CMD ["node", "server.js"]
