FROM node:20-alpine
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY backend/package.json ./backend/
RUN cd backend && npm install --omit=dev --no-audit --no-fund
COPY backend/ ./backend/
COPY frontend/package.json ./frontend/
RUN cd frontend && npm install --no-audit --no-fund
COPY frontend/ ./frontend/
RUN cd frontend && npm run build
RUN mkdir -p /app/backend/data && chown -R node:node /app
USER node
WORKDIR /app/backend
EXPOSE 3001
ENV NODE_ENV=production
ENV PORT=3001
ENV DATA_DIR=/app/backend/data
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD wget -qO- http://127.0.0.1:3001/ready || exit 1
CMD ["node","server.js"]
