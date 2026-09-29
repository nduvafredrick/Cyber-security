FROM node:20-alpine

WORKDIR /app
COPY backend/package.json backend/package-lock.json ./backend/
RUN cd backend && npm ci --omit=dev
COPY backend/ ./backend/
COPY frontend/package.json frontend/package-lock.json ./frontend/
RUN cd frontend && npm ci
COPY frontend/ ./frontend/
RUN cd frontend && npm run build

RUN mkdir -p /app/backend/data && chown -R node:node /app
USER node
WORKDIR /app/backend
EXPOSE 3001
ENV NODE_ENV=production
ENV PORT=3001
CMD ["node", "server.js"]
