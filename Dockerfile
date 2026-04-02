FROM node:20-alpine

WORKDIR /app

# Install backend deps
COPY backend/package.json ./backend/
RUN cd backend && npm install --omit=dev

# Copy backend source
COPY backend/ ./backend/

# Build frontend
COPY frontend/package.json ./frontend/
RUN cd frontend && npm install
COPY frontend/ ./frontend/
RUN cd frontend && npm run build

# Move built frontend into backend's expected path
RUN mkdir -p /app/frontend/dist && cp -r /app/frontend/dist /app/frontend/dist

WORKDIR /app/backend

# Create data dir
RUN mkdir -p data

EXPOSE 3001

ENV NODE_ENV=production
ENV PORT=3001

CMD ["node", "server.js"]
