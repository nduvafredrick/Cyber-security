FROM node:20-alpine

WORKDIR /app

COPY backend/package.json ./backend/
RUN cd backend && npm install --omit=dev

COPY backend/ ./backend/

COPY frontend/package.json ./frontend/
RUN cd frontend && npm install
COPY frontend/ ./frontend/
RUN cd frontend && npm run build

WORKDIR /app/backend
RUN mkdir -p data

EXPOSE 3001
ENV NODE_ENV=production
ENV PORT=3001

CMD ["node", "server.js"]
