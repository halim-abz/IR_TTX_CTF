FROM node:22-alpine
WORKDIR /app
COPY public ./public
COPY server ./server
RUN mkdir -p /app/data && chown -R node:node /app
USER node
ENV HOST=0.0.0.0 PORT=3000 DATA_DIR=/app/data
EXPOSE 3000
CMD ["node", "server/server.cjs"]
