# Node 22 is the maintained LTS line (the image ran on Node 16, which gets no fixes any more).
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /home/node/app

# Exactly the locked versions, without development tools.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY index.js ./
COPY lib ./lib
COPY public ./public
COPY views ./views
COPY scripts ./scripts

# No root in the container, and node directly (no npm process kept in memory).
USER node
EXPOSE 3000
CMD ["node", "index.js"]
