FROM node:20-alpine AS base
WORKDIR /app

# Dependencies
COPY package.json package-lock.json ./
RUN npm ci --production=false

# Source
COPY . .

# Build
RUN npx next build

# Production
FROM node:20-alpine AS production
WORKDIR /app
ENV NODE_ENV=production

COPY --from=base /app/.next ./.next
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./package.json
COPY --from=base /app/public ./public
COPY --from=base /app/lib ./lib
COPY --from=base /app/generated ./generated
COPY --from=base /app/conformance ./conformance
COPY --from=base /app/mcp-server ./mcp-server

EXPOSE 3000
CMD ["npm", "start"]
