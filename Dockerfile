# syntax=docker/dockerfile:1.4

ARG NODE_VERSION=22

####################################################################################################
## Build Packages

FROM node:${NODE_VERSION}-alpine AS builder

# Remove again once corepack >= 0.31 made it into base image
# (see https://github.com/directus/directus/issues/24514)
RUN npm install --global corepack@latest

RUN apk --no-cache add python3 py3-setuptools build-base

WORKDIR /directus

COPY package.json .
RUN corepack enable && corepack prepare

# Deploy as 'node' user to match pnpm setups in production image
# (see https://github.com/directus/directus/issues/23822)
RUN chown node:node .
USER node

ENV NODE_OPTIONS=--max-old-space-size=8192

COPY pnpm-lock.yaml .
RUN pnpm fetch

COPY --chown=node:node . .
RUN <<EOF
	set -ex
	pnpm install --recursive --offline --frozen-lockfile
	npm_config_workspace_concurrency=2 pnpm run build
	pnpm --filter directus deploy --legacy --prod dist
	cd dist
	# Regenerate package.json file with essential fields only
	# (see https://github.com/directus/directus/issues/20338)
	node -e '
		const f = "package.json", {name, version, type, exports, bin} = require(`./${f}`), {packageManager} = require(`../${f}`);
		fs.writeFileSync(f, JSON.stringify({name, version, type, exports, bin, packageManager}, null, 2));
	'
	mkdir -p database extensions uploads
EOF

####################################################################################################
## Create Production Image

FROM node:${NODE_VERSION}-alpine AS runtime

# Pin exact versions to avoid unexpected updates via floating tags
RUN npm install --global \
	pm2@7.0.1 \
	corepack@0.35.0

USER node

WORKDIR /directus

LABEL org.opencontainers.image.source="https://github.com/directus/directus" \
      org.opencontainers.image.description="Directus – flexible backend for all your projects" \
      org.opencontainers.image.licenses="BUSL-1.1"

ENV \
	DB_CLIENT="sqlite3" \
	DB_FILENAME="/directus/database/database.sqlite" \
	NODE_ENV="production" \
	NPM_CONFIG_UPDATE_NOTIFIER="false"

COPY --from=builder --chown=node:node /directus/ecosystem.config.cjs .
COPY --from=builder --chown=node:node /directus/dist .

EXPOSE 8055

# Kubernetes and Docker health checks use this endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
	CMD wget -qO- http://localhost:8055/server/health || exit 1

CMD : \
	&& node cli.js bootstrap \
	&& pm2-runtime start ecosystem.config.cjs \
	;
