FROM node:21.7-bookworm-slim@sha256:fbdb66de323c6aa010c6afc04dda9a4031d113ebc623588f42633b124b3a5ac6 as node-base


FROM node-base as node-http-auth
ARG NODE_APP=.
ARG NODE_APP_NAME=http-service/server
# Add an env to save ARG
ENV NODE_APP_PATH "/app/${NODE_APP_NAME}"
COPY "$NODE_APP" /app
# Dont use exec form to interpolate correctly
CMD node $NODE_APP_PATH
