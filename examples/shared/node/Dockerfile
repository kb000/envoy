FROM node:21.6-bookworm-slim@sha256:e8a7eb273ef8a9ebc03f0ad03c0fd4bbc3562ec244691e6fc37344ee2c4357d2 as node-base


FROM node-base as node-http-auth
ARG NODE_APP=.
ARG NODE_APP_NAME=http-service/server
# Add an env to save ARG
ENV NODE_APP_PATH "/app/${NODE_APP_NAME}"
COPY "$NODE_APP" /app
# Dont use exec form to interpolate correctly
CMD node $NODE_APP_PATH
