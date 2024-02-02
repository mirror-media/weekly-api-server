ARG NODE_VERSION=16.19.1

FROM node:${NODE_VERSION} AS build

WORKDIR /build

COPY package.json yarn.lock /build/

RUN yarn install

COPY . /build/

RUN yarn build


FROM node:${NODE_VERSION}

WORKDIR /app

ENV NODE_ENV=production

# Automatically leverage output traces to reduce image size
COPY --from=build /build/node_modules ./node_modules
COPY --from=build /build/lib ./lib

CMD ["node", "lib/server.js"]
