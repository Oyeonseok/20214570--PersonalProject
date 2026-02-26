FROM node:latest
COPY . .
USER root
RUN npm install
