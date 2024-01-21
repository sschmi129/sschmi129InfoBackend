FROM node:20

WORKDIR /sschmi129InfoBackend

COPY package*.json ./

RUN npm install

COPY src/ src/

EXPOSE 3000

CMD ["node", "src/sschmi129InfoBackend.js"]





