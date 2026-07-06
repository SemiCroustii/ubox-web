# Utiliser une version LTS de Node.js
FROM node:20-slim

# Installation des dépendances système nécessaires à la compilation (node-gyp)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*
    
# Créer le répertoire de travail
WORKDIR /usr/src/app

# Copier les fichiers de dépendances
COPY package*.json ./

# Installer les dépendances
RUN npm install

# Copier le reste du code source
COPY . .

# Exposer les ports de l'application
EXPOSE 8554 48263

# Lancer l'application (utilisez nodemon pour le développement)
CMD ["npm", "run", "dev"]