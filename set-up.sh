#!/bin/bash

# Crave App Project Setup Script
# This script creates the complete project structure and files

echo "🚀 Setting up Crave App project..."

# Create main project directory
mkdir -p crave-app
cd crave-app

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p {mobile/{src/{components,screens,hooks,services,store/{slices},types,utils,contexts,__tests__},android,ios}
mkdir -p backend/{api-gateway,auth-service,post-service,business-service,user-service,notification-service}/{src/{controllers,models,services,middleware,utils,__tests__},dist}
mkdir -p {infrastructure/{k8s,docker},shared/{types,config,utils},scripts,docs,logs}

# Root package.json
echo "📦 Creating root package.json..."
cat > package.json << 'EOF'
{
  "name": "crave-app",
  "version": "1.0.0",
  "description": "Local food and drink discovery app",
  "scripts": {
    "dev": "concurrently \"npm run dev:backend\" \"npm run dev:mobile\"",
    "dev:backend": "concurrently \"npm run dev:auth\" \"npm run dev:posts\" \"npm run dev:business\" \"npm run dev:users\" \"npm run dev:gateway\"",
    "dev:mobile": "cd mobile && npm run start",
    "dev:auth": "cd backend/auth-service && npm run dev",
    "dev:posts": "cd backend/post-service && npm run dev",
    "dev:business": "cd backend/business-service && npm run dev",
    "dev:users": "cd backend/user-service && npm run dev",
    "dev:gateway": "cd backend/api-gateway && npm run dev",
    "setup": "npm run install:all && npm run db:migrate",
    "install:all": "npm ci && npm run install:backend && npm run install:mobile",
    "install:backend": "concurrently \"npm --prefix backend/auth-service ci\" \"npm --prefix backend/post-service ci\" \"npm --prefix backend/business-service ci\" \"npm --prefix backend/user-service ci\" \"npm --prefix backend/api-gateway ci\"",
    "install:mobile": "cd mobile && npm ci"
  },
  "devDependencies": {
    "concurrently": "^7.6.0"
  }
}
EOF

# Environment files
echo "🔐 Creating environment configuration..."
cat > .env.example << 'EOF'
# Application
NODE_ENV=development
API_VERSION=v1

# Security
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
BCRYPT_ROUNDS=12

# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/crave_db
REDIS_URL=redis://localhost:6379

# AWS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_S3_BUCKET=crave-app-media

# External Services
SENDGRID_API_KEY=your-sendgrid-key
GOOGLE_MAPS_API_KEY=your-google-maps-key
SENTRY_DSN=your-sentry-dsn

# Push Notifications
FCM_SERVER_KEY=your-fcm-server-key
EOF

# Docker Compose
echo "🐳 Creating Docker configuration..."
cat > infrastructure/docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgis/postgis:14-3.2
    environment:
      - POSTGRES_DB=crave_db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
EOF

# API Gateway package.json and main file
echo "🌐 Creating API Gateway service..."
cat > backend/api-gateway/package.json << 'EOF'
{
  "name": "crave-api-gateway",
  "version": "1.0.0",
  "main": "dist/app.js",
  "scripts": {
    "dev": "nodemon src/app.ts",
    "build": "tsc",
    "start": "node dist/app.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "http-proxy-middleware": "^2.0.6",
    "cors": "^2.8.5",
    "helmet": "^6.1.5",
    "express-rate-limit": "^6.7.0",
    "winston": "^3.8.2"
  },
  "devDependencies": {
    "@types/express": "^4.17.17",
    "@types/cors": "^2.8.13",
    "typescript": "^5.0.4",
    "nodemon": "^2.0.22",
    "ts-node": "^10.9.1"
  }
}
EOF

# Auth Service package.json
cat > backend/auth-service/package.json << 'EOF'
{
  "name": "crave-auth-service",
  "version": "1.0.0",
  "main": "dist/app.js",
  "scripts": {
    "dev": "nodemon src/app.ts",
    "build": "tsc",
    "start": "node dist/app.js",
    "test": "jest",
    "db:migrate": "sequelize-cli db:migrate",
    "db:seed": "sequelize-cli db:seed:all"
  },
  "dependencies": {
    "express": "^4.18.2",
    "sequelize": "^6.31.1",
    "pg": "^8.11.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.0",
    "joi": "^17.9.2",
    "nodemailer": "^6.9.2"
  },
  "devDependencies": {
    "@types/express": "^4.17.17",
    "@types/bcryptjs": "^2.4.2",
    "@types/jsonwebtoken": "^9.0.2",
    "typescript": "^5.0.4",
    "nodemon": "^2.0.22",
    "ts-node": "^10.9.1",
    "jest": "^29.5.0",
    "sequelize-cli": "^6.6.0"
  }
}
EOF

# Mobile App package.json
echo "📱 Creating React Native app configuration..."
cat > mobile/package.json << 'EOF'
{
  "name": "CraveApp",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "android": "react-native run-android",
    "ios": "react-native run-ios",
    "start": "react-native start",
    "test": "jest",
    "lint": "eslint . --ext .js,.jsx,.ts,.tsx",
    "build:android": "cd android && ./gradlew assembleRelease",
    "build:ios": "cd ios && xcodebuild -workspace CraveApp.xcworkspace -scheme CraveApp archive"
  },
  "dependencies": {
    "react": "18.2.0",
    "react-native": "0.72.0",
    "@react-navigation/native": "^6.1.6",
    "@react-navigation/stack": "^6.3.16",
    "@react-navigation/bottom-tabs": "^6.5.7",
    "@reduxjs/toolkit": "^1.9.5",
    "react-redux": "^8.0.7",
    "redux-persist": "^6.0.0",
    "@react-native-async-storage/async-storage": "^1.18.2",
    "@react-native-community/geolocation": "^3.0.6",
    "react-native-vector-icons": "^9.2.0",
    "axios": "^1.4.0",
    "@react-native-firebase/app": "^18.0.0",
    "@react-native-firebase/analytics": "^18.0.0"
  },
  "devDependencies": {
    "@babel/core": "^7.21.8",
    "@babel/preset-env": "^7.21.5",
    "@babel/runtime": "^7.21.5",
    "@react-native/eslint-config": "^0.72.2",
    "@react-native/metro-config": "^0.72.7",
    "@tsconfig/react-native": "^3.0.0",
    "@types/react": "^18.2.6",
    "@types/react-test-renderer": "^18.0.0",
    "babel-jest": "^29.2.1",
    "eslint": "^8.42.0",
    "jest": "^29.2.1",
    "metro-react-native-babel-preset": "0.76.5",
    "prettier": "^2.8.8",
    "react-test-renderer": "18.2.0",
    "typescript": "4.8.4"
  }
}
EOF

# TypeScript configurations
echo "⚙️ Creating TypeScript configurations..."
cat > tsconfig.json << 'EOF'
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
EOF

# Copy TypeScript config to each service
for service in api-gateway auth-service post-service business-service user-service; do
  cp tsconfig.json backend/$service/
done

# Mobile TypeScript config
cat > mobile/tsconfig.json << 'EOF'
{
  "extends": "@tsconfig/react-native/tsconfig.json",
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@/*": ["./*"],
      "@/components/*": ["./components/*"],
      "@/screens/*": ["./screens/*"],
      "@/services/*": ["./services/*"]
    }
  },
  "include": ["src/**/*", "App.tsx"],
  "exclude": ["node_modules"]
}
EOF

# README files
echo "📄 Creating documentation..."
cat > README.md << 'EOF'
# Crave App 🍽️

A location-based social discovery app for local bars and restaurants, combining the visual appeal of Instagram with real-time deal promotion.

## Features

- 📍 **Location-Based Discovery** - Find nearby restaurants and bars automatically
- 📱 **Instagram-Style Feed** - Visual content with stories and engagement features
- 🍺 **Real-Time Deals** - Live happy hours and daily specials
- 🏪 **Business Profiles** - Complete business management system
- 📊 **Analytics Dashboard** - Performance insights for businesses
- 💰 **Monetization Ready** - Promoted posts and premium accounts

## Tech Stack

### Backend
- Node.js + TypeScript
- PostgreSQL + PostGIS (geospatial queries)
- Redis (caching)
- Docker + Kubernetes
- AWS S3 (media storage)

### Mobile App
- React Native + TypeScript
- Redux Toolkit (state management)
- Firebase (analytics, push notifications)
- React Navigation

## Quick Start

1. **Clone and setup:**
```bash
git clone <your-repo>
cd crave-app
npm run setup
```

2. **Start development environment:**
```bash
# Start all services
npm run dev

# Or start individual services
npm run dev:backend  # Backend services
npm run dev:mobile   # React Native app
```

3. **Database setup:**
```bash
# Copy environment file
cp .env.example .env

# Start database
docker-compose -f infrastructure/docker-compose.yml up postgres redis -d

# Run migrations
npm run db:migrate
```

## Project Structure

```
crave-app/
├── mobile/                 # React Native app
├── backend/               # Microservices
│   ├── api-gateway/      # API Gateway & load balancing
│   ├── auth-service/     # Authentication & user management
│   ├── post-service/     # Posts & content management
│   └── business-service/ # Business profiles & management
├── infrastructure/       # Docker & Kubernetes configs
└── shared/              # Shared types & utilities
```

## Development

- `npm run dev` - Start all services
- `npm run test` - Run all tests
- `npm run lint` - Code quality checks
- `npm run build` - Production build

## Deployment

- `npm run docker:up` - Local Docker deployment
- `npm run k8s:deploy` - Kubernetes deployment

## License

MIT License
EOF

# Installation instructions
cat > SETUP.md << 'EOF'
# Crave App Setup Instructions

## Prerequisites

- Node.js 18+
- PostgreSQL 14+ with PostGIS extension
- Redis 7+
- Docker & Docker Compose
- React Native development environment

## Step-by-Step Setup

### 1. Environment Configuration
```bash
# Copy and configure environment variables
cp .env.example .env

# Edit .env with your actual values:
# - Database credentials
# - AWS S3 credentials  
# - API keys (SendGrid, Google Maps, etc.)
```

### 2. Database Setup
```bash
# Start PostgreSQL and Redis with Docker
docker-compose -f infrastructure/docker-compose.yml up postgres redis -d

# Install dependencies
npm run install:all

# Run database migrations
npm run db:migrate
```

### 3. Mobile Development Setup

#### iOS Setup:
```bash
cd mobile/ios
pod install
cd ..
```

#### Android Setup:
- Install Android Studio and SDK
- Create virtual device or connect physical device
- Enable developer options and USB debugging

### 4. Start Development
```bash
# Terminal 1: Start backend services
npm run dev:backend

# Terminal 2: Start React Native
npm run dev:mobile

# Terminal 3: Run mobile app
cd mobile
npm run android  # For Android
npm run ios      # For iOS
```

### 5. Testing
```bash
# Run all tests
npm run test

# Test specific services
npm run test:auth
npm run test:mobile
```

## Troubleshooting

### Common Issues:

1. **Database connection errors**
   - Ensure PostgreSQL is running
   - Check DATABASE_URL in .env file

2. **React Native build errors**
   - Clean build: `cd mobile && npx react-native clean`
   - Reset Metro cache: `npx react-native start --reset-cache`

3. **iOS build issues**
   - Clean build folder in Xcode
   - Re-run `pod install`

4. **Android build issues**
   - Clean gradle: `cd mobile/android && ./gradlew clean`
   - Check Android SDK path

## Production Deployment

See deployment documentation in `/docs/deployment.md`
EOF

# Create basic app files
echo "🚀 Creating basic application files..."

# Mobile App.tsx
cat > mobile/App.tsx << 'EOF'
import React from 'react';
import {NavigationContainer} from '@react-navigation/native';
import {createBottomTabNavigator} from '@react-navigation/bottom-tabs';
import {Provider} from 'react-redux';
import {Text, View} from 'react-native';

// Placeholder store
const store = {
  dispatch: () => {},
  getState: () => ({}),
  subscribe: () => () => {},
  replaceReducer: () => {},
};

const Tab = createBottomTabNavigator();

function HomeScreen() {
  return (
    <View style={{flex: 1, justifyContent: 'center', alignItems: 'center'}}>
      <Text>Crave - Home Screen</Text>
      <Text>Welcome to Crave! 🍽️</Text>
    </View>
  );
}

function SearchScreen() {
  return (
    <View style={{flex: 1, justifyContent: 'center', alignItems: 'center'}}>
      <Text>Search for local deals</Text>
    </View>
  );
}

export default function App() {
  return (
    <Provider store={store}>
      <NavigationContainer>
        <Tab.Navigator>
          <Tab.Screen name="Home" component={HomeScreen} />
          <Tab.Screen name="Search" component={SearchScreen} />
        </Tab.Navigator>
      </NavigationContainer>
    </Provider>
  );
}
EOF

# Basic API Gateway
cat > backend/api-gateway/src/app.ts << 'EOF'
import express from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'OK', service: 'API Gateway' });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'Crave API Gateway',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`🚀 API Gateway running on port ${PORT}`);
});
EOF

# Git configuration
echo "📝 Creating Git configuration..."
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
*/node_modules/

# Production builds
dist/
build/
*.tgz

# Environment files
.env
.env.local
.env.production

# Logs
logs/
*.log
npm-debug.log*

# Database
*.sqlite
*.db

# OS files
.DS_Store
Thumbs.db

# Editor files
.vscode/
.idea/

# Mobile specific
mobile/android/app/build/
mobile/ios/build/
mobile/ios/Pods/

# Docker
docker-compose.override.yml
EOF

# Initialize git repository
git init
git add .
git commit -m "Initial Crave App setup"

echo "✅ Crave App project setup complete!"
echo ""
echo "🎯 Next steps:"
echo "1. Configure environment variables: cp .env.example .env && edit .env"
echo "2. Start services: docker-compose -f infrastructure/docker-compose.yml up -d"
echo "3. Install dependencies: npm run install:all"
echo "4. Start development: npm run dev"
echo ""
echo "📖 See SETUP.md for detailed instructions"
echo "📁 Project created in: $(pwd)"