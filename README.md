# Flight Movements Portal (Render-ready)

## Deploy to Render (no local install)
1) Put this code on GitHub (upload repo).
2) Create Render Web Service:
   - Build: `npm run build`
   - Start: `node dist/server/index.js`
   - Disk: 1 GB at `/opt/render/project/src/uploads`
   - Env:
     - NODE_ENV=production
     - JWT_SECRET=replace-with-long-random
     - UPLOAD_DIR=/opt/render/project/src/uploads
     - DATABASE_URL=file:/opt/render/project/src/server/prisma/dev.db
3) After first deploy, open Render Shell:
   - `npx prisma migrate deploy`
   - Create admin user with the one-liner from the chat.