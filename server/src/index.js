// © 2026 Abubakri Faaruq Adebowale (IbnAbubakri). All rights reserved.
// Faruqsuzay@gmail.com | +2349061345507

import app from './app.js';
import env from './config/env.js';
import logger from './utils/logger.js';
import { migrate } from './db/index.js';

app.listen(env.PORT, async () => {
  try {
    await migrate();
    try {
      const { default: seed } = await import('./seed.js');
      await seed();
    } catch (err) {
      if (err?.code !== 'ERR_MODULE_NOT_FOUND') throw err;
    }
    logger.info(`Server running on http://localhost:${env.PORT} [${env.NODE_ENV}]`);
  } catch (err) {
    logger.error({ err: err.message }, 'Startup failed');
    process.exit(1);
  }
});