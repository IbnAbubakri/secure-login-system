import app from '../server/src/app.js';
import { migrate } from '../server/src/db/index.js';

let ready = null;

export default async function handler(req, res) {
  if (!ready) {
    ready = migrate().catch((err) => {
      ready = null;
      throw err;
    });
  }
  await ready;
  return app(req, res);
}