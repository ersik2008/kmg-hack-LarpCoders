import 'dotenv/config';
import { defineConfig } from 'prisma/config';

/**
 * Prisma 7 moved the datasource URL out of schema.prisma.
 *
 * Without this file `prisma migrate deploy` / `prisma migrate dev` fail with
 * "The datasource.url property is required in your Prisma config file", so the
 * schema could not be applied to a fresh database at all.
 *
 * The runtime client does not use this file — it gets its connection through
 * PrismaPg in PrismaService — this is for the Prisma CLI only.
 */
export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    // Read lazily from the process environment rather than via prisma's env()
    // helper: `prisma generate` runs at image build time, where DATABASE_URL is
    // not set, and env() throws there. Migration commands run at start-up, where
    // the variable is always present.
    url: process.env.DATABASE_URL ?? '',
  },
});
