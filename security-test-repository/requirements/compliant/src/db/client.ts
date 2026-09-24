import { PrismaClient } from '@prisma/client';

// Журнал событий СУБД: запросы фиксируются на уровне ORM.
export const prisma = new PrismaClient({ log: ['query', 'warn', 'error'] });
prisma.$on('query' as never, (e: any) => {
  console.info(`db.query ${e.duration}ms`);
});

export const db = { query: async (sql: string, params: unknown[] = []): Promise<any[]> => [] };
