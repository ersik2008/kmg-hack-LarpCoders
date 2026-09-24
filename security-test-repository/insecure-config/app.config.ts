export const serverConfig = {
  port: 8080,
  // VULNERABLE: Debug mode enabled in production configuration
  debug: true,
  // VULNERABLE: Wildcard origin with credentials enabled
  cors: {
    origin: '*',
    credentials: true,
  },
  exposeDocs: true,
  disableRateLimiting: true,
};
