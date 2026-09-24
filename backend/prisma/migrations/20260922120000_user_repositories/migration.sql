-- CreateTable
CREATE TABLE "user_repositories" (
    "userId" TEXT NOT NULL,
    "repositoryId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_repositories_pkey" PRIMARY KEY ("userId","repositoryId")
);

-- CreateIndex
CREATE INDEX "user_repositories_repositoryId_idx" ON "user_repositories"("repositoryId");

-- AddForeignKey
ALTER TABLE "user_repositories" ADD CONSTRAINT "user_repositories_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_repositories" ADD CONSTRAINT "user_repositories_repositoryId_fkey" FOREIGN KEY ("repositoryId") REFERENCES "repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Существующие репозитории привязываются к владельцу по логину GitHub-аккаунта:
-- без этого список у уже зарегистрированных пользователей окажется пустым до
-- первой синхронизации.
INSERT INTO "user_repositories" ("userId", "repositoryId")
SELECT ga."userId", r."id"
FROM "repositories" r
JOIN "github_accounts" ga ON ga."login" = r."owner"
ON CONFLICT DO NOTHING;
