-- AlterTable
ALTER TABLE "repositories" ADD COLUMN     "pushedAt" TIMESTAMP(3),
                           ADD COLUMN     "stars" INTEGER NOT NULL DEFAULT 0,
                           ADD COLUMN     "openIssues" INTEGER NOT NULL DEFAULT 0;
