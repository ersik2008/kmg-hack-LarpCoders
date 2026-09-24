-- CreateEnum
CREATE TYPE "RequirementStatus" AS ENUM ('PASS', 'VIOLATION', 'INSUFFICIENT_EVIDENCE', 'NOT_APPLICABLE');

-- CreateTable
CREATE TABLE "requirement_results" (
    "id" TEXT NOT NULL,
    "requirementId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "requirementText" TEXT NOT NULL,
    "status" "RequirementStatus" NOT NULL,
    "confidence" "Confidence" NOT NULL,
    "summary" TEXT NOT NULL,
    "insufficientReason" TEXT,
    "evidence" JSONB,
    "violations" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "scanId" TEXT NOT NULL,

    CONSTRAINT "requirement_results_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "requirement_results_scanId_requirementId_key" ON "requirement_results"("scanId", "requirementId");

-- AddForeignKey
ALTER TABLE "requirement_results" ADD CONSTRAINT "requirement_results_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
