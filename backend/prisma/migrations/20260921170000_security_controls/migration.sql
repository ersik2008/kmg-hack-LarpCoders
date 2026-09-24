-- CreateEnum
CREATE TYPE "ControlStatus" AS ENUM ('IMPLEMENTED', 'PARTIAL', 'MISSING', 'NOT_APPLICABLE', 'UNKNOWN');

-- CreateTable
CREATE TABLE "security_controls" (
    "id" TEXT NOT NULL,
    "control" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "status" "ControlStatus" NOT NULL,
    "confidence" "Confidence" NOT NULL,
    "summary" TEXT NOT NULL,
    "risk" TEXT,
    "recommendation" TEXT,
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "scanId" TEXT NOT NULL,

    CONSTRAINT "security_controls_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "security_controls_scanId_control_key" ON "security_controls"("scanId", "control");

-- AddForeignKey
ALTER TABLE "security_controls" ADD CONSTRAINT "security_controls_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
