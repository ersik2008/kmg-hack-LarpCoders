export class AuditService {
  private readonly entries: Array<Record<string, unknown>> = [];

  record(entry: Record<string, unknown>): void {
    this.entries.push(entry);
  }
}

export const auditLog = new AuditService();
