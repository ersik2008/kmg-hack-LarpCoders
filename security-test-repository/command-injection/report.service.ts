import { exec } from 'child_process';

export class ReportService {
  generateReport(filename: string) {
    // VULNERABLE: Direct concatenation of user input into OS shell command
    exec(`cat /var/reports/${filename}.log`, (error, stdout) => {
      if (error) console.error(error);
      return stdout;
    });
  }
}
