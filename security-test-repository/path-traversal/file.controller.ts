import * as fs from 'fs';
import * as path from 'path';

export class FileController {
  downloadFile(fileName: string) {
    // VULNERABLE: Direct path concatenation allowing directory traversal (../../etc/passwd)
    const filePath = path.join('/var/uploads/', fileName);
    return fs.readFileSync(filePath, 'utf8');
  }
}
