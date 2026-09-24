/**
 * Utility to redact sensitive values from objects before logging or returning to clients.
 */
export class SecretRedactor {
  private static readonly patterns: Array<{ regex: RegExp; replacement: string }> = [
    // GitHub tokens
    { regex: /ghp_[a-zA-Z0-9]{36}/g, replacement: 'ghp_***REDACTED***' },
    { regex: /gho_[a-zA-Z0-9]{36}/g, replacement: 'gho_***REDACTED***' },
    { regex: /github_pat_[a-zA-Z0-9_]{82}/g, replacement: 'github_pat_***REDACTED***' },
    
    // Groq API keys  
    { regex: /gsk_[a-zA-Z0-9]{50,}/g, replacement: 'gsk_***REDACTED***' },
    
    // Generic API keys/tokens/passwords
    { regex: /(?:api[_-]?key|token|password|secret|auth)["\s]*[:=]["\s]*[^\s"',}{]+/gi, replacement: '[KEY_REDACTED]' },
    
    // Database URLs
    { regex: /postgresql:\/\/[^@\s]+@/g, replacement: 'postgresql://***@' },
    { regex: /postgres:\/\/[^@\s]+@/g, replacement: 'postgres://***@' },
    
    // JWT tokens
    { regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, replacement: '[JWT_REDACTED]' },

    // AWS keys
    { regex: /AKIA[0-9A-Z]{16}/g, replacement: 'AKIA***REDACTED***' },
  ];

  /**
   * Redact sensitive values from a string.
   */
  static redact(input: string): string {
    let result = input;
    for (const { regex, replacement } of SecretRedactor.patterns) {
      result = result.replace(regex, replacement);
    }
    return result;
  }

  /**
   * Deep-redact sensitive values from any object (recursively).
   */
  static redactObject(obj: any): any {
    if (typeof obj === 'string') return SecretRedactor.redact(obj);
    if (Array.isArray(obj)) return obj.map(item => SecretRedactor.redactObject(item));
    if (obj !== null && typeof obj === 'object') {
      const result: any = {};
      for (const [key, value] of Object.entries(obj)) {
        // Automatically redact values of known sensitive key names
        const sensitiveKeys = ['password', 'secret', 'token', 'accessToken', 'accessTokenHash', 'apiKey', 'authorization'];
        if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk.toLowerCase()))) {
          result[key] = '***REDACTED***';
        } else {
          result[key] = SecretRedactor.redactObject(value);
        }
      }
      return result;
    }
    return obj;
  }
}
