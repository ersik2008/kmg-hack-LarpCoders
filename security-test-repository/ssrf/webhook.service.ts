export class WebhookService {
  async dispatchEvent(targetUrl: string, payload: any) {
    // VULNERABLE: Direct HTTP request to user-controlled URL without allowlist or internal IP checks
    const response = await fetch(targetUrl, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return response.json();
  }
}
