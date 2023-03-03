export class InvalidCryptoExchangeError extends Error {
  public code: string

  constructor (message = 'Invalid crypto exchange') {
    super(message);
    this.code = InvalidCryptoExchangeError.code;
  }

  static get code (): string {
    return 'ERR_INVALID_CRYPTO_EXCHANGE';
  }
}

