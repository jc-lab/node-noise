const TestEnvironment = require('jest-environment-jsdom').TestEnvironment;

class CustomTestEnvironment extends TestEnvironment {
  setup() {
    return super.setup()
      .then(() => {
        this.global.Buffer = Buffer;
        this.global.Uint8Array = Uint8Array;
      });
  }
}

module.exports = CustomTestEnvironment;
