import type { Metrics } from './@types/metrics';

export type MetricsRegistry = ReturnType<typeof registerMetrics>

export function registerMetrics (metrics: Metrics) {
  return {
    handshakeSuccesses: metrics.registerCounter(
      'libp2p_noise_xxhandshake_successes_total', {
        help: 'Total count of noise xxHandshakes successes_'
      }),

    handshakeErrors: metrics.registerCounter(
      'libp2p_noise_xxhandshake_error_total', {
        help: 'Total count of noise xxHandshakes errors'
      }),

    encryptedPackets: metrics.registerCounter(
      'libp2p_noise_encrypted_packets_total', {
        help: 'Total count of noise encrypted packets successfully'
      }),

    decryptedPackets: metrics.registerCounter(
      'libp2p_noise_decrypted_packets_total', {
        help: 'Total count of noise decrypted packets'
      }),

    decryptErrors: metrics.registerCounter(
      'libp2p_noise_decrypt_errors_total', {
        help: 'Total count of noise decrypt errors'
      })
  };
}
