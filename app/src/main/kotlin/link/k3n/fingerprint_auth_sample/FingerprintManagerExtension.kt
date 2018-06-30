package link.k3n.fingerprint_auth_sample

import android.app.KeyguardManager
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat

/**
 * 指紋センサが搭載され、端末ロックが有効で、既に指紋が登録されているかを元に、指紋認証機能の利用が可能かを返す
 *
 * @param keyguardManager KeyguardManager
 * @return 指紋認証機能の利用が可能ならtrue
 */
fun FingerprintManagerCompat.canUseFingerprintAuth(keyguardManager: KeyguardManager): Boolean {
    return (isHardwareDetected && keyguardManager.isKeyguardSecure && hasEnrolledFingerprints())
}
