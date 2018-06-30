package link.k3n.fingerprint_auth_sample

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import java.security.KeyStore
import java.security.KeyStore.getInstance
import java.security.KeyStoreException
import javax.crypto.Cipher

val keyAlias: String
    get() {
        return "KEY_ALIAS"
    }

val cipherAlgorithm: String
    get() {
        // 古いOSだとAESの利用がサポートされていない。バージョン間の差異を考慮しRSAを採用
        return "RSA/ECB/PKCS1Padding"
    }

/**
 * FingerprintManagerのauthenticateに渡す、DecryptMode Cipherの入ったCryptoObjectを取得する
 *
 * @return DecryptMode Cipherの入ったCryptoObject
 * @throws KeyPermanentlyInvalidatedException 鍵が無効化されており、利用できない場合
 * @throws KeyStoreException KeyStore例外
 */
@Throws(KeyPermanentlyInvalidatedException::class, KeyStoreException::class)
fun KeyStore.getCryptoObjectForDecryption(): FingerprintManagerCompat.CryptoObject? {
    getInstance("AndroidKeyStore")
    load(null)

    val privateKey = getKey(keyAlias, null)
    val cipher = Cipher.getInstance(cipherAlgorithm)
    cipher.init(Cipher.DECRYPT_MODE, privateKey)

    return FingerprintManagerCompat.CryptoObject(cipher)
}
