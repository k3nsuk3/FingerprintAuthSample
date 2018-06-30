package link.k3n.fingerprint_auth_sample

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.util.Base64
import java.security.KeyStore
import java.security.KeyStoreException
import javax.crypto.Cipher

/**
 * 文字列をRSAで暗号化し、Base64エンコードした文字列を返す
 *
 * @param source 暗号化する文字列
 * @return 入力された文字列をRSAで暗号化しBase64エンコードした文字列
 * @throws KeyPermanentlyInvalidatedException 鍵が無効化されており、利用できない場合
 * @throws KeyStoreException KeyStore例外
 */
@Throws(KeyPermanentlyInvalidatedException::class, KeyStoreException::class)
fun String.encrypt(source: String): String? {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)

    val publicKey = keyStore.getCertificate(keyAlias).publicKey
    val cipher = Cipher.getInstance(cipherAlgorithm)
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)

    return Base64.encodeToString(cipher.doFinal(source.toByteArray()), Base64.DEFAULT)
}

/**
 * RSAで暗号化しBase64エンコードされた文字列を復号する
 *
 * @param source RSAで暗号化しBase64エンコードされた文字列
 * @param cipher 復号に用いるRSA秘密鍵の復号用途で初期化されたCipherインスタンス
 * @return 復号された文字列
 * @throws KeyPermanentlyInvalidatedException 鍵が無効化されており、利用できない場合
 * @throws KeyStoreException KeyStore例外
 */
@Throws(KeyPermanentlyInvalidatedException::class, KeyStoreException::class)
fun String.decrypt(source: String, cipher: Cipher): String? {
    return String(cipher.doFinal(Base64.decode(source, Base64.DEFAULT)))
}
