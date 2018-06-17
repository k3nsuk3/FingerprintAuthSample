package link.k3n.fingerprint_auth_sample

import android.app.KeyguardManager
import android.content.Context
import android.content.Context.KEYGUARD_SERVICE
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.util.Base64
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

object KeyStoreUtil {

    private const val KEY_ALIAS = "KEY_ALIAS"
    // 古いOSだとAESの利用がサポートされていない。バージョン間の差異を考慮しRSAを採用
    private const val CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding"

    /**
     * 文字列をRSAで暗号化し、Base64エンコードした文字列を返す
     *
     * @param source 暗号化する文字列
     * @return 入力された文字列をRSAで暗号化しBase64エンコードした文字列
     * @throws KeyPermanentlyInvalidatedException 鍵が無効化されており、利用できない場合
     * @throws KeyStoreException KeyStore例外
     */
    @Throws(KeyPermanentlyInvalidatedException::class, KeyStoreException::class)
    fun encrypt(source: String): String? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        return Base64.encodeToString(cipher.doFinal(source.toByteArray()), Base64.DEFAULT)
    }

    /**
     * RSAで暗号化しBase64エンコードされた文字列を復号する
     *
     * @param source RSAで暗号化しBase64エンコードされた文字列
     * @param cipher 復号に用いるRSA秘密鍵の復号用途で初期化されたCipherインスタンス
     * @return 復号された平文文字列
     * @throws KeyPermanentlyInvalidatedException 鍵が無効化されており、利用できない場合
     * @throws KeyStoreException KeyStore例外
     */
    @Throws(KeyPermanentlyInvalidatedException::class, KeyStoreException::class)
    fun decrypt(source: String, cipher: Cipher): String? {
        return String(cipher.doFinal(Base64.decode(source, Base64.DEFAULT)))
    }

    /**
     * FingerprintManagerのauthenticateに渡す、Decrypt Mode Cipherの入ったCryptoObjectを取得する
     *
     * @return Decrypt Mode Cipherの入ったCryptoObject
     * @throws KeyPermanentlyInvalidatedException 鍵が無効化されており、利用できない場合
     * @throws KeyStoreException KeyStore例外
     */
    @Throws(KeyPermanentlyInvalidatedException::class, KeyStoreException::class)
    fun getCryptoObjectForDecryption(): FingerprintManagerCompat.CryptoObject? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val privateKey = keyStore.getKey(KEY_ALIAS, null)
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        return FingerprintManagerCompat.CryptoObject(cipher)
    }

    /**
     * 鍵が存在するかを確認する
     *
     * @return 鍵が登録されていない、また鍵の無効化処理等で消去された場合、true
     */
    fun isKeyAvailable(): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return !keyStore.containsAlias(KEY_ALIAS)
    }

    /**
     * 暗号化・復号に用いるRSA鍵ペアを生成し、KeyStoreに保存する
     *
     * @param context Context
     */
    fun createKey(context: Context) {
        // Android Mを境にKeyStore鍵生成処理の手順が改善されているため、以下で切り替える
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            val fingerprintManagerCompat = FingerprintManagerCompat.from(context)
            val keyguardManager = context.getSystemService(KEYGUARD_SERVICE) as KeyguardManager
            val canUseFingerprintAuth = canUseFingerprintAuth(fingerprintManagerCompat, keyguardManager)
            keyPairGenerator.initialize(createKeyGenParameterSpec(canUseFingerprintAuth))
            keyPairGenerator.genKeyPair()
        } else {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore")
            keyPairGenerator.initialize(createKeyPairGeneratorSpec(context))
            keyPairGenerator.genKeyPair()
        }
    }

    /**
     * 指紋センサが搭載され、端末ロックが有効で、既に指紋が登録されているかを元に、指紋認証機能の利用が可能かを返す
     *
     * @param fingerprintManager FingerprintManagerCompat
     * @param keyguardManager KeyguardManager
     * @return 指紋認証機能の利用が可能ならtrue
     */
    private fun canUseFingerprintAuth(fingerprintManager: FingerprintManagerCompat, keyguardManager: KeyguardManager): Boolean {
        return (fingerprintManager.isHardwareDetected && keyguardManager.isKeyguardSecure && fingerprintManager.hasEnrolledFingerprints())
    }

    /**
     * M以前のOSで用いるKeyPairGeneratorSpecを構築する
     *
     * @param context Context
     * @return KeyPairGeneratorSpec
     */
    @Suppress("DEPRECATION")
    private fun createKeyPairGeneratorSpec(context: Context): KeyPairGeneratorSpec {
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        // 鍵生成時に用いる自己署名証明書の有効期限
        end.add(Calendar.YEAR, 100)
        val builder = KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEY_ALIAS)
                .setSubject(X500Principal("CN=$KEY_ALIAS"))
                .setSerialNumber(BigInteger.valueOf(1000000))
                .setStartDate(start.time)
                .setEndDate(end.time)

        return builder.build()
    }

    /**
     * M以上のOSで用いるKeyGenParameterSpecを構築する
     *
     * userAuthenticationRequiredは既に指紋が登録されている状態でないと利用できないため、canUseFingerprintAuthパラメータで有効・無効を切り替えるよう実装
     *
     * @param canUseFingerprintAuth userAuthenticationRequiredを有効にするか
     * @return KeyGenParameterSpec
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private fun createKeyGenParameterSpec(canUseFingerprintAuth: Boolean): KeyGenParameterSpec {
        // userAuthenticationRequiredを用いる場合、復号処理でPrivate Keyを使うたびに指紋認証の操作が必要となる
        // 1回の指紋認証操作で複数の情報（例えばユーザIDとパスワード、など）、それら情報をまとめたJSON文字列を作成するなどし、
        // これを暗号化・復号して1回の処理で済むよう実装する必要がある
        val builder = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setUserAuthenticationValidityDurationSeconds(-1)
                .setUserAuthenticationRequired(canUseFingerprintAuth)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && canUseFingerprintAuth) {
            // N以降ではsetInvalidatedByBiometricEnrollmentを無効にすることで指紋の追加・削除時も鍵の有効性が維持される
            // ここではtrueにして指紋の追加・削除時も鍵を無効化させる
            // setUserAuthenticationRequiredが有効で、setUserAuthenticationValidityDurationSecondsに正数がセットされていない場合にのみ効力を持つ
            builder.setInvalidatedByBiometricEnrollment(true)
        }

        return builder.build()
    }
}