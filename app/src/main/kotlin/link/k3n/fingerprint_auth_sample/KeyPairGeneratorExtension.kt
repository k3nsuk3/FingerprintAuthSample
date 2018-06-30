package link.k3n.fingerprint_auth_sample

import android.app.KeyguardManager
import android.content.Context
import android.content.Context.KEYGUARD_SERVICE
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.util.*
import javax.security.auth.x500.X500Principal

/**
 * 暗号化・復号に用いるRSA鍵ペアを作成し、KeyStoreに保存する
 *
 * @param context Context
 */
fun KeyPairGenerator.createKey(context: Context) {
    // Android Mを境にKeyStore鍵生成処理の手順が改善されているため、以下で切り替える
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        initialize(createKeyGenParameterSpec(FingerprintManagerCompat.from(context).canUseFingerprintAuth(context.getSystemService(KEYGUARD_SERVICE) as KeyguardManager)))
        genKeyPair()
    } else {
        initialize(createKeyPairGeneratorSpec(context))
        genKeyPair()
    }
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

    KeyPairGeneratorSpec.Builder(context).run {
        setAlias(keyAlias)
        setSubject(X500Principal("CN=$keyAlias"))
        setSerialNumber(BigInteger.valueOf(1000000))
        setStartDate(start.time)
        setEndDate(end.time)
        return build()
    }
}

/**
 * M以上のOSで用いるKeyGenParameterSpecを構築する
 *
 * userAuthenticationRequiredは既に指紋が登録されている状態でないと利用できないため、パラメータで有効・無効を切り替えるよう実装
 *
 * @param requiredUserAuthentication 鍵の利用にユーザ認証を必要とするか。指紋認証が利用可能な状態でないと、この機能を用いることはできない
 * @return KeyGenParameterSpec
 */
@RequiresApi(api = Build.VERSION_CODES.M)
private fun createKeyGenParameterSpec(requiredUserAuthentication: Boolean): KeyGenParameterSpec {
    // userAuthenticationRequiredを用いる場合、復号処理でPrivate Keyを使うたびに指紋認証の操作が必要となる
    // 1回の指紋認証操作で複数の情報（例えばユーザIDとパスワード）を復号したい場合、それら情報をまとめたJSON文字列を作成するなどし、
    // これを暗号化・復号して1回の処理で済むよう実装する必要がある
    KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).run {
        setBlockModes(KeyProperties.BLOCK_MODE_ECB)
        setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        setUserAuthenticationValidityDurationSeconds(-1)
        setUserAuthenticationRequired(requiredUserAuthentication)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && requiredUserAuthentication) {
            // N以降ではsetInvalidatedByBiometricEnrollmentを無効にすることで指紋の追加・削除時も鍵の有効性が保持される
            // ここではtrueにして指紋の追加・削除時も鍵を無効化させる（なお、エミュレータでは鍵が上手く無効化されない場合が見られる）
            // setUserAuthenticationRequiredが有効で、setUserAuthenticationValidityDurationSecondsに正数がセットされていない場合にのみ効力を持つ
            setInvalidatedByBiometricEnrollment(true)
        }

        return build()
    }
}
