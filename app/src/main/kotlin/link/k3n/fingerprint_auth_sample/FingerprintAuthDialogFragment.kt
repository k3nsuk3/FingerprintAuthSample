package link.k3n.fingerprint_auth_sample

import android.Manifest
import android.app.Dialog
import android.app.KeyguardManager
import android.content.Context.KEYGUARD_SERVICE
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.support.design.widget.FloatingActionButton
import android.support.v4.app.DialogFragment
import android.support.v4.content.res.ResourcesCompat
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat
import android.support.v4.os.CancellationSignal
import android.support.v7.app.AlertDialog
import android.view.View
import android.widget.TextView
import javax.crypto.Cipher

class FingerprintAuthDialogFragment : DialogFragment() {

    interface OnAuthenticationListener {
        fun onSucceeded(cipher: Cipher?)
        fun onFailed()
        fun onError()
        fun onKeyInvalidated()
        fun onPermissionNotGranted()
        fun onScannerNotAvailable()
        fun onNotConfiguredSecureLockScreen()
        fun onNotEnrolledFingerprints()
    }

    var onAuthenticationListener: OnAuthenticationListener? = null

    private val fingerprintManager: FingerprintManagerCompat? by lazy {
        context?.let { FingerprintManagerCompat.from(it) }
    }

    private val keyguardManager: KeyguardManager? by lazy {
        context?.let { it.getSystemService(KEYGUARD_SERVICE) as KeyguardManager }
    }

    private var cryptoObject: FingerprintManagerCompat.CryptoObject? = null
    private var cancellationSignal: CancellationSignal? = null
    private var selfCancelled = false

    private lateinit var description: TextView
    private lateinit var icon: FloatingActionButton
    private lateinit var help: TextView
    private lateinit var dialog: AlertDialog

    private val authenticationCallback = object : FingerprintManagerCompat.AuthenticationCallback() {
        override fun onAuthenticationError(errMsgId: Int, errString: CharSequence?) {
            super.onAuthenticationError(errMsgId, errString)

            // 指紋認証システムのエラーや、CancellationSignalによる認証キャンセル時に呼ばれる
            if (errMsgId == FingerprintManager.FINGERPRINT_ERROR_CANCELED) {
                // 電源ボタンを押した際にも呼ばれるため、その場合はView処理等を行わせないようにする
                return
            }

            if (!selfCancelled) {
                // ユーザによる明示的なキャンセル操作でない場合
                errString?.let { help.text = it } ?: let { help.text = "Authentication Error" }
                icon.backgroundTintList = ColorStateList.valueOf(ResourcesCompat.getColor(resources, R.color.red, null))

                Handler().postDelayed({
                    onAuthenticationListener?.onFailed() ?: onAuthenticationListener?.onError()
                    ?: dismiss()
                }, LONG_DELAY_MILLIS)
            }
        }

        override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()

            // 指紋を読み取れたが、登録されているものではなかった場合
            // これが呼ばれても指紋認証自体は終了しておらず、再度指紋センサに触れるとハンドリングされる
            icon.backgroundTintList = ColorStateList.valueOf(ResourcesCompat.getColor(resources, R.color.red, null))
            help.text = "Authentication Failed"
            Handler().postDelayed({
                resetDialogState()
            }, SHORT_DELAY_MILLIS)
        }

        override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence?) {
            super.onAuthenticationHelp(helpMsgId, helpString)

            // 読み取り不十分などの場合に呼ばれる。helpStringに理由テキストが入る
            // これが呼ばれても指紋認証自体は終了していないため、再度指紋センサに触れるとハンドリングされる
            helpString?.let { help.text = it }
            icon.backgroundTintList = ColorStateList.valueOf(ResourcesCompat.getColor(resources, R.color.red, null))
            Handler().postDelayed({
                resetDialogState()
            }, LONG_DELAY_MILLIS)
        }

        override fun onAuthenticationSucceeded(result: FingerprintManagerCompat.AuthenticationResult?) {
            super.onAuthenticationSucceeded(result)

            // 認証成功時に呼ばれる。FingerprintManager.authenticateにCryptoObjectを渡していた場合、result内にそれが含まれている
            result?.let {
                it.cryptoObject?.let {
                    it.cipher?.let {
                        help.text = "Authentication Succeeded"
                        icon.backgroundTintList = ColorStateList.valueOf(ResourcesCompat.getColor(resources, R.color.light_green, null))
                        icon.setImageDrawable(ResourcesCompat.getDrawable(resources, R.drawable.check, null))

                        Handler().postDelayed({
                            onAuthenticationListener?.onSucceeded(it)
                                    ?: onAuthenticationListener?.onError() ?: dismiss()
                        }, SHORT_DELAY_MILLIS)
                    } ?: let { onAuthenticationListener?.onError() ?: dismiss() }
                } ?: let { onAuthenticationListener?.onError() ?: dismiss() }
            } ?: let { onAuthenticationListener?.onError() ?: dismiss() }
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        return initDialog()
    }

    override fun onResume() {
        super.onResume()
        try {
            context?.let { cryptoObject = KeyStoreUtil.getCryptoObjectForDecryption() }
                    ?: onAuthenticationListener?.onError() ?: dismiss()
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && e is KeyPermanentlyInvalidatedException) {
                onAuthenticationListener?.onKeyInvalidated() ?: dismiss()
            } else {
                throw e
            }
        }

        startAuthentication(cryptoObject)
    }

    override fun onPause() {
        super.onPause()
        stopAuthentication()
    }

    private fun initDialog(): Dialog {
        isCancelable = false
        val view = View.inflate(context, R.layout.dialog_fingerprint_auth, null)
        description = view.findViewById(R.id.description_text)
        icon = view.findViewById(R.id.biometric_icon)
        help = view.findViewById(R.id.biometric_error_text)

        resetDialogState()

        dialog = AlertDialog.Builder(activity!!).run {
            setNegativeButton("Cancel") { _, _ ->
                onAuthenticationListener?.onFailed() ?: dismiss()
            }
        }.setView(view).setCancelable(false).create()

        return dialog
    }

    private fun startAuthentication(cryptoObject: FingerprintManagerCompat.CryptoObject?) {
        if (!canUseFingerprintAuth()) {
            dismiss()
            return
        }

        cryptoObject ?: let {
            onAuthenticationListener?.onError() ?: dismiss()
            return
        }

        cancellationSignal = CancellationSignal()
        selfCancelled = false
        fingerprintManager?.authenticate(cryptoObject, 0, cancellationSignal, authenticationCallback, Handler())
                ?: let {
                    onAuthenticationListener?.onError() ?: dismiss()
                }
    }

    private fun stopAuthentication() {
        cancellationSignal?.let {
            selfCancelled = true
            it.cancel()
            cancellationSignal = null
        } ?: let {
            onAuthenticationListener?.onError()
        }
        dismiss()
    }

    private fun resetDialogState() {
        description.text = "Confirm fingerprint to continue."
        icon.setImageDrawable(ResourcesCompat.getDrawable(resources, R.drawable.fingerprint, null))
        icon.backgroundTintList = ColorStateList.valueOf(ResourcesCompat.getColor(resources, R.color.blue, null))
        help.text = "Touch Sensor"
    }

    private fun canUseFingerprintAuth(): Boolean {
        context?.let {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (it.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                    // 指紋利用の権限が無いため、機能使用不可（アプリインストール時点で許可されているはずなので、到達しないはず…）
                    onAuthenticationListener?.onPermissionNotGranted()
                    return false
                }
            }
        } ?: return false

        fingerprintManager?.let {
            if (it.isHardwareDetected == false) {
                // 指紋ハードウェアがデバイスに搭載されていないため、機能使用不可
                onAuthenticationListener?.onScannerNotAvailable()
                return false
            }
        } ?: return false

        keyguardManager?.let {
            if (it.isKeyguardSecure == false) {
                // Secure Lock Screenが設定されていない
                onAuthenticationListener?.onNotConfiguredSecureLockScreen()
                return false
            }
        } ?: return false

        fingerprintManager?.let {
            if (it.hasEnrolledFingerprints() == false) {
                // 指紋が登録されていない
                onAuthenticationListener?.onNotEnrolledFingerprints()
                return false
            }
        } ?: return false

        return true
    }

    companion object {
        const val LONG_DELAY_MILLIS = 3000L
        const val SHORT_DELAY_MILLIS = 500L

        fun newInstance() = FingerprintAuthDialogFragment()
    }
}