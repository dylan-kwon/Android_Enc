package dylan.kwon.keystore.cipher

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac

/**
 * HMAC.
 */
fun hMac(string: String): List<ByteArray> {
    val alias = "hmac_sha_512"
    val provider = "AndroidKeyStore"

    val keyStore = KeyStore.getInstance(provider).apply {
        load(null)
    }
    if (!keyStore.containsAlias(alias)) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_HMAC_SHA512, provider
        )
        val keySpec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).build()

        keyGenerator.apply {
            init(keySpec)
        }.generateKey()
    }
    val secretKey = (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey
    val mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA512).apply {
        init(secretKey)
    }
    return listOf(
        mac.doFinal(string.toByteArray())
    )
}