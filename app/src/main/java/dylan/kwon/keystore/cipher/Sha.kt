package dylan.kwon.keystore.cipher

import android.security.keystore.KeyProperties
import java.security.MessageDigest
import javax.crypto.KeyGenerator

/**
 * SHA-512.
 */
fun sha(string: String): List<ByteArray> {
    val salt = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA512).apply {
        init(32)
    }.generateKey().encoded

    val messageDigest = MessageDigest.getInstance(KeyProperties.DIGEST_SHA512).apply {
        update(string.toByteArray())
        update(salt)
    }
    val hash = messageDigest.digest()

    return listOf(hash, salt)
}