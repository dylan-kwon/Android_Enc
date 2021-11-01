package dylan.kwon.keystore.cipher

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES256.
 */
fun aes(string: String): List<ByteArray> {
    val alias = "aes_256"
    val provider = "AndroidKeyStore"
    val transformation = arrayOf(
        KeyProperties.KEY_ALGORITHM_AES,
        KeyProperties.BLOCK_MODE_CBC,
        KeyProperties.ENCRYPTION_PADDING_PKCS7
    ).joinToString("/")

    val keyStore = KeyStore.getInstance(provider).apply {
        load(null)
    }
    if (!keyStore.containsAlias(alias)) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, provider
        )
        val keySpec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .build()

        keyGenerator.apply {
            init(keySpec)
        }.generateKey()
    }
    val secretKey = (keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry).secretKey

    val encCipher = Cipher.getInstance(transformation).apply {
        init(Cipher.ENCRYPT_MODE, secretKey)
    }
    val enc = encCipher.doFinal(string.toByteArray())

    val decCipher = Cipher.getInstance(transformation).apply {
        init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(encCipher.iv))
    }
    val dec = decCipher.doFinal(enc)

    return listOf(enc, dec)
}
