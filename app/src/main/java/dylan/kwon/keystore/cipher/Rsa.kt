package dylan.kwon.keystore.cipher

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher

/**
 * RSA.
 */
fun rsa(string: String): List<ByteArray> {
    val alias = "rsa_512"
    val provider = "AndroidKeyStore"
    val transformation = arrayOf(
        KeyProperties.KEY_ALGORITHM_RSA,
        KeyProperties.BLOCK_MODE_ECB,
        KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
    ).joinToString("/")

    val keyStore = KeyStore.getInstance(provider).apply {
        load(null)
    }
    if (!keyStore.containsAlias(alias)) {
        val keyGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, provider
        )
        val keySpec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setKeySize(2048)
            .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .build()

        keyGenerator.apply {
            initialize(keySpec)
        }.generateKeyPair()
    }
    val keyEntry = (keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry)

    val privateKey = keyEntry.privateKey
    val publicKey = keyEntry.certificate.publicKey

    val encCipher = Cipher.getInstance(transformation).apply {
        init(Cipher.ENCRYPT_MODE, publicKey)
    }
    val enc = encCipher.doFinal(string.toByteArray())

    val decCipher = Cipher.getInstance(transformation).apply {
        init(Cipher.DECRYPT_MODE, privateKey)
    }
    val dec = decCipher.doFinal(enc)

    return listOf(enc, dec)
}
