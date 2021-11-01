package dylan.kwon.keystore

import android.os.Bundle
import android.security.keystore.KeyProperties
import androidx.appcompat.app.AppCompatActivity
import dylan.kwon.keystore.databinding.ActivityMainBinding
import dylan.kwon.keystore.cipher.aes
import dylan.kwon.keystore.cipher.hMac
import dylan.kwon.keystore.cipher.rsa
import dylan.kwon.keystore.cipher.sha

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)

        aes("zz")
        rsa("zz")
        hMac("zz")
        sha("zz")

    }

}