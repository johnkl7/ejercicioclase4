import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher

const val ALGORITHM = "RSA"

fun main() {


    var n = generateKeys()
    var publica = n.first
    var privada = n.second

    var finish = 2


    while(finish == 2) {

        println()
        println("mi clave publica: $publica")
        println("pulsa 1 para encriptar, pulsa 2 para desencriptar")
        var opcion1 = readln().toInt()
        if (opcion1 == 1) {

            println("escribe mensaje para cifrar")
            var mensaje1 = readln().toString()
            println("Clave publica del destinatario")
            var publica2 = readln().toString()
            val c = encrypt(mensaje1, publica2)
            println(c)

        }

        if (opcion1 == 2) {

            println("escribe mensaje cifrado")
            var mensaje2 = readln().toString()
            println(decrypt(mensaje2, privada))
        }
    }

}











fun generateKeys(): Pair<String, String> {
    val keyGen = KeyPairGenerator.getInstance(ALGORITHM).apply {
        initialize(512)
    }

    // Key generation
    val keys = keyGen.genKeyPair()

    // Transformation to String (well encoded)
    val publicKeyString = Base64.getEncoder().encodeToString(keys.public.encoded)
    val privateKeyString = Base64.getEncoder().encodeToString(keys.private.encoded)

    return Pair(publicKeyString, privateKeyString)
}

fun encrypt(message: String, publicKey: String): String {
    // From a String, we obtain the Public Key
    val publicBytes = Base64.getDecoder().decode(publicKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePublic(X509EncodedKeySpec(publicBytes))

    // With the public, we encrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.ENCRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(message.encodeToByteArray())
    return String(Base64.getEncoder().encode(bytes))
}

fun decrypt(encryptedMessage: String, privateKey: String): String {
    // From a String, we obtain the Private Key
    val publicBytes = Base64.getDecoder().decode(privateKey)
    val decodedKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(PKCS8EncodedKeySpec(publicBytes))

    // Knowing the Private Key, we can decrypt the message
    val cipher = Cipher.getInstance(ALGORITHM).apply {
        init(Cipher.DECRYPT_MODE, decodedKey)
    }
    val bytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage))
    return String(bytes)
}

