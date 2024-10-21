package dev.kwasi.echoservercomplete.network

import android.util.Log
import com.google.gson.Gson
import dev.kwasi.echoservercomplete.models.ContentModel
import java.io.BufferedReader
import java.io.BufferedWriter
import java.net.Socket
import kotlin.concurrent.thread
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import androidx.test.espresso.base.Default
import dev.kwasi.echoservercomplete.R
import java.nio.charset.StandardCharsets.UTF_8
import javax.crypto.SecretKey

class Client (private val networkMessageInterface: NetworkMessageInterface){
    private lateinit var clientSocket: Socket
    private lateinit var reader: BufferedReader
    private lateinit var writer: BufferedWriter
    var ip:String = ""

    fun ByteArray.toHex() = joinToString(separator = "") { byte -> "%02x".format(byte) }

    fun getFirstNChars(str: String, n:Int) = str.substring(0,n)

    fun hashStrSha256(str: String): String{
        val algorithm = "SHA-256"
        val hashedString = MessageDigest.getInstance(algorithm).digest(str.toByteArray(UTF_8))
        return hashedString.toHex();
    }
    fun generateAESKey(seed: String): SecretKeySpec {
        val first32Chars = getFirstNChars(seed,32)
        val secretKey = SecretKeySpec(first32Chars.toByteArray(), "AES")
        return secretKey
    }
    fun generateIV(seed: String): IvParameterSpec {
        val first16Chars = getFirstNChars(seed, 16)
        return IvParameterSpec(first16Chars.toByteArray())
    }

    fun encryptMessage(plaintext: String, aesKey: SecretKey, aesIv: IvParameterSpec):String{
        val plainTextByteArr = plaintext.toByteArray()

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv)

        val encrypt = cipher.doFinal(plainTextByteArr)
        return Base64.encodeToString(encrypt, Base64.DEFAULT)
       // return Base64.Default.encode(encrypt)
    }

    fun decryptMessage(encryptedText: String, aesKey:SecretKey, aesIv: IvParameterSpec):String{
        //val textToDecrypt = Base64.decode(base64, Base64.DEFAULT)
        //val textToDecrypt = Base64.Default.decode(encryptedText)
        val textToDecrypt = Base64.decode(encryptedText, Base64.DEFAULT)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

        cipher.init(Cipher.DECRYPT_MODE, aesKey,aesIv)

        val decrypt = cipher.doFinal(textToDecrypt)
        return String(decrypt)

    }

    fun sendMessage(content: ContentModel) {
        thread {
            if (!clientSocket.isConnected) {
                throw Exception("We aren't currently connected to the server!")
            }
            val contentAsStr: String = Gson().toJson(content)
            writer.write("$contentAsStr\n")
            writer.flush()
        }
    }

    private fun incomingMsg(aesKey: SecretKeySpec, aesIv: IvParameterSpec) {
        while (true) {
            val serverResponse = reader.readLine()
            if (serverResponse != null) {
                val serverContent = Gson().fromJson(serverResponse, ContentModel::class.java)

                // Decrypt the incoming message
                val decryptedMessage = decryptMessage(serverContent.message, aesKey, aesIv)
                val decryptedContent = ContentModel(decryptedMessage, serverContent.senderIp)

                networkMessageInterface.onContent(decryptedContent)
            }
        }
    }


    fun close(){
            clientSocket.close()

    }
    init {
        thread {
            clientSocket = Socket("192.168.49.1", Server.PORT)
            reader = clientSocket.inputStream.bufferedReader()
            writer = clientSocket.outputStream.bufferedWriter()
            ip = clientSocket.inetAddress.hostAddress!!


            //Challenge-Response
            try{

                //Send initial "I am here" message
                val hereMsg = ContentModel("I am here", ip)
                sendMessage(hereMsg)

                //Listen for server
                val challengeResponse = reader.readLine()
                if (challengeResponse != null) {
                    val challengeContent = Gson().fromJson(challengeResponse, ContentModel::class.java)
                    val challenge = challengeContent.message
                    networkMessageInterface.onContent(challengeContent)

                //Generate AES key and IV using hashed student ID
                    val strongSeed = hashStrSha256("816117992")
                    val aesKey = generateAESKey(strongSeed)
                    val aesIv = generateIV(strongSeed)

                //Encrypt the challenge response and send back a response
                    val encryptedResponse = encryptMessage(challenge, aesKey, aesIv)
                    val responseContent = ContentModel(encryptedResponse, "816117992")
                    sendMessage(responseContent)

                    //networkMessageInterface.onContent(challengeContent)

                    incomingMsg(aesKey,aesIv)
            }



        }finally{
            close()
        }
    }
    }
}