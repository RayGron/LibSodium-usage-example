#include <QCoreApplication>
#include <string>
#include <sodium.h>
#include <iostream>

using namespace std;

string byteToHexString(vector<unsigned char> data)
{
    int psize = data.size() * 2 + 1;
    vector<char> p(psize);
    sodium_bin2hex(p.data(), psize, data.data(), data.size());
    string s(p.begin(), p.end());
    return s;
}
string byteToHexString(string &data)
{
    vector<unsigned char> v(data.begin(), data.end());
    return byteToHexString(v);
}

string hexStringToByte(string data)
{
    vector<unsigned char> p;
    p.resize(data.length() / 2 + 1);
    const char *end;
    size_t size;
    int r = sodium_hex2bin(p.data(), p.size(), data.c_str(), data.length(), NULL, &size, &end);
    string res;
    if (r == 0)
    {
        res = string(p.begin(), p.end());
        res.resize(res.size() - 1);
    }
    return res;
}

void keygen(string &secKey, string &pubKey)
{
    vector<unsigned char> sk(crypto_sign_SECRETKEYBYTES);
    vector<unsigned char> pk(crypto_sign_PUBLICKEYBYTES);
    crypto_sign_keypair(pk.data(), sk.data());
    secKey = string(sk.begin(), sk.end());
    pubKey = string(pk.begin(), pk.end());
}

string encrypt(string msg, string &public_key_receiver, string &secret_key_sender)
{
    unsigned long long enc_size = crypto_box_MACBYTES + msg.length();

    vector<unsigned char> pkr(public_key_receiver.begin(), public_key_receiver.end());
    vector<unsigned char> sks(secret_key_sender.begin(), secret_key_sender.end());

    vector<unsigned char> xsks(crypto_scalarmult_curve25519_BYTES);
    crypto_sign_ed25519_sk_to_curve25519(xsks.data(), sks.data());

    vector<unsigned char> xpkr(crypto_scalarmult_curve25519_BYTES);
    crypto_sign_ed25519_pk_to_curve25519(xpkr.data(), pkr.data());

    vector<unsigned char> enc_msg(enc_size);
    vector<unsigned char> dec_msg(msg.begin(), msg.end());
    vector<unsigned char> nonce;
    nonce.resize(crypto_box_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    int r = crypto_box_easy(enc_msg.data(), dec_msg.data(), dec_msg.size(), nonce.data(), xpkr.data(),
                            xsks.data());
    string res;
    if (r == 0)
    {
        res = string(enc_msg.begin(), enc_msg.end());
        res.insert(res.begin(), nonce.begin(), nonce.end());
    }
    return res;
}

string decrypt(string msg, string &secret_key_receiver, string &public_key_sender)
{
    string s_nonce = msg.substr(0, crypto_box_NONCEBYTES);
    msg.erase(0, crypto_box_NONCEBYTES);
    vector<unsigned char> nonce(s_nonce.begin(), s_nonce.end());

    vector<unsigned char> skr(secret_key_receiver.begin(), secret_key_receiver.end());
    vector<unsigned char> pks(public_key_sender.begin(), public_key_sender.end());

    vector<unsigned char> enc_msg(msg.begin(), msg.end());
    vector<unsigned char> dec_msg(enc_msg.size() - crypto_box_MACBYTES);

    vector<unsigned char> xskr(crypto_scalarmult_curve25519_BYTES);
    crypto_sign_ed25519_sk_to_curve25519(xskr.data(), skr.data());

    vector<unsigned char> xpks(crypto_scalarmult_curve25519_BYTES);
    crypto_sign_ed25519_pk_to_curve25519(xpks.data(), pks.data());

    int r = crypto_box_open_easy(dec_msg.data(), enc_msg.data(), enc_msg.size(), nonce.data(), xpks.data(),
                                 xskr.data());
    string res;
    if (r == 0)
    {
        res = string(dec_msg.begin(), dec_msg.end());
    }
    return res;
}

string encryptSym(string msg, string &secret_key)
{
    unsigned long long enc_size = crypto_secretbox_MACBYTES + msg.length();

    vector<unsigned char> sk(secret_key.begin(), secret_key.end());

    vector<unsigned char> enc_msg(enc_size);
    vector<unsigned char> dec_msg(msg.begin(), msg.end());
    vector<unsigned char> nonce;
    nonce.resize(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    int r = crypto_secretbox_easy(enc_msg.data(), dec_msg.data(), dec_msg.size(), nonce.data(), sk.data());
    string res;
    if (r == 0)
    {
        res = string(enc_msg.begin(), enc_msg.end());
        res.insert(res.begin(), nonce.begin(), nonce.end());
    }
    return res;
}

string decryptSym(string msg, string &secret_key)
{
    string s_nonce = msg.substr(0, crypto_secretbox_NONCEBYTES);
    msg.erase(0, crypto_secretbox_NONCEBYTES);
    vector<unsigned char> nonce(s_nonce.begin(), s_nonce.end());

    vector<unsigned char> sk(secret_key.begin(), secret_key.end());
    vector<unsigned char> enc_msg(msg.begin(), msg.end());
    vector<unsigned char> dec_msg(enc_msg.size() - crypto_secretbox_MACBYTES);

    int r =
        crypto_secretbox_open_easy(dec_msg.data(), enc_msg.data(), enc_msg.size(), nonce.data(), sk.data());
    string res;
    if (r == 0)
    {
        res = string(dec_msg.begin(), dec_msg.end());
    }
    return res;
}

string sign(string msg, string &secret_key)
{
    vector<unsigned char> sk(secret_key.begin(), secret_key.end());
    vector<unsigned char> vmsg(msg.begin(), msg.end());
    vector<unsigned char> vsig(crypto_sign_BYTES);
    crypto_sign_detached(vsig.data(), NULL, vmsg.data(), vmsg.size(), sk.data());
    string sig(vsig.begin(), vsig.end());
    return sig;
}

bool verify(string msg, string sig, string &public_key)
{
    vector<unsigned char> pk(public_key.begin(), public_key.end());
    vector<unsigned char> vmsg(msg.begin(), msg.end());
    vector<unsigned char> vsig(sig.begin(), sig.end());
    if (crypto_sign_verify_detached(vsig.data(), vmsg.data(), vmsg.size(), pk.data()) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    //    vector<unsigned char> msgBuf(64);
    //    randombytes(msgBuf.data(), msgBuf.size());
    //    std::string msg(msgBuf.begin(), msgBuf.end());
    std::string msg("Hello World!!!");
    if (sodium_init() == 0)
    {

        string u1pk, u1sk;
        string u2pk, u2sk;

        cout << "Hex/Bin test:" << endl;
        cout << "Msg: " << msg << endl;
        string t1 = byteToHexString(msg);
        cout << "Hex: " << t1 << endl;
        string t2 = hexStringToByte(t1);
        cout << "Bin: " << t2 << endl;

        keygen(u1sk, u1pk);
        cout << endl << "U1 public key: " << endl << byteToHexString(u1pk) << endl;
        cout << "U1 private key: " << endl << byteToHexString(u1sk) << endl;
        keygen(u2sk, u2pk);
        cout << "U2 public key: " << endl << byteToHexString(u2pk) << endl;
        cout << "U2 private key: " << endl << byteToHexString(u2sk) << endl;

        cout << endl << "Message: " << endl << msg << endl;
        string encrypted_message = encrypt(msg, u2pk, u1sk);
        cout << "Encrypted message: " << endl << byteToHexString(encrypted_message) << endl;
        string decrypted_message = decrypt(encrypted_message, u2sk, u1pk);
        cout << "Decrypted message: " << endl << decrypted_message << endl;

        cout << endl << "Signature test: " << endl;
        cout << "Message: " << endl << msg << endl;
        string signature = sign(msg, u2sk);
        cout << "Signature (u2): " << endl << byteToHexString(signature) << endl;
        cout << "Verification (u1): " << verify(msg, signature, u1pk) << endl;
        cout << "Verification (u2): " << verify(msg, signature, u2pk) << endl;

        cout << endl << "Self encryption test: " << endl;
        cout << "Message: " << endl << msg << endl;
        string encrypted_message_self = encrypt(msg, u1pk, u1sk);
        cout << "Encrypted message: " << endl << byteToHexString(encrypted_message_self) << endl;
        string decrypted_message_self = decrypt(encrypted_message_self, u1sk, u1pk);
        cout << "Decrypted message: " << endl << decrypted_message_self << endl;

        cout << endl << "Symmetric encryption test: " << endl;
        vector<unsigned char> sk(crypto_secretbox_KEYBYTES);
        crypto_secretbox_keygen(sk.data());
        string sks(sk.begin(), sk.end());
        cout << "Message: " << endl << msg << endl;
        string encrypted_message_sym = encryptSym(msg, sks);
        cout << "Encrypted message: " << endl << byteToHexString(encrypted_message_sym) << endl;
        string decrypted_message_sym = decryptSym(encrypted_message_sym, sks);
        cout << "Decrypted message: " << endl << decrypted_message_sym << endl;
    }
    else
    {
        std::cout << "sodium init error" << std::endl;
    }
    return a.exec();
}
