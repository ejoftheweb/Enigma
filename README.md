# Enigma
Enigma is a simplified Java wrapper for the BouncyCastle OpenPGP implementation. It aims greatly to simplify the deployment of OpenPGP-compatible cryptography in working systems.
Enigma works in particular with org.jdom2 xml objects such as Elements, but it also encrypts and/or signs strings and character arrays.
Enigma is suitable for use in most Java applications - so long as the BouncyCastle libraries (which are required dependencies) work, Enigma should work. However, for Android, you need to use the related library Minigma which uses the SpongyCastle libraries because of a naming conflict between BouncyCastle and Android's own internal cryptosystems. The API in each case is identical.


