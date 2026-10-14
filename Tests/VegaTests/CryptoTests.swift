#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Testing
import VegaCrypto
import VegaTLS

private func hex(_ bytes: [UInt8]) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    for b in bytes {
        out.append(digits[Int(b >> 4)])
        out.append(digits[Int(b & 15)])
    }
    return String(decoding: out, as: UTF8.self)
}

private func bytes(_ hex: String) -> [UInt8] {
    let h = Array(hex.utf8.filter { $0 != 32 && $0 != 10 })
    func v(_ c: UInt8) -> UInt8 { c <= 57 ? c - 48 : (c | 0x20) - 87 }
    return stride(from: 0, to: h.count, by: 2).map { v(h[$0]) << 4 | v(h[$0 + 1]) }
}

/// base64url without padding, as JOSE writes it.
private func b64url(_ s: String) -> [UInt8] {
    var out = [UInt8](), acc: UInt32 = 0, bits = 0
    for c in s.utf8 {
        let v: UInt32
        switch c {
        case 65...90: v = UInt32(c - 65)
        case 97...122: v = UInt32(c - 71)
        case 48...57: v = UInt32(c + 4)
        case 45: v = 62
        case 95: v = 63
        default: continue
        }
        acc = acc << 6 | v
        bits += 6
        if bits >= 8 {
            bits -= 8
            out.append(UInt8(truncatingIfNeeded: acc >> UInt32(bits)))
        }
    }
    return out
}

private let jwsPayload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

/// RFC 7515 A.2's RSA key, written as PKCS #1 from its JWK.
private let rfc7515RSAKey = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd/wWJcyQoTbji9k0
    l8W26mPddxHmfHQp+Vaw+4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL+yRT+SFd2lZS+pC
    gNMsD1W/YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb/7OMg0LOL+bSf63kpaSHSX
    ndS5z5rexMdbBYUsLA9e+KXBdQOS+UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uD
    Zlxvb3qCo5ZwKh9kG4LT6/I5IhlJH7aGhyxXFvUK+DWNmoudF8NAco9/h9iaGNj8
    q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQIDAQABAoIBABKucaRpzQorw35S
    bEUAVx8dYXUdZOlJcHtiWQ+dC6V8ljxAHj/PLyzTveyI5QO/xkObCyjIL303l2cf
    UhPu2MFaJdjVzqACXuOrLot/eSFvxjvqVidTtAZExqFRJ9mylUVAoLvhowVWmC1O
    n95fZCXxTUtxNEG1Xcc7m0rtzJKs45J+N/V9DP1edYH6USyPSWGp6wuA+KgHRnKK
    Vf9GRx80JQY7nVNkL17eHoTWEwga+lwi0FEoW9Y7lDtWXYmKBWhUE+U8PGxlJf8f
    40493HDw1WRQ/aSLoS4QTp3rn7gYgeHEvfJdkkf0UMhlknlo53M09EFPdadQ4TlU
    bjqKc50CgYEA4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH/5IB3jw3bcxGn6QLvnE
    tfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw/Py5PJdTJNPY8cQn7ouZ2KKDcmnPG
    BY5t7yLc1QlQ5xHdwW1VhvKn+nXqhJTBgIPgtldC+KDV5z+y2XDwGUcCgYEAuQPE
    fgmVtjL0Uyyx88GZFF1fOunH3+7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYs
    p1ZSe7zFYHj7C6ul7TjeLQeZD/YwD66t62wDmpe/HlB+TnBA+njbglfIsRLtXlnD
    zQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdcCgYAHAp9XcCSrn8wVkMVkKdb7
    DOX4IKjzdahm+ctDAJN4O/y7OW5FKebvUjdAIt2GuoTZ71iTG+7F0F+lP88jtjP4
    U4qe7VHoewl4MKOfXZKTe+YCS1XbNvfgwJ3Ltyl1OH9hWvu2yza7q+d5PCsDzqtm
    27kxuvULVeya+TEdAB1ijQKBgQCH/3r6YrVH/uCWGy6bzV1nGNOdjKc9tmkfOJmN
    54dxdixdpozCQ6U4OxZrsj3FcOhHBsqAHvX2uuYjagqvo3cOj1TRqNocX40omfCC
    Mx3bD1yPPf/6TI2XECva/ggqEY2mYzmIiA5LVVmc5nrybr+lssFKneeyxN2Wq93S
    0iJMdQKBgCGHewxzoa1r8ZMD0LETNrToK423K377UCYqXfg5XMclbrjPbEC3YI1Z
    NqMtuhdBJqUnBi6tjKMF+34Xf0CUN8ncuXGO2CAYvO8PdyCixHX52ybaDjy1FtCE
    6yUXjoKNXKvUm7MWGsAYH6f4IegOetN5NvmUMFStCSkh7ixZLkN1
    -----END RSA PRIVATE KEY-----
    """

@Suite("Crypto")
struct CryptoTests {
    // MARK: Hashes, HMAC, KDFs

    @Test func hashes() throws {
        let abc = Array("abc".utf8)
        #expect(hex(Hash.sha256(abc)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(hex(Hash.sha384(abc))
                == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        #expect(hex(Hash.sha512(abc))
                == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
        #expect(hex(Hash.sha256([])) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        var h = try Hash(.sha256)
        h.update(Array("a".utf8))
        let copy = try h.copy()
        h.update(Array("bc".utf8))
        #expect(h.snapshot() == Hash.sha256(abc))
        h.update(Array("d".utf8))
        #expect(h.finalize() == Hash.sha256(Array("abcd".utf8)))
        // Final starts over.
        h.update(abc)
        #expect(h.finalize() == Hash.sha256(abc))
        #expect(copy.snapshot() == Hash.sha256(Array("a".utf8)))
    }

    /// RFC 4231 test cases 1, 2 and 6.
    @Test func hmac() throws {
        let key1 = [UInt8](repeating: 0x0b, count: 20), data1 = Array("Hi There".utf8)
        #expect(hex(HMAC.authenticationCode(.sha256, key: key1, data: data1))
                == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        #expect(hex(HMAC.authenticationCode(.sha384, key: key1, data: data1))
                == "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")
        #expect(hex(HMAC.authenticationCode(.sha512, key: key1, data: data1))
                == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854")

        let jefe = try HMAC(.sha512, key: Array("Jefe".utf8))
        let data2 = Array("what do ya want for nothing?".utf8)
        let mac = jefe.authenticationCode(for: data2)
        #expect(hex(mac)
                == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")
        #expect(jefe.authenticationCode(for: data2) == mac) // the keyed state isn't used up
        #expect(jefe.isValid(mac, for: data2))
        var bad = mac
        bad[63] ^= 1
        #expect(!jefe.isValid(bad, for: data2))
        #expect(!jefe.isValid(Array(mac.prefix(32)), for: data2))
        #expect(hex(try HMAC(.sha384, key: Array("Jefe".utf8)).authenticationCode(for: data2))
                == "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")

        #expect(hex(try HMAC(.sha256, key: [UInt8](repeating: 0xaa, count: 131))
            .authenticationCode(for: Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8)))
                == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        // An empty key and message are fine.
        #expect(try HMAC(.sha256, key: []).authenticationCode(for: []) == HMAC.authenticationCode(.sha256, key: [], data: []))
    }

    @Test func constantTime() {
        #expect(ConstantTime.equals([1, 2, 3], [1, 2, 3]))
        #expect(!ConstantTime.equals([1, 2, 3], [1, 2, 4]))
        #expect(!ConstantTime.equals([1, 2, 3], [1, 2]))
        #expect(ConstantTime.equals([], []))
    }

    @Test func pbkdf2() throws {
        let password = Array("password".utf8), salt = Array("salt".utf8)
        #expect(hex(try PBKDF2.deriveKey(.sha256, password: password, salt: salt, iterations: 1))
                == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        #expect(hex(try PBKDF2.deriveKey(.sha256, password: password, salt: salt, iterations: 4096))
                == "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        #expect(try PBKDF2.deriveKey(.sha512, password: password, salt: salt, iterations: 2).count == 64)
        #expect(throws: CryptoError.self) { try PBKDF2.deriveKey(password: password, salt: salt, iterations: 0) }
    }

    /// RFC 5869 test cases 1 and 3.
    @Test func hkdf() throws {
        let ikm = [UInt8](repeating: 0x0b, count: 22)
        let prk = HKDF.extract(.sha256, salt: bytes("000102030405060708090a0b0c"), inputKeyMaterial: ikm)
        #expect(hex(prk) == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        #expect(hex(try HKDF.expand(.sha256, pseudoRandomKey: prk, info: bytes("f0f1f2f3f4f5f6f7f8f9"), length: 42))
                == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

        let prk3 = HKDF.extract(.sha256, salt: [], inputKeyMaterial: ikm)
        #expect(hex(prk3) == "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        #expect(hex(try HKDF.deriveKey(.sha256, inputKeyMaterial: ikm, length: 42))
                == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        #expect(throws: CryptoError.self) { try HKDF.expand(.sha256, pseudoRandomKey: prk, info: [], length: 255 * 32 + 1) }
    }

    // MARK: AEAD

    /// RFC 8439 2.8.2.
    @Test func chacha20Poly1305() throws {
        let key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = bytes("070000004041424344454647")
        let aad = bytes("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let aead = try AEAD(.chacha20Poly1305, key: key)
        let sealed = try aead.seal(nonce: nonce, aad: aad, plaintext: plaintext)
        #expect(hex(sealed) == """
            d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b\
            1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
            3ff4def08e4b7a9de576d26586cec64b6116\
            1ae10b594f09e26a7e902ecbd0600691
            """)
        #expect(try aead.open(nonce: nonce, aad: aad, ciphertext: sealed) == plaintext)
        // Again on the same context: the key stays bound.
        #expect(try aead.seal(nonce: nonce, aad: aad, plaintext: plaintext) == sealed)

        var tampered = sealed
        tampered[5] ^= 0x80
        #expect(throws: CryptoError.authenticationFailure) { try aead.open(nonce: nonce, aad: aad, ciphertext: tampered) }
        #expect(throws: CryptoError.authenticationFailure) { try aead.open(nonce: nonce, aad: [], ciphertext: sealed) }
        #expect(throws: CryptoError.authenticationFailure) { try aead.open(nonce: nonce, aad: aad, ciphertext: [1, 2]) }
        // And it still works after a failure.
        #expect(try aead.open(nonce: nonce, aad: aad, ciphertext: sealed) == plaintext)
    }

    /// McGrew and Viega's GCM test cases 2, 4 and 14.
    @Test func aesGCM() throws {
        let zero = try AEAD(.aes128GCM, key: [UInt8](repeating: 0, count: 16))
        #expect(hex(try zero.seal(nonce: [UInt8](repeating: 0, count: 12), plaintext: [UInt8](repeating: 0, count: 16)))
                == "0388dace60b6a392f328c2b971b2fe78" + "ab6e47d42cec13bdf53a67b21257bddf")

        let aead = try AEAD(.aes128GCM, key: bytes("feffe9928665731c6d6a8f9467308308"))
        let nonce = bytes("cafebabefacedbaddecaf888")
        let aad = bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let plaintext = bytes("""
            d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525\
            b16aedf5aa0de657ba637b39
            """)
        let sealed = try aead.seal(nonce: nonce, aad: aad, plaintext: plaintext)
        #expect(hex(sealed) == """
            42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05\
            1ba30b396a0aac973d58e091\
            5bc94fbc3221a5db94fae95ae7121a47
            """)
        #expect(try aead.open(nonce: nonce, aad: aad, ciphertext: sealed) == plaintext)

        let zero256 = try AEAD(.aes256GCM, key: [UInt8](repeating: 0, count: 32))
        #expect(hex(try zero256.seal(nonce: [UInt8](repeating: 0, count: 12), plaintext: [UInt8](repeating: 0, count: 16)))
                == "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919")

        #expect(throws: CryptoError.self) { _ = try AEAD(.aes256GCM, key: [UInt8](repeating: 0, count: 16)) }
        #expect(throws: CryptoError.self) { try zero.seal(nonce: [0], plaintext: []) }
        // An empty message is just a tag.
        let tag = try zero.seal(nonce: [UInt8](repeating: 0, count: 12), plaintext: [])
        #expect(tag.count == 16)
        #expect(try zero.open(nonce: [UInt8](repeating: 0, count: 12), ciphertext: tag) == [])
    }

    @Test func aeadInPlace() throws {
        for algorithm in AEADAlgorithm.allCases {
            let aead = try AEAD(algorithm, key: SecureRandom.bytes(algorithm.keyByteCount))
            let nonce = SecureRandom.bytes(12), aad: [UInt8] = [1, 2, 3]
            let message = SecureRandom.bytes(100)
            let expected = try aead.seal(nonce: nonce, aad: aad, plaintext: message)
            var buffer = message + [UInt8](repeating: 0, count: 16)
            let n = buffer.withUnsafeMutableBytes { b in
                nonce.withUnsafeBytes { iv in
                    aad.withUnsafeBytes { a in
                        aead.seal(nonce: iv.baseAddress!, aad: a, plaintext: UnsafeRawBufferPointer(rebasing: b[..<100]),
                                  into: b.baseAddress!)
                    }
                }
            }
            #expect(n == 116)
            #expect(buffer == expected)
            let m = buffer.withUnsafeMutableBytes { b in
                nonce.withUnsafeBytes { iv in
                    aad.withUnsafeBytes { a in
                        aead.open(nonce: iv.baseAddress!, aad: a, ciphertext: UnsafeRawBufferPointer(b), into: b.baseAddress!)
                    }
                }
            }
            #expect(m == 100)
            #expect(Array(buffer.prefix(100)) == message)
        }
    }

    // MARK: QUIC (RFC 9001 Appendix A)

    @Test func quicInitialKeys() throws {
        let salt = bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
        let initial = HKDF.extract(.sha256, salt: salt, inputKeyMaterial: bytes("8394c8f03e515708"))
        #expect(hex(initial) == "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")

        let client = try HKDF.expandLabel(.sha256, secret: initial, label: "client in", length: 32)
        #expect(hex(client) == "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        #expect(hex(try HKDF.expandLabel(.sha256, secret: client, label: "quic key", length: 16))
                == "1f369613dd76d5467730efcbe3b1a22d")
        #expect(hex(try HKDF.expandLabel(.sha256, secret: client, label: "quic iv", length: 12))
                == "fa044b2f42a3fd3b46fb255c")
        let clientHP = try HKDF.expandLabel(.sha256, secret: client, label: "quic hp", length: 16)
        #expect(hex(clientHP) == "9f50449e04a0e810283a1e9933adedd2")

        let server = try HKDF.expandLabel(.sha256, secret: initial, label: "server in", length: 32)
        #expect(hex(server) == "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        #expect(hex(try HKDF.expandLabel(.sha256, secret: server, label: "quic key", length: 16))
                == "cf3a5331653c364c88f0f379b6067e37")
        #expect(hex(try HKDF.expandLabel(.sha256, secret: server, label: "quic iv", length: 12))
                == "0ac1493ca1905853b0bba03e")
        let serverHP = try HKDF.expandLabel(.sha256, secret: server, label: "quic hp", length: 16)
        #expect(hex(serverHP) == "c206b8d9b9f0f37644430b490eeaa314")

        // A.2 and A.3: AES header protection.
        let hpClient = try HeaderProtection(.aes128GCM, key: clientHP)
        #expect(hex(try hpClient.mask(sample: bytes("d1b1c98dd7689fb8ec11d242b123dc9b"))) == "437b9aec36")
        let hpServer = try HeaderProtection(.aes128GCM, key: serverHP)
        #expect(hex(try hpServer.mask(sample: bytes("2cd0991cd25b0aac406a5816b6394100"))) == "2ec0d8356a")
    }

    /// A.5: a ChaCha20-Poly1305 short-header packet, start to finish.
    @Test func quicChaCha20Packet() throws {
        let secret = bytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        let key = try HKDF.expandLabel(.sha256, secret: secret, label: "quic key", length: 32)
        #expect(hex(key) == "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        let iv = try HKDF.expandLabel(.sha256, secret: secret, label: "quic iv", length: 12)
        #expect(hex(iv) == "e0459b3474bdd0e44a41c144")
        let hp = try HKDF.expandLabel(.sha256, secret: secret, label: "quic hp", length: 32)
        #expect(hex(hp) == "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        #expect(hex(try HKDF.expandLabel(.sha256, secret: secret, label: "quic ku", length: 32))
                == "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")

        var nonce = iv
        let pn: UInt64 = 654_360_564
        for i in 0..<8 { nonce[4 + i] ^= UInt8(truncatingIfNeeded: pn >> (56 - 8 * UInt64(i))) }
        #expect(hex(nonce) == "e0459b3474bdd0e46d417eb0")
        let header = bytes("4200bff4")
        let payload = try AEAD(.chacha20Poly1305, key: key).seal(nonce: nonce, aad: header, plaintext: [0x01])
        #expect(hex(payload) == "655e5cd55c41f69080575d7999c25a5bfb")

        let mask = try HeaderProtection(.chacha20Poly1305, key: hp).mask(sample: Array(payload[1..<17]))
        #expect(hex(mask) == "aefefe7d03")
        var protected = header
        protected[0] ^= mask[0] & 0x1f
        for i in 1..<4 { protected[i] ^= mask[i] }
        #expect(hex(protected + payload) == "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
    }

    // MARK: Key exchange

    /// RFC 7748 6.1.
    @Test func x25519() throws {
        let alice = try KeyExchange(x25519PrivateKey: bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        #expect(hex(alice.publicKey) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let bob = try KeyExchange(x25519PrivateKey: bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        #expect(hex(bob.publicKey) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        #expect(hex(try alice.sharedSecret(with: bob.publicKey)) == shared)
        #expect(hex(try bob.sharedSecret(with: alice.publicKey)) == shared)
        #expect(throws: CryptoError.self) { try alice.sharedSecret(with: [1, 2, 3]) }
        // A low-order point gives an all-zero secret, which is refused.
        #expect(throws: CryptoError.self) { try alice.sharedSecret(with: [UInt8](repeating: 0, count: 32)) }
    }

    @Test func keyExchangeGroups() throws {
        for (group, publicLength, secretLength) in [(KeyExchangeGroup.x25519, 32, 32), (.p256, 65, 32), (.p384, 97, 48)] {
            let a = try KeyExchange(group), b = try KeyExchange(group)
            #expect(a.publicKey.count == publicLength)
            #expect(a.publicKey != b.publicKey)
            let s = try a.sharedSecret(with: b.publicKey)
            #expect(s.count == secretLength)
            #expect(try b.sharedSecret(with: a.publicKey) == s)
            var bad = b.publicKey
            bad[bad.count - 1] ^= 1
            if group != .x25519 {
                // Off the curve.
                #expect(throws: CryptoError.self) { try a.sharedSecret(with: bad) }
            }
        }
        let p256 = try KeyExchange(.p256), p384 = try KeyExchange(.p384)
        #expect(throws: CryptoError.self) { try p256.sharedSecret(with: p384.publicKey) }
    }

    @Test func random() {
        let a = SecureRandom.bytes(32), b = SecureRandom.bytes(32)
        #expect(a.count == 32)
        #expect(a != b)
        #expect(SecureRandom.bytes(0).isEmpty)
    }

    // MARK: JWS (RFC 7515 Appendix A, RFC 8037)

    @Test func hs256() {
        let key = b64url("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
        let input = Array(("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." + jwsPayload).utf8)
        #expect(HMAC.authenticationCode(.sha256, key: key, data: input) == b64url("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
    }

    @Test func rs256() throws {
        let key = try SigningKey(pem: rfc7515RSAKey)
        #expect(key.type == .rsa)
        let input = Array(("eyJhbGciOiJSUzI1NiJ9." + jwsPayload).utf8)
        let expected = b64url("""
            cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4\
            BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv\
            hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw
            """)
        #expect(try key.signature(for: input, algorithm: .rs256) == expected)

        // The public key from the JWK's n and e.
        let n = b64url("""
            ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b\
            32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5Ih\
            lJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ
            """)
        let jwk = try PublicKey(.rsa(modulus: n, exponent: b64url("AQAB")))
        #expect(jwk.bits == 2048)
        #expect(jwk.isValidSignature(expected, for: input, algorithm: .rs256))
        #expect(!jwk.isValidSignature(expected, for: input + [0x20], algorithm: .rs256))
        #expect(!jwk.isValidSignature(expected, for: input, algorithm: .rs384))
        #expect(!jwk.isValidSignature(expected, for: input, algorithm: .es256)) // not this key's
        #expect(jwk.components == .rsa(modulus: n, exponent: [1, 0, 1]))
        #expect(key.publicKey.components == jwk.components)
        // PEM round trips.
        #expect(try PublicKey(pem: jwk.pem).components == jwk.components)
        #expect(try SigningKey(pem: key.pem).signature(for: input, algorithm: .rs256) == expected)
        #expect(key.pem.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        #expect(jwk.pem.hasPrefix("-----BEGIN PUBLIC KEY-----"))
    }

    @Test func ps256() throws {
        let key = try SigningKey(pem: rfc7515RSAKey)
        let input = Array("eyJhbGciOiJQUzI1NiJ9.e30".utf8)
        for algorithm in [SignatureAlgorithm.ps256, .ps384, .ps512, .rs384, .rs512] {
            let a = try key.signature(for: input, algorithm: algorithm)
            #expect(a.count == 256)
            #expect(key.publicKey.isValidSignature(a, for: input, algorithm: algorithm))
            #expect(!key.publicKey.isValidSignature(a, for: input + [0], algorithm: algorithm))
        }
        // PSS is randomized; PKCS #1 v1.5 isn't.
        #expect(try key.signature(for: input, algorithm: .ps256) != key.signature(for: input, algorithm: .ps256))
        #expect(try key.signature(for: input, algorithm: .rs512) == key.signature(for: input, algorithm: .rs512))
        let ps = try key.signature(for: input, algorithm: .ps256)
        #expect(!key.publicKey.isValidSignature(ps, for: input, algorithm: .rs256))
        #expect(!key.publicKey.isValidSignature(ps, for: input, algorithm: .ps384))
    }

    @Test func es256() throws {
        let x = b64url("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"), y = b64url("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
        let key = try PublicKey(.ec(curve: .p256, x: x, y: y))
        #expect(key.type == .p256)
        let input = Array(("eyJhbGciOiJFUzI1NiJ9." + jwsPayload).utf8)
        let signature = b64url("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")
        #expect(key.isValidSignature(signature, for: input, algorithm: .es256))
        var bad = signature
        bad[40] ^= 1
        #expect(!key.isValidSignature(bad, for: input, algorithm: .es256))
        #expect(!key.isValidSignature(Array(signature.prefix(63)), for: input, algorithm: .es256))
        #expect(key.components == .ec(curve: .p256, x: x, y: y))
        // Not on the curve.
        var offX = x
        offX[31] ^= 1
        #expect(throws: CryptoError.self) { try PublicKey(.ec(curve: .p256, x: offX, y: y)) }
        #expect(throws: CryptoError.self) { try PublicKey(.ec(curve: .p384, x: x, y: y)) }
    }

    @Test func es512() throws {
        let key = try PublicKey(.ec(curve: .p521,
                                    x: b64url("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"),
                                    y: b64url("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")))
        let signature = b64url("""
            AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp\
            EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn
            """)
        #expect(signature.count == 132)
        #expect(key.isValidSignature(signature, for: Array("eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA".utf8), algorithm: .es512))
        #expect(!key.isValidSignature(signature, for: Array("eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZB".utf8), algorithm: .es512))
    }

    /// RFC 8032 7.1 test 1, and RFC 8037 A.4.
    @Test func ed25519() throws {
        let seed = bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let key = try SigningKey(ed25519PrivateKey: seed)
        #expect(key.publicKey.components == .ed25519(x: bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")))
        #expect(hex(try key.signature(for: [], algorithm: .eddsa)) == """
            e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b\
            d25bf5f0595bbe24655141438e7a100b
            """)

        let input = Array("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc".utf8)
        let expected = b64url("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
        #expect(try key.signature(for: input, algorithm: .eddsa) == expected)
        let jwk = try PublicKey(.ed25519(x: b64url("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")))
        #expect(jwk.isValidSignature(expected, for: input, algorithm: .eddsa))
        #expect(!jwk.isValidSignature(expected, for: input.dropLast() + [0], algorithm: .eddsa))
        #expect(try PublicKey(pem: key.pem).components == jwk.components)
        #expect(throws: CryptoError.self) { try key.signature(for: input, algorithm: .es256) }
    }

    @Test func generatedKeys() throws {
        let input = Array("signing input".utf8)
        let cases: [(KeyType, SignatureAlgorithm, Int)] = [
            (.p256, .es256, 64), (.p384, .es384, 96), (.p521, .es512, 132), (.ed25519, .eddsa, 64), (.rsa, .ps256, 256),
        ]
        for (type, algorithm, length) in cases {
            let key = try SigningKey.generate(type)
            #expect(key.type == type)
            let signature = try key.signature(for: input, algorithm: algorithm)
            #expect(signature.count == length)
            #expect(key.publicKey.isValidSignature(signature, for: input, algorithm: algorithm))

            // Through the JWK's members and back.
            let fromJWK = try PublicKey(key.publicKey.components)
            #expect(fromJWK.isValidSignature(signature, for: input, algorithm: algorithm))
            // Through PEM and back, private and public.
            let reloaded = try SigningKey(pem: key.pem)
            #expect(reloaded.publicKey.components == key.publicKey.components)
            #expect(try PublicKey(pem: key.publicKey.pem).components == key.publicKey.components)
            // A public key isn't a signing key.
            #expect(throws: CryptoError.self) { try SigningKey(pem: key.publicKey.pem) }

            // And every TLS 1.3 scheme it offers.
            #expect(!key.signatureSchemes.isEmpty)
            for scheme in key.signatureSchemes {
                let s = try key.signature(for: input, scheme: scheme)
                #expect(key.publicKey.isValidSignature(s, for: input, scheme: scheme))
                #expect(!key.publicKey.isValidSignature(s, for: input + [1], scheme: scheme))
            }
        }
        #expect(throws: CryptoError.self) { try SigningKey.generate(.rsa, rsaBits: 1024) }
        #expect(throws: CryptoError.self) { try SigningKey(pem: "not a key") }
        #expect(try SigningKey.generate(.p384).signatureSchemes == [.ecdsaSecp384r1SHA384])
        #expect(try SigningKey(pem: rfc7515RSAKey).signatureSchemes == [.rsaPSSRSAESHA256, .rsaPSSRSAESHA384, .rsaPSSRSAESHA512])
    }

    // MARK: Certificate keys

    @Test func certificateKey() throws {
        let identity = try TLSIdentity.selfSigned(names: ["vega.test", "*.wild.test", "127.0.0.1"])
        let ck = try CertificateKey(chainPEM: identity.certificateChain, keyPEM: identity.privateKey)
        #expect(ck.certificateChain.count == 1)
        #expect(ck.certificateChain[0].first == 0x30) // a DER SEQUENCE
        #expect(ck.signatureSchemes == [.ecdsaSecp256r1SHA256])

        // The certificate's own public key verifies what the key signs.
        let leaf = try PublicKey(certificateDER: ck.certificateChain[0])
        #expect(leaf.components == ck.publicKey.components)
        #expect(try PublicKey(pem: identity.certificateChain).components == leaf.components)
        let content = [UInt8](repeating: 0x20, count: 64) + Array("TLS 1.3, server CertificateVerify\0".utf8) + Hash.sha256([1])
        for scheme in ck.signatureSchemes {
            let signature = try ck.signature(for: content, scheme: scheme)
            #expect(signature.first == 0x30) // ECDSA in DER for TLS
            #expect(leaf.isValidSignature(signature, for: content, scheme: scheme))
            #expect(!leaf.isValidSignature(signature, for: content + [0], scheme: scheme))
        }
        #expect(throws: CryptoError.self) { try ck.signature(for: content, scheme: .ed25519) }

        #expect(ck.matches(host: "vega.test"))
        #expect(ck.matches(host: "VEGA.Test"))
        #expect(ck.matches(host: "a.wild.test"))
        #expect(!ck.matches(host: "a.b.wild.test"))
        #expect(!ck.matches(host: "wild.test"))
        #expect(!ck.matches(host: "other.test"))
        #expect(!ck.matches(host: ""))
        #expect(!ck.matches(host: "vega.test\0.evil"))

        // A key that isn't the certificate's.
        let other = try TLSIdentity.selfSigned(names: ["other.test"])
        #expect(throws: CryptoError.self) {
            try CertificateKey(chainPEM: identity.certificateChain, keyPEM: other.privateKey)
        }
        #expect(throws: CryptoError.self) { try CertificateKey(chainPEM: "", keyPEM: identity.privateKey) }
        #expect(throws: CryptoError.self) { try CertificateKey(chainFile: "/nonexistent/chain.pem", keyFile: "/nonexistent/key.pem") }
    }

    @Test func hostMatching() {
        #expect(CertificateKey.hostMatches(pattern: "example.com", host: "EXAMPLE.com"))
        #expect(CertificateKey.hostMatches(pattern: "*.example.com", host: "www.example.com"))
        #expect(!CertificateKey.hostMatches(pattern: "*.example.com", host: "example.com"))
        #expect(!CertificateKey.hostMatches(pattern: "*.example.com", host: "a.b.example.com"))
        #expect(!CertificateKey.hostMatches(pattern: "*.example.com", host: ".example.com"))
        #expect(!CertificateKey.hostMatches(pattern: "*.", host: "a."))
        #expect(!CertificateKey.hostMatches(pattern: "", host: ""))
    }
}
#endif
