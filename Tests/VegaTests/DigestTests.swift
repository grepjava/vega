import Testing
import VegaTLS

private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String($0, radix: 16).count == 1 ? "0" + String($0, radix: 16) : String($0, radix: 16) }.joined()
}

/// Against the published vectors: FIPS 180-2, RFC 4231, RFC 7914's PBKDF2
/// cases for SHA-256.
@Suite("Digest", .enabled(if: Digest.isAvailable))
struct DigestTests {
    @Test func sha256() throws {
        #expect(hex(try Digest.sha256(Array("abc".utf8)))
                == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(hex(try Digest.sha256([]))
                == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test func hmacSHA256() throws {
        #expect(hex(try Digest.hmacSHA256(key: Array("Jefe".utf8), Array("what do ya want for nothing?".utf8)))
                == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        // A key longer than a block is hashed first.
        #expect(hex(try Digest.hmacSHA256(key: [UInt8](repeating: 0xaa, count: 131),
                                          Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8)))
                == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    }

    @Test func pbkdf2SHA256() throws {
        let password = Array("password".utf8), salt = Array("salt".utf8)
        #expect(hex(try Digest.pbkdf2SHA256(password: password, salt: salt, iterations: 1))
                == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        #expect(hex(try Digest.pbkdf2SHA256(password: password, salt: salt, iterations: 4096))
                == "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        #expect(try Digest.pbkdf2SHA256(password: password, salt: salt, iterations: 1, length: 64).count == 64)
    }

    @Test func refusesNoIterations() {
        #expect(throws: DigestError()) {
            try Digest.pbkdf2SHA256(password: [], salt: [], iterations: 0)
        }
    }
}
