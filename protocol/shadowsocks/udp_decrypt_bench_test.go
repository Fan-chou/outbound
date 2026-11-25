package shadowsocks

import (
	"crypto/sha1"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

// hkdfReaderDecryptUDP decrypts a UDP packet using hkdf.New + io.ReadFull
// rather than inline deriveSubKey, providing a reference baseline for
// DecryptUDPFromPool benchmarks. Not wired into production.
func hkdfReaderDecryptUDP(key *Key, shadowBytes pool.PB, reusedInfo []byte) (pool.PB, error) {
	conf := key.CipherConf
	buf := pool.Get(len(shadowBytes))
	if buf.HeadOverlap(shadowBytes) {
		buf = pool.PB(make([]byte, len(shadowBytes)))
	}
	subKey := getSubKey(conf.KeyLen)
	kdf := hkdf.New(sha1.New, key.MasterKey, shadowBytes[:conf.SaltLen], reusedInfo)
	if _, err := io.ReadFull(kdf, subKey); err != nil {
		pool.Put(buf)
		return nil, err
	}
	ciph, err := conf.NewCipher(subKey)
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	out, err := ciph.Open(buf[:0], ciphers.ZeroNonce[:conf.NonceLen], shadowBytes[conf.SaltLen:], nil)
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	putSubKey(subKey)
	return pool.PB(out), nil
}

func newUDPDecryptBenchFixture(b *testing.B, payloadSize int) (*Key, pool.PB, []byte) {
	b.Helper()
	conf := ciphers.AeadCiphersConf["chacha20-ietf-poly1305"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(masterKey)
	_, _ = fastrand.Read(salt)
	key := &Key{CipherConf: conf, MasterKey: masterKey}
	info := []byte("juicity-reused-info")
	plaintext := make([]byte, payloadSize)
	_, _ = fastrand.Read(plaintext)
	encrypted, err := EncryptUDPFromPool(key, plaintext, salt, info)
	if err != nil {
		b.Fatal(err)
	}
	return key, encrypted, info
}

// BenchmarkUDPDecrypt_HKDFReader benchmarks UDP decryption using hkdf.New + io.ReadFull.
func BenchmarkUDPDecrypt_HKDFReader(b *testing.B) {
	key, encrypted, info := newUDPDecryptBenchFixture(b, 1400)
	defer encrypted.Put()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec, err := hkdfReaderDecryptUDP(key, encrypted, info)
		if err != nil {
			b.Fatal(err)
		}
		dec.Put()
	}
}

// BenchmarkUDPDecrypt_InlineKeySchedule benchmarks DecryptUDPFromPool with inline deriveSubKey.
func BenchmarkUDPDecrypt_InlineKeySchedule(b *testing.B) {
	key, encrypted, info := newUDPDecryptBenchFixture(b, 1400)
	defer encrypted.Put()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec, err := DecryptUDPFromPool(key, encrypted, info)
		if err != nil {
			b.Fatal(err)
		}
		dec.Put()
	}
}

// BenchmarkCipherOnly_1400 isolates NewCipher + AEAD Open (chacha20poly1305) for
// a 1400-byte payload, excluding HKDF and buffer pooling. Used to confirm how
// much of the full UDP decrypt CPU is the cipher vs the rest.
func BenchmarkCipherOnly_1400(b *testing.B) {
	conf := ciphers.AeadCiphersConf["chacha20-ietf-poly1305"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	_, _ = fastrand.Read(masterKey)
	_, _ = fastrand.Read(salt)
	subKey := make([]byte, conf.KeyLen)
	deriveSubKey(subKey, masterKey, salt, []byte("juicity-reused-info"))

	nonce := ciphers.ZeroNonce[:conf.NonceLen]
	plaintext := make([]byte, 1400)
	_, _ = fastrand.Read(plaintext)
	ciph0, _ := conf.NewCipher(subKey)
	ciphertext := make([]byte, len(plaintext)+conf.TagLen)
	ciph0.Seal(ciphertext[:0], nonce, plaintext, nil)
	out := make([]byte, len(plaintext))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciph, _ := conf.NewCipher(subKey)
		if _, err := ciph.Open(out[:0], nonce, ciphertext, nil); err != nil {
			b.Fatal(err)
		}
	}
}
