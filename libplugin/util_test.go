package libplugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCertCAFingerprint(t *testing.T) {
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
	caSigner, err := ssh.NewSignerFromSigner(caPriv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}

	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("user keygen: %v", err)
	}
	userKey, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("user public key: %v", err)
	}

	cert := &ssh.Certificate{
		Key:         userKey,
		CertType:    ssh.UserCert,
		KeyId:       "test",
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}

	got, err := CertCAFingerprint(cert.Marshal())
	if err != nil {
		t.Fatalf("CertCAFingerprint(cert): %v", err)
	}
	want := ssh.FingerprintSHA256(caSigner.PublicKey())
	if got != want {
		t.Errorf("cert CA fingerprint = %q, want %q", got, want)
	}

	// A plain (non-certificate) public key yields an empty fingerprint, no error.
	plain, err := CertCAFingerprint(userKey.Marshal())
	if err != nil {
		t.Fatalf("CertCAFingerprint(plain): %v", err)
	}
	if plain != "" {
		t.Errorf("plain key fingerprint = %q, want empty", plain)
	}
}
