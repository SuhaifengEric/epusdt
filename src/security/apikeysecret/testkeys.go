package apikeysecret

// Fixture master keys used only by automated tests. They are not production material.
const (
	TestActiveKeyID    = "test-master-v1"
	TestActiveKeyHex   = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	TestPreviousKeyID  = "test-master-v0"
	TestPreviousKeyHex = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

// InstallTestKeyring installs the fixture active key. Safe for unit tests only.
func InstallTestKeyring() error {
	ring, err := NewKeyring(TestActiveKeyID, TestActiveKeyHex, nil)
	if err != nil {
		return err
	}
	Replace(ring)
	return nil
}

// InstallRotatedTestKeyring installs overlapping v0+v1 keys with v1 active.
func InstallRotatedTestKeyring() error {
	ring, err := NewKeyring(TestActiveKeyID, TestActiveKeyHex, map[string]string{
		TestPreviousKeyID: TestPreviousKeyHex,
	})
	if err != nil {
		return err
	}
	Replace(ring)
	return nil
}
