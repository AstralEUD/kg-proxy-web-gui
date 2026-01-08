//go:build windows

package services

// Mock xdpObjects for Windows compilation
type xdpObjects struct {
	GeoAllowed       *mockMap
	IpStats          *mockMap
	BlockedIps       *mockMap
	XdpTrafficFilter *mockProgram
}

func (o *xdpObjects) Close() error {
	return nil
}

func loadXdpObjects(obj interface{}, opts interface{}) error {
	return nil
}

type mockMap struct{}

func (m *mockMap) Put(key, value interface{}) error    { return nil }
func (m *mockMap) Lookup(key, value interface{}) error { return nil }
func (m *mockMap) Close() error                        { return nil }
func (m *mockMap) Iterate() interface{}                { return &mockIterator{} }

type mockIterator struct{}

func (i *mockIterator) Next(key, val interface{}) bool { return false }
func (i *mockIterator) Err() error                     { return nil }

type mockProgram struct{}

func (p *mockProgram) Close() error { return nil }
