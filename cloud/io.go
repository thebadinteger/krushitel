package cloud

import "os"

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}
