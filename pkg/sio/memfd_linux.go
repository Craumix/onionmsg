package sio

import (
	"log"
	"strconv"

	"golang.org/x/sys/unix"
)

//CreateMemFD creates an anonymous file and then returns the path for the created file.
func CreateMemFD(name string) (path string, err error) {
	handle, err := unix.MemfdCreate(name, 0)
	if err != nil {
		log.Printf("Unable to create Memfd \"%s\"!\n", name)
		return "", err
	}

	path = "/proc/self/fd/" + strconv.Itoa(handle)

	return path, nil
}
