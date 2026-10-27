//go:build !linux

package main

import "fmt"

func main() {
	fmt.Println("xdpshield only runs on linux")
}
