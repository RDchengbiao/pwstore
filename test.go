package main
import (
	"path/filepath"
	"fmt"
)

func main(){
	abs, err := filepath.Abs(".")
	fmt.Println(abs)
	fmt.Println(err)

	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	fmt.Println(dir)
	fmt.Println(base)

}
