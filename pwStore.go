package  main
import (
	"fmt"
	"strings"
	"bufio"
	"os"
	"strconv"
	"path/filepath"
	"io"
	"secret"
	"bytes"
	"io/ioutil"
	"crypto/md5"
	"os/signal"
	"syscall"
	"golang.org/x/crypto/ssh/terminal"
)

type Item struct {
	content string
}

func (item *Item) Set(str string) {
	item.content = str
}

func (item Item) Get() string{
	return item.content
}

type cryptFile struct{
	filePath string
	file *os.File
}

type pwStore struct{
	pwMd5 string
	pwMd5File *os.File
	pw string
	list []Item
	cryptfile cryptFile
}


func (this *pwStore) Setpw(pw string){
	this.pw = pw
}

func (this *pwStore) Append(item Item) bool {
	this.list = append(this.list, item)
	return true
}

func (this pwStore) ShowList() {
//	fmt.Printf("len %d\n", len(this.list))
	for i:=0; i < len(this.list); i++{
		fmt.Printf("%d.%s\n", i+1, this.list[i].Get())
	}
}

func (this pwStore) Len() int {
	return len(this.list)
}

func (this *pwStore) ModifyItem(id int, str string) {
	this.list[id].Set(str)
}

func (this pwStore) ShowItem(id int) {
	fmt.Printf("%s\n", this.list[id].Get())
}

func (this *pwStore)DelItem(id int){
	this.list = append(this.list[:id], this.list[id+1:]...)
}

func (this *pwStore) InitPwMd5(){
	allData, err := ioutil.ReadAll(this.pwMd5File)
	if err != nil {
		fmt.Printf("read all error: %s\n", err)
		os.Exit(1)
	}
	
	this.pwMd5 = strings.Trim(string(allData), "\n")
}

func (this *pwStore) InitList(){
	var err error
	var bt []byte
	var off int
	str := ""
	bt = make([]byte, 1024)
	for{
//		fmt.Println(off)
		offt := int64(off)
//		fmt.Println("vvvvvvvvv")
//		fmt.Println(offt)

		if off, err = this.cryptfile.file.ReadAt(bt, offt); err == nil {
//			fmt.Println("33333333333")
			str += string(bt)
		}else if(err == io.EOF){
//			fmt.Println("444444444444444")
//			fmt.Printf("len %d\n", len(bt))
			str += string(bt[:off])
			break
		}else{
			fmt.Printf("init list, read at error:%s", err)
			os.Exit(1)
		}
	}

	encrptedStr := str
	if strings.TrimSpace(encrptedStr) == ""{
		return
	}

//	fmt.Printf("#%s#\n", encrptedStr)

	repeat := 16 - len(this.pw) % 16;
//	fmt.Println(repeat)
//	os.Exit(0)
	pad := bytes.Repeat([]byte{byte(repeat)}, repeat)
	
	key := append([]byte(this.pw), pad...)
//	fmt.Printf("key -------> %s\n", string(key))
//	os.Exit(0)


//	fmt.Printf("----encrptedStr--------%s###\n", encrptedStr)

	decrptedStr, err := secret.Dncrypt(encrptedStr, key)
	if err != nil {
		fmt.Printf("Dncrypt err: %s\n", err)
		os.Exit(1)
	}
	
//	fmt.Printf("%s----decrptedStr---------\n", decrptedStr)
	
	lines := strings.Split(decrptedStr, "\n")

//	fmt.Printf("%v-------------\n", lines)
//	fmt.Printf("%d-----+++++--------\n", len(lines))

	for i := 0; i < len(lines)-1; i++ {
		item := Item{lines[i]}
//		item.Set(lines[i])
		this.list = append(this.list, item)
//		this.list[i].Set(lines[i])
//		fmt.Println(lines[i])
	}
//	fmt.Printf("%v +++++++++\n", this.list)
	fmt.Println("init list success!")
}

func (this pwStore) SaveFile(){
	allContents := ""
	for i := 0; i < len(this.list); i++ {
		str := this.list[i].Get() + "\n"
		allContents += str
	}
	var n int64
	var err error
	repeat := 16 - len(this.pw) % 16;
	pad := bytes.Repeat([]byte{byte(repeat)}, repeat)
	key := append([]byte(this.pw), pad...)
	encrptedStr, err := secret.Encrypt([]byte(allContents), key)
	if err != nil {
		fmt.Printf("encrypt error %s\n", err)
		os.Exit(1)
	}

	if err = this.cryptfile.file.Truncate(0); err != nil{
		fmt.Printf("truncate error: %s", err)
		os.Exit(1)
	}

	if n, err = this.cryptfile.file.Seek(0, 2); err != nil {
		fmt.Printf("seek error: %s", err)
		os.Exit(1)
	}
	if _, err := this.cryptfile.file.WriteAt([]byte(encrptedStr), n); err != nil {
		fmt.Printf("write at error: %s", err)
		os.Exit(1)
	}

}

func fileExist(path string) bool {
	var fileInfo os.FileInfo
	var err error
	if fileInfo, err = os.Stat(path); err != nil {
		return false
	}
	if fileInfo.IsDir() {
		return false
	}else{
		return true
	}
}

func dirExist(path string) bool {
	var fileInfo os.FileInfo
	var err error
	if fileInfo, err = os.Stat(path); err != nil {
		return false
	}
	if fileInfo.IsDir() {
		return true 
	}else{
		return false 
	}
}

func gentleExit(){
	fmt.Println("clear resource, gentle exit")
	os.Exit(0)
}


func main() {
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func(){
		for s := range(ch) {
			switch s {
			case syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT:
				fmt.Println("gentle exit")
				gentleExit()
			case syscall.SIGINT:
				fmt.Println("ignore this signal")
			case syscall.SIGUSR1:
				fmt.Println("ignore user1")
			case syscall.SIGUSR2:
				fmt.Println("ignore user2")
			default:
				fmt.Println("other signal")
			}
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	fileName := "./data/cryptContent.txt"

	var fd, md5fd *os.File
	var err error
	defer func(){ 
		fd.Close()
		fmt.Println("fd close")
	}()
	defer func(){ 
		md5fd.Close();
		fmt.Println("md5fd close")
	}()

	if fileExist(fileName) {
		if fd, err = os.OpenFile(fileName, os.O_RDWR, 0666); err != nil {
			fmt.Printf("open file %s error: %s\n", fileName, err)
			os.Exit(1)
		}
	}else{
		dir := filepath.Dir(fileName)
		if !dirExist(dir) {
			if err = os.MkdirAll(dir, os.ModePerm); err != nil {
				fmt.Printf("mkdir %s error: %s\n", dir, err)
				os.Exit(1)
			}
		}
		if fd, err = os.Create(fileName); err != nil {
			fmt.Printf("create file %s error: %s\n", fileName, err)
			os.Exit(1)
		}
	}
	cryptfile := cryptFile{fileName, fd}

	pwMd5Name := "./data/pwMd5.txt"
	if fileExist(pwMd5Name) {
		if md5fd, err = os.OpenFile(pwMd5Name, os.O_RDWR, 0666); err != nil {
			fmt.Printf("open file %s error: %s\n", pwMd5Name, err)
			os.Exit(1)
		}
	}else{
		fmt.Printf("%s not exist\n", pwMd5Name)
		os.Exit(1)
	}

	pwst := pwStore{"", md5fd, "", make([]Item, 0, 1024), cryptfile}
	pwst.InitPwMd5()

	for i := 1; ; i++ {
		pwTips := `
			please input password to enter menu :`
		fmt.Printf(pwTips)

		var input string
		bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
		input = string(bytePassword)
		input = strings.Trim(input, "\n")
		//[16]byte
		inputMd5 := md5.Sum([]byte(input))
		inputMd5Str := fmt.Sprintf("%X", inputMd5)

		if inputMd5Str != pwst.pwMd5 {
			if(i >= 3){
				fmt.Printf("\nerror password beyond three times\n\n")
				os.Exit(0)
			}
			continue
		}
		pw := input
		pwst.Setpw(pw)
		pwst.InitList()

		for{
			tips := `
			####################### menu ##########################
			a. append new item
			d. delete one item
			l. list all item
			m. modify item
			q. list one item
			qt. quit
			#######################################################
			`
			fmt.Printf(tips)
			input, _ = reader.ReadString('\n')
			input = strings.Trim(input, "\n")

			switch input{
			case "a":
				input, _ = reader.ReadString('\n')
				input = strings.Trim(input, "\n")
				item := Item{input}
				if pwst.Append(item) == true {
					fmt.Printf("%s\n", "add new item success!")
				}
				continue
			case "l":
				fmt.Printf("%s\n", "item list:")
				pwst.ShowList()
				continue
			case "m":
				fmt.Printf("which item do you want to modify? enter item no :")
				input, _ = reader.ReadString('\n')
				input = strings.Trim(input, "\n")
				var itemNo int
				var err error
				if itemNo, err = strconv.Atoi(input); err != nil || itemNo <= 0{
					fmt.Printf("%s\n", "please input integer!")
					fmt.Printf("which item do you want to modify? enter item no :")
					input, _ = reader.ReadString('\n')
					input = strings.Trim(input, "\n")

					if itemNo, err = strconv.Atoi(input); err != nil || itemNo <= 0 {
						fmt.Printf("%s\n", "error, input is not integer!")
						continue
					}
				}
//				fmt.Printf("itemNo %d", itemNo)

				pwstLen := pwst.Len()
//				fmt.Printf("pwstLen %d", pwstLen)
				if(itemNo > pwstLen){
					fmt.Printf("%s\n", "error, input beyond max item no!")
					continue
				}

				input, _ = reader.ReadString('\n')
				input = strings.Trim(input, "\n")
				pwst.ModifyItem(itemNo-1, input)

				fmt.Printf("%s\n", "modify item success!")
				continue
			case "q":
				fmt.Printf("which item do you want to query? enter item no :")
				input, _ = reader.ReadString('\n')
				input = strings.Trim(input, "\n")
				var itemNo int
				var err error
				if itemNo, err = strconv.Atoi(input); err != nil || itemNo <= 0{
					fmt.Printf("%s\n", "please input integer!")
					fmt.Printf("which item do you want to query? enter item no :")
					input, _ = reader.ReadString('\n')
					input = strings.Trim(input, "\n")
					if itemNo, err = strconv.Atoi(input); err != nil || itemNo <= 0 {
						fmt.Printf("%s\n", "error, input is not integer!")
						continue
					}
				}

				pwstLen := pwst.Len()
				if(itemNo > pwstLen){
					fmt.Printf("%s\n", "error, input beyond max item no!")
					continue
				}
				pwst.ShowItem(itemNo-1)
				continue

			case "d":
				fmt.Printf("which item do you want to delete? enter item no :")
				input, _ = reader.ReadString('\n')
				input = strings.Trim(input, "\n")
				var itemNo int
				var err error
				if itemNo, err = strconv.Atoi(input); err != nil || itemNo <= 0{
					fmt.Printf("%s\n", "please input integer!")
					fmt.Printf("which item do you want to delete? enter item no :")
					input, _ = reader.ReadString('\n')
					input = strings.Trim(input, "\n")
					if itemNo, err = strconv.Atoi(input); err != nil || itemNo <= 0 {
						fmt.Printf("%s\n", "error, input is not integer!")
						continue
					}
				}
				pwstLen := pwst.Len()
				if(itemNo > pwstLen){
					fmt.Printf("%s\n", "error, input beyond max item no!")
					continue
				}
				fmt.Printf("you will delete item:%d, are you sure? Y/N:", itemNo)

				bt, err := reader.ReadByte()
				if err != nil {
					fmt.Printf("read Y/N error!\n")
					continue
				}
				upper := bytes.ToUpper([]byte{bt})
				if bytes.Equal(upper, []byte{'Y'}) {
					pwst.DelItem(itemNo-1)
					fmt.Printf("delete success!\n")
				}else if bytes.Equal(upper, []byte{'N'}) {
					fmt.Printf("delete abort!\n")
				}else{
					fmt.Printf("input not Y/N, delete abort!\n")
				}
				continue
			case "qt":
				exitStr := `
							see you ~~
				`
				fmt.Printf("%s\n", exitStr)
				pwst.SaveFile()
				os.Exit(0)
			default:
				continue
			}
		}
	}
}
