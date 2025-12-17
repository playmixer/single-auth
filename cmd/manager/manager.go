package main

import (
	"auth/internal/adapters/storage"
	"auth/pkg/utils"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	isNew := flag.Bool("new", false, "new user")
	username := flag.String("u", "", "username")
	password := flag.String("p", "", "password")

	isGenKey := flag.Bool("genkey", false, "generate key pare")
	genname := flag.String("n", "", "key name")

	flag.Parse()

	fmt.Println(*isNew, *username, *password)

	store, err := storage.New()
	if err != nil {
		log.Fatal(err)
		return
	}

	defer store.Close()

	if *isNew {
		passwordHash, err := utils.HashPassword(*password)
		if err != nil {
			log.Fatal(err)
			return
		}
		if *username == "" || *password == "" {
			log.Fatal(errors.New("username or password not valid"))
			return
		}
		_, err = store.CreateUser(context.Background(), *username, passwordHash)
		if err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println("User created")
		return
	}

	if *isGenKey {
		if *genname == "" {
			fmt.Println("key name is empty")
			return
		}

		keys, err := utils.GenerateRSAKeys()
		if err != nil {
			log.Fatal(err)
			return
		}

		// Создаём файл для записи
		privateFile, err := os.Create("./data/" + *genname + "_private_key.pem")
		if err != nil {
			log.Fatal(err)
			return
		}

		_, err = privateFile.WriteString("-----BEGIN RSA PRIVATE KEY-----\n" + base64.RawStdEncoding.EncodeToString(keys["private_key"]) + "\n-----END RSA PRIVATE KEY-----")
		if err != nil {
			log.Fatal(err)
			return
		}
		privateFile.Close()

		// Создаём файл для записи
		publickFile, err := os.Create("./data/" + *genname + "_public_key.pem")
		if err != nil {
			log.Fatal(err)
			return
		}

		_, err = publickFile.WriteString("-----BEGIN PUBLIC KEY-----\n" + base64.RawStdEncoding.EncodeToString(keys["public_key"]) + "\n-----END PUBLIC KEY-----")
		if err != nil {
			log.Fatal(err)
			return
		}
		publickFile.Close()

		fmt.Println("Keys created")
		return
	}

	fmt.Println("uncnown command")
}
