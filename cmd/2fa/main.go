package main

import (
	"crypto"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"

	"github.com/insomniacslk/mfastore"
	"github.com/kirsle/configdir"
	"github.com/sec51/twofactor"
	"github.com/spf13/pflag"
)

const progname = "2fa"

var (
	DefaultStoreFile = path.Join(configdir.LocalConfig(progname), "store.json")
)

var (
	flagEmail     = pflag.StringP("email", "e", "", "E-mail for 2fa authentication")
	flagIssuer    = pflag.StringP("issuer", "i", "", "Issuer name (for new TOTP generation)")
	flagDigits    = pflag.IntP("digits", "d", 6, "Number of digits for TOTP")
	flagStoreFile = pflag.StringP("store-file", "s", DefaultStoreFile, "Store file, containing keys. It is unencrypted, you are responsible for secure storage of its content")
)

func main() {
	pflag.Parse()

	if *flagStoreFile == "" {
		log.Fatalf("Empty store file, see --store-file")
	}
	store, err := mfastore.Load(*flagStoreFile)
	if err != nil {
		log.Fatalf("Failed to get store from file '%s': %v", *flagStoreFile, err)
	}

	action := pflag.Arg(0)
	switch action {
	case "new":
		if *flagEmail == "" {
			log.Fatal("Missing --email")
		}
		if *flagIssuer == "" {
			log.Fatal("Missing --issuer")
		}
		var totp []byte
		totp, err = generateTOTP(*flagEmail, *flagIssuer, *flagDigits)
		if err != nil {
			break
		}
		// add or overwrite TOTP key for this issuer/email
		err = store.SetKey(*flagIssuer, *flagEmail, totp)
	case "validate":
		var (
			otp *twofactor.Totp
			key *mfastore.Key
		)
		key, err = store.GetKey(*flagIssuer, *flagEmail)
		if err != nil {
			break
		}
		otp, err = twofactor.TOTPFromBytes(key.Bytes, *flagIssuer)
		if err != nil {
			break
		}
		var token string
		fmt.Printf("Type token from authenticator\n")
		fmt.Scan(&token)
		err = otp.Validate(token)
	case "":
		err = fmt.Errorf("no action specified")
	default:
		err = fmt.Errorf("unknown action")
	}
	if err != nil {
		log.Fatalf("Action '%s' failed: %v", action, err)
	}
	fmt.Println("Authentication successful!")

	// save store to file at the end
	if err := store.Save(*flagStoreFile); err != nil {
		log.Fatalf("Failed to save key store to file: %v", err)
	}
}

func generateTOTP(email, name string, digits int) ([]byte, error) {
	otp, err := twofactor.NewTOTP(email, name, crypto.SHA1, digits)
	if err != nil {
		return nil, err
	}
	qrBytes, err := otp.QR()
	if err != nil {
		return nil, err
	}
	// TODO expose the QR code through better means than calling "open qr.png"
	if err := os.WriteFile("qr.png", qrBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write QR code to file: %w", err)
	}
	cmd := exec.Command("open", "qr.png")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to open QR code image: %w", err)
	}
	var token string
	fmt.Printf("Type token from authenticator\n")
	fmt.Scan(&token)
	if err := otp.Validate(token); err != nil {
		return nil, err
	}
	// if there is an error, then the authentication failed
	// if it succeeded, then store this information and do not display the QR code ever again.
	return otp.ToBytes()
}
