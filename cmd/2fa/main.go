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
	flagUsername    = pflag.StringP("username", "u", "", "E-mail for 2fa authentication")
	flagIssuer      = pflag.StringP("issuer", "i", "", "Issuer name (for new TOTP generation)")
	flagDigits      = pflag.IntP("digits", "d", 6, "Number of digits for TOTP")
	flagStoreFile   = pflag.StringP("store-file", "s", DefaultStoreFile, "Store file, containing keys. It is unencrypted, you are responsible for secure storage of its content")
	flagUserEnabled = pflag.BoolP("user-enabled", "U", true, "If true, the user can log in")
	flagMFAEnabled  = pflag.BoolP("mfa-enabled", "M", true, "If true, MFA is required for the user to log in")
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
		if *flagUsername == "" {
			log.Fatal("Missing --username")
		}
		if *flagIssuer == "" {
			log.Fatal("Missing --issuer")
		}
		var totp []byte
		totp, err = generateTOTP(*flagUsername, *flagIssuer, *flagDigits)
		if err != nil {
			break
		}
		// add or overwrite TOTP key for this issuer/user
		err = store.SetKey(
			*flagIssuer,
			&mfastore.Key{
				Username:    *flagUsername,
				Bytes:       totp,
				UserEnabled: *flagUserEnabled,
				MFAEnabled:  *flagMFAEnabled,
			},
		)
	case "validate":
		var (
			otp *twofactor.Totp
			key *mfastore.Key
		)
		key, err = store.GetKey(*flagIssuer, *flagUsername)
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
		if !key.UserEnabled {
			err = fmt.Errorf("user not enabled to log in")
			break
		}
		if !key.MFAEnabled {
			err = nil
			break
		}
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

func generateTOTP(username, name string, digits int) ([]byte, error) {
	otp, err := twofactor.NewTOTP(username, name, crypto.SHA1, digits)
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
