package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inferlabshq/akasha/internal/sign"
)

var (
	keygenOut       string
	signKeyPath     string
	signPublisher   string
	verifyPubKeyArg string
)

// keygen creates a publisher keypair. A publisher (Akasha itself, or a
// third-party plugin author) signs templates with the private key; users trust
// the public key. This is the root of the marketplace trust model.
var keygenCmd = &cobra.Command{
	Use:          "keygen",
	Short:        "Generate an Ed25519 publisher keypair for signing plugins",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		pub, priv, err := sign.GenerateKey()
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		if keygenOut == "" {
			// Print to stdout; never let a private key sit unannounced.
			fmt.Fprintf(w, "public key:  %s\n", sign.EncodeKey(pub))
			fmt.Fprintf(w, "private key: %s\n", sign.EncodeKey(priv))
			fmt.Fprintln(w, "\nKeep the private key secret. Publish only the public key.")
			return nil
		}
		if err := os.WriteFile(keygenOut+".key", []byte(sign.EncodeKey(priv)), 0600); err != nil {
			return err
		}
		if err := os.WriteFile(keygenOut+".pub", []byte(sign.EncodeKey(pub)), 0644); err != nil {
			return err
		}
		fmt.Fprintf(w, "✓ Wrote %s.key (private, 0600) and %s.pub (public)\n", keygenOut, keygenOut)
		fmt.Fprintf(w, "  public key: %s\n", sign.EncodeKey(pub))
		return nil
	},
}

var templateSignCmd = &cobra.Command{
	Use:          "sign <file>",
	Short:        "Sign a plugin file, producing <file>.sig",
	Long:         "Signs a plugin's bytes with a publisher private key. Distribute the .sig alongside the .yaml; users who trust the publisher get the plugin auto-approved.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if signKeyPath == "" || signPublisher == "" {
			return fmt.Errorf("--key <private-key-file> and --publisher <id> are required")
		}
		content, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		priv, err := sign.LoadPrivateKey(signKeyPath)
		if err != nil {
			return err
		}
		s := sign.Sign(content, signPublisher, priv)
		if err := sign.WriteSignature(args[0], s); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Wrote %s (publisher %q)\n", sign.SigPath(args[0]), signPublisher)
		return nil
	},
}

var templateVerifyCmd = &cobra.Command{
	Use:          "verify <file>",
	Short:        "Verify a plugin's signature against a public key",
	Long:         "Checks <file>.sig against a public key (base64 string or a .pub file). For author/debug use; the daemon verifies against trusted publishers automatically.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifyPubKeyArg == "" {
			return fmt.Errorf("--pubkey <base64-or-.pub-file> is required")
		}
		content, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		sig, ok, err := sign.LoadSignature(args[0])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no signature found at %s", sign.SigPath(args[0]))
		}
		pubStr := verifyPubKeyArg
		if data, ferr := os.ReadFile(verifyPubKeyArg); ferr == nil {
			pubStr = string(data)
		}
		pub, err := sign.DecodePublicKey(pubStr)
		if err != nil {
			return err
		}
		if sig.Verify(content, pub) {
			fmt.Fprintf(cmd.OutOrStdout(), "✓ valid signature by publisher %q\n", sig.Publisher)
			return nil
		}
		return fmt.Errorf("signature does NOT verify (wrong key, or file changed since signing)")
	},
}

func init() {
	keygenCmd.Flags().StringVar(&keygenOut, "out", "", "Write <out>.key and <out>.pub instead of printing")
	templateSignCmd.Flags().StringVar(&signKeyPath, "key", "", "Publisher private key file")
	templateSignCmd.Flags().StringVar(&signPublisher, "publisher", "", "Publisher id to record in the signature")
	templateVerifyCmd.Flags().StringVar(&verifyPubKeyArg, "pubkey", "", "Public key (base64) or a .pub file")
	templateCmd.AddCommand(templateSignCmd, templateVerifyCmd)
}
