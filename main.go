package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/cnelson/oneloginaws/client"
	"github.com/namsral/flag"
	"golang.org/x/term"
	"io"
	"os"
	"os/exec"
	"strings"
)

type AWSSTSAssumeRoleRespone struct {
	Credentials     AWSSTSAssumeRoleResponeCredentials
	AssumedRoleUser AWSAWSSTSAssumeRoleResponeAssumedRoleUser
}

type AWSSTSAssumeRoleResponeCredentials struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

type AWSAWSSTSAssumeRoleResponeAssumedRoleUser struct {
	AssumedRoleId string
	Arn           string
}

func login(args ...string) {
	var endpoint string
	var username string
	var appid string
	var rolearn string
	var principalarn string

	fs := flag.NewFlagSetWithEnvPrefix(args[0], "ONELOGINAWS", 0)

	fs.StringVar(&endpoint, "endpoint", "", "The onelogin endpoint for your company, https://foo.onelogin.com/")
	fs.StringVar(&username, "username", "", "The username to login with")
	fs.StringVar(&appid, "appid", "", "The app id to use. This can be found by examing the url for an app. Given a url like https://foo.onelogin.com/client/apps/select/31337916, the app id is 31337916.")
	fs.StringVar(&rolearn, "rolearn", "", "An AWS ARN for the role you will be assuming")
	fs.StringVar(&principalarn, "principalarn", "", "An AWS ARN for the OneLogin saml provider")

	fs.Parse(args[1:])

	usage := func() {
		out := "Required flags:\n"
		out += "They may be specified as environment varibes with the prefix ONELOGINAWS_, for example ONELOGINAWS_APPID\n"
		var b bytes.Buffer
		fs.SetOutput(io.Writer(&b))
		fs.PrintDefaults()

		out += b.String() + "\n"

		out += "This app expects to be able to read two lines from stdin:\n"
		out += " - The first line is the password for the user.\n"
		out += " - The second line is the OTP from your Authenticator if MFA is enabled, or a blank line.\n"

		printAndExit(out, 1)
	}

	if endpoint == "" || username == "" || appid == "" || rolearn == "" || principalarn == "" {
		usage()
	}

	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	otp, _ := reader.ReadString('\n')
	otp = strings.TrimSpace(otp)

	if password == "" {
		usage()
	}

	client, err := client.NewClient(endpoint)
	if err != nil {
		printAndExit(fmt.Sprintf("Error communicating with endpoint %s: %s", endpoint, err), 2)
	}

	err = client.Login(username, password, otp)
	if err != nil {
		printAndExit(fmt.Sprintf("Error authenticating: %s", err), 3)
	}

	samlAssertion, err := client.SamlAssertionForApp(appid)
	if err != nil {
		printAndExit(fmt.Sprintf("Error retreiving SAML Assertion: %s", err), 4)
	}

	// get AWS temporary tokens from the saml response
	cmd := exec.Command(
		"aws",
		"sts", "assume-role-with-saml",
		"--role-arn", rolearn,
		"--principal-arn", principalarn,
		"--saml-assertion", samlAssertion,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		printAndExit(fmt.Sprintf("Failed running aws cli: %s\n%s", err, stderr.String), 5)
	}

	stsresp, err := decodeSTSResponse(stdout.Bytes())

	if err != nil {
		printAndExit(fmt.Sprintf("Failed decoding STS Response: %s", err), 6)
	}

	fmt.Printf(
		"export AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s;\n",
		stsresp.Credentials.AccessKeyId,
		stsresp.Credentials.SecretAccessKey,
		stsresp.Credentials.SessionToken,
	)

	printAndExit(
		fmt.Sprintf("Authenticated to AWS as %s", stsresp.AssumedRoleUser.Arn),
		0,
	)

}

func printAndExit(content string, exitCode int) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println(content)
	} else {
		fmt.Printf(`echo -e "%s"`, strings.Replace(strings.Replace(content, `"`, `\"`, -1), "\n", `\n`, -1))
	}
	os.Exit(exitCode)

}

func decodeSTSResponse(body []byte) (*AWSSTSAssumeRoleRespone, error) {
	var stsresp AWSSTSAssumeRoleRespone
	err := json.Unmarshal(body, &stsresp)
	if err != nil {
		return nil, err
	}

	return &stsresp, nil
}

func main() {
	login(os.Args...)
}
