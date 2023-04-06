# oneloginaws
An extremely janky tool for scraping SAML Assertions out of OneLogin for use with the awscli.

If you have admin privileges to your OneLogin instance, please consider the [official](https://github.com/onelogin/onelogin-aws-cli-assume-role) or [community](https://github.com/physera/onelogin-aws-cli) solutions, instead of this dreck.

# install
```
go install github.com/cnelson/oneloginaws@latest
```

# usage
```
eval $(echo "password\nmfaotp" | oneloginaws --appid 31337 --endpoint https://<company>.onelogin.com/ --principalarn "arn:aws:iam::31337:saml-provider/..." --rolearn "arn:aws:iam::31337:role/..." --username username)
```