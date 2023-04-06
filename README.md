# oneloginaws
An extremely janky tool for scraping SAML Assertions out of OneLogin for use with the awscli


# install
```
go install  github.com/cnelson/oneloginaws@latest
```

# usage
```
eval $(echo "password\nmfaotp" | oneloginaws --appid 31337 --endpoint https://<company>.onelogin.com/ --principalarn "arn:aws:iam::31337:saml-provider/..." --rolearn "arn:aws:iam::31337:role/..." --username username)

```