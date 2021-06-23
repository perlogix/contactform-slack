# contactform-slack
[![Go Report Card](https://goreportcard.com/badge/github.com/perlogix/contactform-slack)](https://goreportcard.com/report/github.com/perlogix/contactform-slack)

Send contact form input to Slack with email validation and GeoLite2 information

# Features

- Small web service
- Validate email string
- Block cURL requests
- JSON error messages
- Block free email addresses
- Parse GeoLite2 info for Slack message
- Detect browser user-agent and is mobile
- Send Slack message of contact information

# Example Slack Message Contents

`Name:` Tim Ski

`Email:` tim@someemail.com

`Message:` Love the site!

`Browser:` Chrome

`Mobile:` false

`Country:` United States

`City:` McLean

`State:` Virginia

# Build

```sh
# Binary Build
make build

# Docker Build
make dbuild

## or

# Go build

CGO_ENABLED=0 go build -a -installsuffix cgo -o contactform-slack -ldflags -s -w .

# Create self-signed certs
openssl req -x509 -newkey rsa:4096 -nodes -keyout ./localhost.key -out ./localhost.pem -days 365 -sha256 -subj '/CN=localhost'

# Docker build
sudo docker build . -t perlogix:contactform-slack
```

# Docker Run

`./env-file` format

```sh
SLACK_URL=https://hooks.slack.com/services/...
REDIRECT_URL=https://somesite.com/contact
GEOLITE_DB=./GeoLite2-City.mmdb
```


```sh
make drun

# or 

sudo docker run --name=contactform-slack -d -p 127.0.0.1:8080:8080 --env-file ./env-file --restart always perlogix:contactform-slack
```

# Example Request

```sh
curl -k -XPOST -H 'User-Agent: test-message' -F 'email=tim@someemail.com' -F 'name=tim ski' -F 'message=whats up' https://localhost:8080/contact
```

Responses

```json
{"error":"Email not valid"}
{"error":"Missing form information"}
```