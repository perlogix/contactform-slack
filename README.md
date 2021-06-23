# contactform-slack
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

# Build

```sh
# Binary Build
make build

# Docker Build
make dbuild
```

# Docker Run

`./env-file` format

```sh
SLACK_URL=https://hooks.slack.com/services/...
REDIRECT_URL=https://somesite.com/contact
GEOLITE_DB=./GeoLite2-City.mmdb
```

```sh
# Run Docker Container
make drun

# or 

sudo docker run --name=contactform-slack -d -p 127.0.0.1:8080:8080 --env-file ./env-file --restart always perlogix:contactform-slack
```

# Example Request

```sh
curl -k -XPOST -H 'User-Agent: test-message' -F 'email=tim@someemail.com' -F 'name=tim ski' -F 'message=whats up' https://localhost:8080/contact
```

# Example Slack Message Contents

`Name:` Tim Ski

`Email:` tim@someemail.com

`Message:` Love the site!

`Browser:` Chrome

`Mobile:` false

`Country:` United States

`City:` McLean

`State:` Virginia