package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/goware/emailx"
	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/mssola/user_agent"
	geoip2 "github.com/oschwald/geoip2-golang"
)

const (
	missingForm        = "Missing form information"
	emailNotValid      = "Email not valid"
	slackURLMissing    = "SLACK_URL ENV var is missing"
	redirectURLMissing = "REDIRECT_URL ENV var is missing"
	geoliteDBMissing   = "GEOLITE_DB ENV var is missing"
)

var (
	cl = &http.Client{
		Timeout: 5 * time.Second,
	}
	ciphers = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	curves           = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
	blackListDomains = []string{"monkeydigital.co", "aol.com", "att.net", "comcast.net", "facebook.com", "gmail.com", "gmx.com", "googlemail.com", "google.com", "hotmail.com", "hotmail.co.uk", "mac.com", "me.com", "mail.com", "msn.com", "live.com", "sbcglobal.net", "verizon.net", "yahoo.com", "yahoo.co.uk", "email.com", "fastmail.fm", "games.com", "gmx.net", "hush.com", "hushmail.com", "icloud.com", "iname.com", "inbox.com", "lavabit.com", "love.com", "outlook.com", "pobox.com", "protonmail.ch", "protonmail.com", "tutanota.de", "tutanota.com", "tutamail.com", "tuta.io", "keemail.me", "rocketmail.com", "safe-mail.net", "wow.com", "ygm.com", "ymail.com", "zoho.com", "yandex.com", "bellsouth.net", "charter.net", "cox.net", "earthlink.net", "juno.com", "btinternet.com", "virginmedia.com", "blueyonder.co.uk", "live.co.uk", "ntlworld.com", "orange.net", "sky.com", "talktalk.co.uk", "tiscali.co.uk", "virgin.net", "bt.com", "sina.com", "sina.cn", "qq.com", "naver.com", "hanmail.net", "daum.net", "nate.com", "yahoo.co.jp", "yahoo.co.kr", "yahoo.co.id", "yahoo.co.in", "yahoo.com.sg", "yahoo.com.ph", "163.com", "yeah.net", "126.com", "21cn.com", "aliyun.com", "foxmail.com", "hotmail.fr", "live.fr", "laposte.net", "yahoo.fr", "wanadoo.fr", "orange.fr", "gmx.fr", "sfr.fr", "neuf.fr", "free.fr", "gmx.de", "hotmail.de", "live.de", "online.de", "t-online.de", "web.de", "yahoo.de", "libero.it", "virgilio.it", "hotmail.it", "aol.it", "tiscali.it", "alice.it", "live.it", "yahoo.it", "email.it", "tin.it", "poste.it", "teletu.it", "bk.ru", "inbox.ru", "list.ru", "mail.ru", "rambler.ru", "yandex.by", "yandex.com", "yandex.kz", "yandex.ru", "yandex.ua", "ya.ru", "hotmail.be", "live.be", "skynet.be", "voo.be", "tvcablenet.be", "telenet.be", "hotmail.com.ar", "live.com.ar", "yahoo.com.ar", "fibertel.com.ar", "speedy.com.ar", "arnet.com.ar", "yahoo.com.mx", "live.com.mx", "hotmail.es", "hotmail.com.mx", "prodigy.net.mx", "yahoo.ca", "hotmail.ca", "bell.net", "shaw.ca", "sympatico.ca", "rogers.com", "yahoo.com.br", "hotmail.com.br", "outlook.com.br", "uol.com.br", "bol.com.br", "terra.com.br", "ig.com.br", "r7.com", "zipmail.com.br", "globo.com", "globomail.com", "oi.com.br"}
)

func init() {
	_, err := getConfigs("url")
	if err != nil {
		panic(err)
	}

	_, err = getConfigs("geolite")
	if err != nil {
		panic(err)
	}

	_, err = getConfigs("redirect")
	if err != nil {
		panic(err)
	}
}

type errorJSON struct {
	Msg string `json:"error"`
}

type location struct {
	City    string
	State   string
	Country string
}

type submit struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Message string `json:"message"`
	City    string `json:"city"`
	State   string `json:"state"`
	Country string `json:"country"`
	Mobile  bool   `json:"mobile"`
	Browser string `json:"browser"`
}

type slackAttachment struct {
	Fallback string `json:"fallback"`
	Text     string `json:"text"`
	Color    string `json:"color"`
}

type slackItem struct {
	Text        string `json:"text"`
	Attachments []slackAttachment
}

func getConfigs(c string) (string, error) {
	switch c {
	case "url":
		url := os.Getenv("SLACK_URL")
		if url == "" {
			return "", errors.New(slackURLMissing)
		}
		return url, nil

	case "redirect":
		redirect := os.Getenv("REDIRECT_URL")
		if redirect == "" {
			return "", errors.New(redirectURLMissing)
		}
		return redirect, nil

	case "geolite":
		geolite := os.Getenv("GEOLITE_DB")
		if geolite == "" {
			return "", errors.New(geoliteDBMissing)
		}
		return geolite, nil
	}

	return "", nil
}

func sendSlack(d *submit) error {
	payload := slackItem{
		Text:        fmt.Sprintf("Name: %s, Email: %s, Message: %s, Browser: %s, Mobile: %t, Country: %s, City: %s, State: %s", d.Name, d.Email, d.Message, d.Browser, d.Mobile, d.Country, d.City, d.State),
		Attachments: []slackAttachment{},
	}

	payload.Attachments = append(payload.Attachments, slackAttachment{
		Fallback: "New Contact",
		Text:     "New Contact",
		Color:    "#17C671",
	})

	log.Println(payload.Text)

	url, _ := getConfigs("url")

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func findLocation(ip string) (*location, error) {
	geolite, _ := getConfigs("geolite")

	db, err := geoip2.Open(geolite)
	if err != nil {
		return nil, err
	}

	defer db.Close()

	parseIP := net.ParseIP(ip)
	record, err := db.City(parseIP)
	if err != nil {
		return nil, err
	}

	loc := &location{}
	if city, ok := record.City.Names["en"]; ok {
		loc.City = city
	}

	if len(record.Subdivisions) != 0 {
		loc.State = record.Subdivisions[0].Names["en"]
	}

	if country, ok := record.Country.Names["en"]; ok {
		loc.Country = country
	}

	return loc, nil
}

func signupRte(c echo.Context) error {
	name := c.FormValue("name")
	email := c.FormValue("email")
	message := c.FormValue("message")

	err := emailx.Validate(email)
	if err != nil {
		e := errorJSON{Msg: emailNotValid}
		return c.JSON(500, e)
	}

	redirect, _ := getConfigs("redirect")

	if name != "" && email != "" && message != "" {
		emailDomain := strings.Split(email, "@")[1]
		for _, e := range blackListDomains {
			if emailDomain == e {
				return c.Redirect(301, redirect)
			}
		}

		agent := c.Request().Header.Get("User-Agent")
		var data *submit
		ua := user_agent.New(agent)

		browser, _ := ua.Browser()
		if browser == "curl" {
			return c.Redirect(301, redirect)
		}

		mobile := ua.Mobile()

		loc, err := findLocation(c.RealIP())
		if err != nil {
			data = &submit{Name: name, Email: email, Message: message, Browser: browser, Mobile: mobile}
		} else {
			data = &submit{Name: name, Email: email, Message: message, Browser: browser, Mobile: mobile, City: loc.City, State: loc.State, Country: loc.Country}
		}

		err = sendSlack(data)
		if err != nil {
			log.Println(err)
			return err
		}

		return c.Redirect(301, redirect)
	}

	e := errorJSON{Msg: missingForm}
	return c.JSON(500, e)
}

func main() {
	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.Secure())

	e.POST("/contact", signupRte)

	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 200
	http.DefaultTransport.(*http.Transport).MaxConnsPerHost = 200

	tlsCfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         curves,
		PreferServerCipherSuites: true,
		CipherSuites:             ciphers,
	}

	s := &http.Server{
		Addr:              "0.0.0.0:8080",
		Handler:           e.Server.Handler,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig:         tlsCfg,
	}

	e.Logger.Fatal(s.ListenAndServeTLS("./localhost.pem", "./localhost.key"))
}
