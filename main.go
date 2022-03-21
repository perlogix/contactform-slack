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
	cmap "github.com/orcaman/concurrent-map"
	geoip2 "github.com/oschwald/geoip2-golang"
)

const (
	missingForm        = "Missing form information"
	emailNotValid      = "Email not valid"
	slackURLMissing    = "SLACK_URL ENV var is missing"
	redirectURLMissing = "REDIRECT_URL ENV var is missing"
	geoliteDBMissing   = "GEOLITE_DB ENV var is missing"
	mapSize            = 100
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
	blacklistAgents  = []string{"01h4x.com", "360spider", "404checker", "404enemy", "80legs", "admantx", "aibot", "alittle client", "aspseek", "abonti", "aboundex", "aboundexbot", "acunetix", "afd-verbotsverfahren", "ahrefsbot", "aihitbot", "aipbot", "alexibot", "allsubmitter", "alligator", "alphabot", "anarchie", "anarchy", "anarchy99", "ankit", "anthill", "apexoo", "aspiegel", "asterias", "atomseobot", "attach", "awariorssbot", "awariosmartbot", "bbbike", "bdcbot", "bdfetch", "blexbot", "backdoorbot", "backstreet", "backweb", "backlink-ceck", "backlinkcrawler", "badass", "bandit", "barkrowler", "batchftp", "battleztar bazinga", "betabot", "bigfoot", "bitacle", "blackwidow", "black hole", "blackboard", "blow", "blowfish", "boardreader", "bolt", "botalot", "brandprotect", "brandwatch", "buck", "buddy", "builtbottough", "builtwith", "bullseye", "bunnyslippers", "buzzsumo", "catexplorador", "ccbot", "code87", "cshttp", "calculon", "cazoodlebot", "cegbfeieh", "censysinspect", "cheteam", "cheesebot", "cherrypicker", "chinaclaw", "chlooe", "citoid", "claritybot", "cliqzbot", "cloud mapping", "cocolyzebot", "cogentbot", "collector", "copier", "copyrightcheck", "copyscape", "cosmos", "craftbot", "crawling at home project", "crazywebcrawler", "crescent", "crunchbot", "curious", "curl", "custo", "cyotekwebcopy", "dblbot", "diibot", "dsearch", "dts agent", "datacha0s", "databasedrivermysqli", "demon", "deusu", "devil", "digincore", "digitalpebble", "dirbuster", "disco", "discobot", "discoverybot", "dispatch", "dittospyder", "dnbcrawler-analytics", "dnyzbot", "domcopbot", "domainappender", "domaincrawler", "domainsigmacrawler", "domainstatsbot", "domains project", "dotbot", "download wonder", "dragonfly", "drip", "eccp/1.0", "email siphon", "email wolf", "easydl", "ebingbong", "ecxi", "eirgrabber", "erocrawler", "evil", "exabot", "express webpictures", "extlinksbot", "extractor", "extractorpro", "extreme picture finder", "eyenetie", "ezooms", "fdm", "fhscan", "femtosearchbot", "fimap", "firefox/7.0", "flashget", "flunky", "foobot", "freeuploader", "frontpage", "fuzz", "fyberspider", "fyrebot", "g-i-g-a-b-o-t", "gt::www", "galaxybot", "genieo", "germcrawler", "getright", "getweb", "getintent", "gigabot", "go!zilla", "go-ahead-got-it", "gozilla", "gotit", "grabnet", "grabber", "grafula", "grapefx", "grapeshotcrawler", "gridbot", "headmasterseo", "hmview", "htmlparser", "http::lite", "httrack", "haansoft", "haosouspider", "harvest", "havij", "heritrix", "hloader", "honolulubot", "humanlinks", "hybridbot", "idbte4m", "idbot", "irlbot", "iblog", "id-search", "ilsebot", "image fetch", "image sucker", "indeedbot", "indy library", "infonavirobot", "infotekies", "intelliseek", "interget", "internetseer", "internet ninja", "iria", "iskanie", "istellabot", "joc web spider", "jamesbot", "jbrofuzz", "jennybot", "jetcar", "jetty", "jikespider", "joomla", "jorgee", "justview", "jyxobot", "kenjin spider", "keybot translation-search-machine", "keyword density", "kinza", "kozmosbot", "lnspiderguy", "lwp::simple", "lanshanbot", "larbin", "leap", "leechftp", "leechget", "lexibot", "lftp", "libweb", "libwhisker", "liebaofast", "lightspeedsystems", "likse", "linkscan", "linkwalker", "linkbot", "linkdexbot", "linkextractorpro", "linkpadbot", "linksmanager", "linqiametadatadownloaderbot", "linqiarssbot", "linqiascrapebot", "lipperhey", "lipperhey spider", "litemage_walker", "lmspider", "ltx71", "mfc_tear_sample", "midown tool", "miixpc", "mj12bot", "mqqbrowser", "msfrontpage", "msiecrawler", "mtrobot", "mag-net", "magnet", "mail.ru_bot", "majestic-seo", "majestic12", "majestic seo", "markmonitor", "markwatch", "mass downloader", "masscan", "mata hari", "mauibot", "mb2345browser", "meanpath bot", "meanpathbot", "mediatoolkitbot", "megaindex.ru", "metauri", "micromessenger", "microsoft data access", "microsoft url control", "minefield", "mister pix", "moblie safari", "mojeek", "mojolicious", "molokaibot", "morfeus fucking scanner", "mozlila", "mr.4x3", "msrabot", "musobot", "nicerspro", "npbot", "name intelligence", "nameprotect", "navroad", "nearsite", "needle", "nessus", "netants", "netlyzer", "netmechanic", "netspider", "netzip", "net vampire", "netcraft", "nettrack", "netvibes", "nextgensearchbot", "nibbler", "niki-bot", "nikto", "nimblecrawler", "nimbostratus", "ninja", "nmap", "not", "nuclei", "nutch", "octopus", "offline explorer", "offline navigator", "oncrawl", "openlinkprofiler", "openvas", "openfind", "openvas", "orangebot", "orangespider", "outclicksbot", "outfoxbot", "pecl::http", "phpcrawl", "poe-component-client-http", "pageanalyzer", "pagegrabber", "pagescorer", "pagething.com", "page analyzer", "pandalytics", "panscient", "papa foto", "pavuk", "peoplepal", "petalbot", "pi-monster", "picscout", "picsearch", "picturefinder", "piepmatz", "pimonster", "pixray", "pleasecrawl", "pockey", "propowerbot", "prowebwalker", "probethenet", "psbot", "pu_in", "pump", "pxbroker", "pycurl", "queryn metasearch", "quick-crawler", "rssingbot", "rankactive", "rankactivelinkbot", "rankflex", "rankingbot", "rankingbot2", "rankivabot", "rankurbot", "re-re", "reget", "realdownload", "reaper", "rebelmouse", "recorder", "redesscrapy", "repomonkey", "ripper", "rocketcrawler", "rogerbot", "sbider", "seokicks", "seokicks-robot", "seolyticscrawler", "seoprofiler", "seostats", "sistrix", "smtbot", "salesintelligent", "scanalert", "scanbot", "scoutjet", "scrapy", "screaming", "screenerbot", "screpybot", "searchestate", "searchmetricsbot", "seekport", "semanticjuice", "semrush", "semrushbot", "sentibot", "seositecheckup", "seobilitybot", "seomoz", "shodan", "siphon", "sitecheckerbotcrawler", "siteexplorer", "sitelockspider", "sitesnagger", "sitesucker", "site sucker", "sitebeam", "siteimprove", "sitevigil", "slysearch", "smartdownload", "snake", "snapbot", "snoopy", "socialrankiobot", "sociscraper", "sogou web spider", "sosospider", "sottopop", "spacebison", "spammen", "spankbot", "spanner", "spbot", "spinn3r", "sputnikbot", "sqlmap", "sqlworm", "sqworm", "steeler", "stripper", "sucker", "sucuri", "superbot", "superhttp", "surfbot", "surveybot", "suzuran", "swiftbot", "szukacz", "t0phackteam", "t8abot", "teleport", "teleportpro", "telesoft", "telesphoreo", "telesphorep", "thenomad", "the intraformant", "thumbor", "tighttwatbot", "titan", "toata", "toweyabot", "tracemyfile", "trendiction", "trendictionbot", "true_robot", "turingos", "turnitin", "turnitinbot", "twengabot", "twice", "typhoeus", "urly.warning", "urly warning", "unisterbot", "upflow", "v-bot", "vb project", "vci", "vacuum", "vagabondo", "velenpublicwebcrawler", "vericitecrawler", "vidiblescraper", "virusdie", "voideye", "voil", "voltron", "wasalive-bot", "wbsearchbot", "webdav", "wisenutbot", "wpscan", "www-collector-e", "www-mechanize", "www::mechanize", "wwwoffle", "wallpapers", "wallpapers/3.0", "wallpapershd", "wesee", "webauto", "webbandit", "webcollage", "webcopier", "webenhancer", "webfetch", "webfuck", "webgo is", "webimagecollector", "webleacher", "webpix", "webreaper", "websauger", "webstripper", "websucker", "webwhacker", "webzip", "web auto", "web collage", "web enhancer", "web fetch", "web fuck", "web pix", "web sauger", "web sucker", "webalta", "webmasterworldforumbot", "webshag", "websiteextractor", "websitequester", "website quester", "webster", "whack", "whacker", "whatweb", "who.is bot", "widow", "winhttrack", "wiseguys robot", "wonderbot", "woobot", "wotbox", "wprecon", "xaldon webspider", "xaldon_webspider", "xenu", "youdaobot", "zade", "zauba", "zermelo", "zeus", "zitebot", "zmeu", "zoombot", "zoominfobot", "zumbot", "zyborg", "adscanner", "archive.org_bot", "arquivo-web-crawler", "arquivo.pt", "autoemailspider", "backlink-check", "cah.io.community", "check1.exe", "clark-crawler", "coccocbot", "cognitiveseo", "com.plumanalytics", "crawl.sogou.com", "crawler.feedback", "crawler4j", "dataforseo.com", "demandbase-bot", "domainsproject.org", "ecatch", "evc-batch", "facebookscraper", "gopher", "heritrix", "instabid", "internetvista monitor", "ips-agent", "isitwp.com", "iubenda-radar", "lwp-request", "lwp-trivial", "magpie-crawler", "meanpathbot", "mediawords", "muhstik-scan", "netestate ne crawler", "obot", "page scorer", "pcbrowser", "plumanalytics", "polaris version", "probe-image-size", "ripz", "s1z.ru", "satoristudio.net", "scalaj-http", "scan.lol", "seobility", "seocompany.store", "seoscanners", "seostar", "serpstatbot", "sexsearcher", "sitechecker.pro", "siteripz", "sogouspider", "sp_auditbot", "spyfu", "sysscan", "takeout", "trendiction.com", "trendiction.de", "ubermetrics-technologies.com", "voyagerx.com", "webgains-bot", "webmeup-crawler", "webpros.com", "webprosbot", "x09mozilla", "x22mozilla", "xpymep1.exe", "zauba.io", "zgrab"}
	emailMap         = cmap.New()
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
	URL     string `json:"url"`
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

func emailPresent(email string) bool {
	if !emailMap.Has(email) {
		if emailMap.Count() > mapSize {
			emailMap.Clear()
		}
		emailMap.Set(email, "")
		return false
	}
	return true
}

func sendSlack(d *submit) error {
	payload := slackItem{
		Text:        fmt.Sprintf("URL: %s, Name: %s, Email: %s, Message: %s, Browser: %s, Mobile: %t, Country: %s, City: %s, State: %s", d.URL, d.Name, d.Email, d.Message, d.Browser, d.Mobile, d.Country, d.City, d.State),
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
	loc := &location{}

	db, err := geoip2.Open(geolite)
	if err != nil {
		return loc, err
	}

	defer db.Close()

	parseIP := net.ParseIP(ip)
	record, err := db.City(parseIP)
	if err != nil {
		return loc, err
	}

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

	if name != "" && email != "" {
		emailDomain := strings.Split(email, "@")[1]
		for _, e := range blackListDomains {
			if strings.Contains(strings.ToLower(emailDomain), e) {
				return c.Redirect(301, redirect)
			}
		}

		if emailPresent(email) {
			return c.Redirect(301, redirect)
		}

		agent := c.Request().Header.Get("User-Agent")
		var data *submit
		ua := user_agent.New(agent)

		browser, _ := ua.Browser()
		for _, e := range blackListDomains {
			if strings.Contains(strings.ToLower(browser), e) {
				return c.Redirect(301, redirect)
			}
		}

		mobile := ua.Mobile()

		loc, err := findLocation(c.RealIP())
		if err != nil {
			log.Println(err)
		}

		url := c.Request().Host + c.Request().URL.String()

		data = &submit{Name: name, Email: email, Message: message, Browser: browser, Mobile: mobile, City: loc.City, State: loc.State, Country: loc.Country, URL: url}

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
