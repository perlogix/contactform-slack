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
	blackListAgents  = []string{"01h4x.com", "360Spider", "404checker", "404enemy", "80legs", "ADmantX", "AIBOT", "ALittle Client", "ASPSeek", "Abonti", "Aboundex", "Aboundexbot", "Acunetix", "AfD-Verbotsverfahren", "AhrefsBot", "AiHitBot", "Aipbot", "Alexibot", "AllSubmitter", "Alligator", "AlphaBot", "Anarchie", "Anarchy", "Anarchy99", "Ankit", "Anthill", "Apexoo", "Aspiegel", "Asterias", "Atomseobot", "Attach", "AwarioRssBot", "AwarioSmartBot", "BBBike", "BDCbot", "BDFetch", "BLEXBot", "BackDoorBot", "BackStreet", "BackWeb", "Backlink-Ceck", "BacklinkCrawler", "Badass", "Bandit", "Barkrowler", "BatchFTP", "Battleztar Bazinga", "BetaBot", "Bigfoot", "Bitacle", "BlackWidow", "Black Hole", "Blackboard", "Blow", "BlowFish", "Boardreader", "Bolt", "BotALot", "Brandprotect", "Brandwatch", "Buck", "Buddy", "BuiltBotTough", "BuiltWith", "Bullseye", "BunnySlippers", "BuzzSumo", "CATExplorador", "CCBot", "CODE87", "CSHttp", "Calculon", "CazoodleBot", "Cegbfeieh", "CensysInspect", "CheTeam", "CheeseBot", "CherryPicker", "ChinaClaw", "Chlooe", "Citoid", "Claritybot", "Cliqzbot", "Cloud mapping", "Cocolyzebot", "Cogentbot", "Collector", "Copier", "CopyRightCheck", "Copyscape", "Cosmos", "Craftbot", "Crawling at Home Project", "CrazyWebCrawler", "Crescent", "CrunchBot", "Curious", "curl", "Custo", "CyotekWebCopy", "DBLBot", "DIIbot", "DSearch", "DTS Agent", "DataCha0s", "DatabaseDriverMysqli", "Demon", "Deusu", "Devil", "Digincore", "DigitalPebble", "Dirbuster", "Disco", "Discobot", "Discoverybot", "Dispatch", "DittoSpyder", "DnBCrawler-Analytics", "DnyzBot", "DomCopBot", "DomainAppender", "DomainCrawler", "DomainSigmaCrawler", "DomainStatsBot", "Domains Project", "Dotbot", "Download Wonder", "Dragonfly", "Drip", "ECCP/1.0", "EMail Siphon", "EMail Wolf", "EasyDL", "Ebingbong", "Ecxi", "EirGrabber", "EroCrawler", "Evil", "Exabot", "Express WebPictures", "ExtLinksBot", "Extractor", "ExtractorPro", "Extreme Picture Finder", "EyeNetIE", "Ezooms", "FDM", "FHscan", "FemtosearchBot", "Fimap", "Firefox/7.0", "FlashGet", "Flunky", "Foobot", "Freeuploader", "FrontPage", "Fuzz", "FyberSpider", "Fyrebot", "G-i-g-a-b-o-t", "GT::WWW", "GalaxyBot", "Genieo", "GermCrawler", "GetRight", "GetWeb", "Getintent", "Gigabot", "Go!Zilla", "Go-Ahead-Got-It", "GoZilla", "Gotit", "GrabNet", "Grabber", "Grafula", "GrapeFX", "GrapeshotCrawler", "GridBot", "HEADMasterSEO", "HMView", "HTMLparser", "HTTP::Lite", "HTTrack", "Haansoft", "HaosouSpider", "Harvest", "Havij", "Heritrix", "Hloader", "HonoluluBot", "Humanlinks", "HybridBot", "IDBTE4M", "IDBot", "IRLbot", "Iblog", "Id-search", "IlseBot", "Image Fetch", "Image Sucker", "IndeedBot", "Indy Library", "InfoNaviRobot", "InfoTekies", "Intelliseek", "InterGET", "InternetSeer", "Internet Ninja", "Iria", "Iskanie", "IstellaBot", "JOC Web Spider", "JamesBOT", "Jbrofuzz", "JennyBot", "JetCar", "Jetty", "JikeSpider", "Joomla", "Jorgee", "JustView", "Jyxobot", "Kenjin Spider", "Keybot Translation-Search-Machine", "Keyword Density", "Kinza", "Kozmosbot", "LNSpiderguy", "LWP::Simple", "Lanshanbot", "Larbin", "Leap", "LeechFTP", "LeechGet", "LexiBot", "Lftp", "LibWeb", "Libwhisker", "LieBaoFast", "Lightspeedsystems", "Likse", "LinkScan", "LinkWalker", "Linkbot", "Linkdexbot", "LinkextractorPro", "LinkpadBot", "LinksManager", "LinqiaMetadataDownloaderBot", "LinqiaRSSBot", "LinqiaScrapeBot", "Lipperhey", "Lipperhey Spider", "Litemage_walker", "Lmspider", "Ltx71", "MFC_Tear_Sample", "MIDown tool", "MIIxpc", "MJ12bot", "MQQBrowser", "MSFrontPage", "MSIECrawler", "MTRobot", "Mag-Net", "Magnet", "Mail.RU_Bot", "Majestic-SEO", "Majestic12", "Majestic SEO", "MarkMonitor", "MarkWatch", "Mass Downloader", "Masscan", "Mata Hari", "MauiBot", "Mb2345Browser", "MeanPath Bot", "Meanpathbot", "Mediatoolkitbot", "MegaIndex.ru", "Metauri", "MicroMessenger", "Microsoft Data Access", "Microsoft URL Control", "Minefield", "Mister PiX", "Moblie Safari", "Mojeek", "Mojolicious", "MolokaiBot", "Morfeus Fucking Scanner", "Mozlila", "Mr.4x3", "Msrabot", "Musobot", "NICErsPRO", "NPbot", "Name Intelligence", "Nameprotect", "Navroad", "NearSite", "Needle", "Nessus", "NetAnts", "NetLyzer", "NetMechanic", "NetSpider", "NetZIP", "Net Vampire", "Netcraft", "Nettrack", "Netvibes", "NextGenSearchBot", "Nibbler", "Niki-bot", "Nikto", "NimbleCrawler", "Nimbostratus", "Ninja", "Nmap", "Not", "Nuclei", "Nutch", "Octopus", "Offline Explorer", "Offline Navigator", "OnCrawl", "OpenLinkProfiler", "OpenVAS", "Openfind", "Openvas", "OrangeBot", "OrangeSpider", "OutclicksBot", "OutfoxBot", "PECL::HTTP", "PHPCrawl", "POE-Component-Client-HTTP", "PageAnalyzer", "PageGrabber", "PageScorer", "PageThing.com", "Page Analyzer", "Pandalytics", "Panscient", "Papa Foto", "Pavuk", "PeoplePal", "Petalbot", "Pi-Monster", "Picscout", "Picsearch", "PictureFinder", "Piepmatz", "Pimonster", "Pixray", "PleaseCrawl", "Pockey", "ProPowerBot", "ProWebWalker", "Probethenet", "Psbot", "Pu_iN", "Pump", "PxBroker", "PyCurl", "QueryN Metasearch", "Quick-Crawler", "RSSingBot", "RankActive", "RankActiveLinkBot", "RankFlex", "RankingBot", "RankingBot2", "Rankivabot", "RankurBot", "Re-re", "ReGet", "RealDownload", "Reaper", "RebelMouse", "Recorder", "RedesScrapy", "RepoMonkey", "Ripper", "RocketCrawler", "Rogerbot", "SBIder", "SEOkicks", "SEOkicks-Robot", "SEOlyticsCrawler", "SEOprofiler", "SEOstats", "SISTRIX", "SMTBot", "SalesIntelligent", "ScanAlert", "Scanbot", "ScoutJet", "Scrapy", "Screaming", "ScreenerBot", "ScrepyBot", "Searchestate", "SearchmetricsBot", "Seekport", "SemanticJuice", "Semrush", "SemrushBot", "SentiBot", "SeoSiteCheckup", "SeobilityBot", "Seomoz", "Shodan", "Siphon", "SiteCheckerBotCrawler", "SiteExplorer", "SiteLockSpider", "SiteSnagger", "SiteSucker", "Site Sucker", "Sitebeam", "Siteimprove", "Sitevigil", "SlySearch", "SmartDownload", "Snake", "Snapbot", "Snoopy", "SocialRankIOBot", "Sociscraper", "Sogou web spider", "Sosospider", "Sottopop", "SpaceBison", "Spammen", "SpankBot", "Spanner", "Spbot", "Spinn3r", "SputnikBot", "Sqlmap", "Sqlworm", "Sqworm", "Steeler", "Stripper", "Sucker", "Sucuri", "SuperBot", "SuperHTTP", "Surfbot", "SurveyBot", "Suzuran", "Swiftbot", "Szukacz", "T0PHackTeam", "T8Abot", "Teleport", "TeleportPro", "Telesoft", "Telesphoreo", "Telesphorep", "TheNomad", "The Intraformant", "Thumbor", "TightTwatBot", "Titan", "Toata", "Toweyabot", "Tracemyfile", "Trendiction", "Trendictionbot", "True_Robot", "Turingos", "Turnitin", "TurnitinBot", "TwengaBot", "Twice", "Typhoeus", "URLy.Warning", "URLy Warning", "UnisterBot", "Upflow", "V-BOT", "VB Project", "VCI", "Vacuum", "Vagabondo", "VelenPublicWebCrawler", "VeriCiteCrawler", "VidibleScraper", "Virusdie", "VoidEYE", "Voil", "Voltron", "WASALive-Bot", "WBSearchBot", "WEBDAV", "WISENutbot", "WPScan", "WWW-Collector-E", "WWW-Mechanize", "WWW::Mechanize", "WWWOFFLE", "Wallpapers", "Wallpapers/3.0", "WallpapersHD", "WeSEE", "WebAuto", "WebBandit", "WebCollage", "WebCopier", "WebEnhancer", "WebFetch", "WebFuck", "WebGo IS", "WebImageCollector", "WebLeacher", "WebPix", "WebReaper", "WebSauger", "WebStripper", "WebSucker", "WebWhacker", "WebZIP", "Web Auto", "Web Collage", "Web Enhancer", "Web Fetch", "Web Fuck", "Web Pix", "Web Sauger", "Web Sucker", "Webalta", "WebmasterWorldForumBot", "Webshag", "WebsiteExtractor", "WebsiteQuester", "Website Quester", "Webster", "Whack", "Whacker", "Whatweb", "Who.is Bot", "Widow", "WinHTTrack", "WiseGuys Robot", "Wonderbot", "Woobot", "Wotbox", "Wprecon", "Xaldon WebSpider", "Xaldon_WebSpider", "Xenu", "YoudaoBot", "Zade", "Zauba", "Zermelo", "Zeus", "Zitebot", "ZmEu", "ZoomBot", "ZoominfoBot", "ZumBot", "ZyBorg", "adscanner", "archive.org_bot", "arquivo-web-crawler", "arquivo.pt", "autoemailspider", "backlink-check", "cah.io.community", "check1.exe", "clark-crawler", "coccocbot", "cognitiveseo", "com.plumanalytics", "crawl.sogou.com", "crawler.feedback", "crawler4j", "dataforseo.com", "demandbase-bot", "domainsproject.org", "eCatch", "evc-batch", "facebookscraper", "gopher", "heritrix", "instabid", "internetVista monitor", "ips-agent", "isitwp.com", "iubenda-radar", "lwp-request", "lwp-trivial", "magpie-crawler", "meanpathbot", "mediawords", "muhstik-scan", "netEstate NE Crawler", "oBot", "page scorer", "pcBrowser", "plumanalytics", "polaris version", "probe-image-size", "ripz", "s1z.ru", "satoristudio.net", "scalaj-http", "scan.lol", "seobility", "seocompany.store", "seoscanners", "seostar", "serpstatbot", "sexsearcher", "sitechecker.pro", "siteripz", "sogouspider", "sp_auditbot", "spyfu", "sysscan", "tAkeOut", "trendiction.com", "trendiction.de", "ubermetrics-technologies.com", "voyagerx.com", "webgains-bot", "webmeup-crawler", "webpros.com", "webprosbot", "x09Mozilla", "x22Mozilla", "xpymep1.exe", "zauba.io", "zgrab"}
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
			if emailDomain == e {
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
			if browser == e {
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
