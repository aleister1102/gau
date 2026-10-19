package flags

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/lynxsecurity/pflag"
	"github.com/lynxsecurity/viper"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

type URLScanConfig struct {
	Host   string `mapstructure:"host"`
	APIKey string `mapstructure:"apikey"`
}

type VirusTotalConfig struct {
	APIKey string `mapstructure:"apikey"`
}

type LeakIXConfig struct {
	APIKey string `mapstructure:"apikey"`
}

type BraveConfig struct {
	APIKey string `mapstructure:"apikey"`
}

type SerpAPIConfig struct {
	APIKey string `mapstructure:"apikey"`
}

type FirecrawlConfig struct {
	APIKey string `mapstructure:"apikey"`
}

type Config struct {
	Filters           providers.Filters `mapstructure:"filters"`
	Proxy             string            `mapstructure:"proxy"`
	Threads           uint              `mapstructure:"threads"`
	Timeout           uint              `mapstructure:"timeout"`
	Verbose           bool              `mapstructure:"verbose"`
	MaxRetries        uint              `mapstructure:"retries"`
	IncludeSubdomains bool              `mapstructure:"subdomains"`
	RemoveParameters  bool              `mapstructure:"parameters"`
	Providers         []string          `mapstructure:"providers"`
	Blacklist         []string          `mapstructure:"blacklist"`
	JSON              bool              `mapstructure:"json"`
	URLScan           URLScanConfig     `mapstructure:"urlscan"`
	OTX               any               `mapstructure:"otx"`
	VirusTotal        VirusTotalConfig  `mapstructure:"virustotal"`
	LeakIX            LeakIXConfig      `mapstructure:"leakix"`
	Brave             BraveConfig       `mapstructure:"brave"`
	SerpAPI           SerpAPIConfig     `mapstructure:"serpapi"`
	Firecrawl         FirecrawlConfig   `mapstructure:"firecrawl"`
	Outfile           string            // output file to write to
}

func (c *Config) ProviderConfig() (*providers.Config, error) {
	var dialer fasthttp.DialFunc

	if c.Proxy != "" {
		parse, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy url: %v", err)
		}
		switch parse.Scheme {
		case "http":
			dialer = fasthttpproxy.FasthttpHTTPDialer(strings.ReplaceAll(c.Proxy, "http://", ""))
		case "socks5":
			dialer = fasthttpproxy.FasthttpSocksDialer(c.Proxy)
		default:
			return nil, fmt.Errorf("unsupported proxy scheme: %s", parse.Scheme)
		}
	}

	urlscanKey := c.URLScan.APIKey
	if urlscanKey == "" {
		if k := os.Getenv("URLSCAN_APIKEY"); k != "" {
			urlscanKey = k
		} else if k := os.Getenv("URLSCAN_API_KEY"); k != "" {
			urlscanKey = k
		}
	}

	otxCfg := normalizeOTXConfig(c.OTX)
	if otxCfg.APIKey == "" {
		if k := os.Getenv("OTX_APIKEY"); k != "" {
			otxCfg.APIKey = k
		} else if k := os.Getenv("OTX_API_KEY"); k != "" {
			otxCfg.APIKey = k
		}
	}

	vtKey := c.VirusTotal.APIKey
	if vtKey == "" {
		if k := os.Getenv("VIRUSTOTAL_APIKEY"); k != "" {
			vtKey = k
		} else if k := os.Getenv("VT_API_KEY"); k != "" {
			vtKey = k
		}
	}

	leakixKey := c.LeakIX.APIKey
	if leakixKey == "" {
		if k := os.Getenv("LEAKIX_APIKEY"); k != "" {
			leakixKey = k
		} else if k := os.Getenv("LEAKIX_API_KEY"); k != "" {
			leakixKey = k
		}
	}

	braveKey := c.Brave.APIKey
	if braveKey == "" {
		if k := os.Getenv("BRAVE_APIKEY"); k != "" {
			braveKey = k
		} else if k := os.Getenv("BRAVE_API_KEY"); k != "" {
			braveKey = k
		}
	}

	serpAPIKey := c.SerpAPI.APIKey
	if serpAPIKey == "" {
		if k := os.Getenv("SERPAPI_APIKEY"); k != "" {
			serpAPIKey = k
		} else if k := os.Getenv("SERPAPI_API_KEY"); k != "" {
			serpAPIKey = k
		}
	}

	firecrawlKey := c.Firecrawl.APIKey
	if firecrawlKey == "" {
		if k := os.Getenv("FIRECRAWL_APIKEY"); k != "" {
			firecrawlKey = k
		} else if k := os.Getenv("FIRECRAWL_API_KEY"); k != "" {
			firecrawlKey = k
		}
	}

	pc := &providers.Config{
		Threads:           c.Threads,
		Timeout:           c.Timeout,
		MaxRetries:        c.MaxRetries,
		IncludeSubdomains: c.IncludeSubdomains,
		RemoveParameters:  c.RemoveParameters,
		Client: &fasthttp.Client{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			Dial: dialer,
		},
		Providers: c.Providers,
		Output:    c.Outfile,
		JSON:      c.JSON,
		URLScan: providers.URLScan{
			Host:   c.URLScan.Host,
			APIKey: urlscanKey,
		},
		OTX: otxCfg,
		VirusTotal: providers.VirusTotalConfig{
			APIKey: vtKey,
		},
		LeakIX: providers.LeakIXConfig{
			APIKey: leakixKey,
		},
		Brave: providers.BraveConfig{
			APIKey: braveKey,
		},
		SerpAPI: providers.SerpAPIConfig{
			APIKey: serpAPIKey,
		},
		Firecrawl: providers.FirecrawlConfig{
			APIKey: firecrawlKey,
		},
	}

	log.SetLevel(log.ErrorLevel)
	if c.Verbose {
		log.SetLevel(log.InfoLevel)
	}
	pc.Blacklist = mapset.NewThreadUnsafeSet(c.Blacklist...)
	pc.Blacklist.Add("")
	return pc, nil
}

func normalizeOTXConfig(raw any) providers.OTXConfig {
	switch v := raw.(type) {
	case nil:
		return providers.OTXConfig{}
	case providers.OTXConfig:
		return v
	case *providers.OTXConfig:
		if v == nil {
			return providers.OTXConfig{}
		}
		return *v
	case string:
		return providers.OTXConfig{BaseURL: strings.TrimSpace(v)}
	case []byte:
		return providers.OTXConfig{BaseURL: strings.TrimSpace(string(v))}
	case fmt.Stringer:
		return providers.OTXConfig{BaseURL: strings.TrimSpace(v.String())}
	case map[string]string:
		return parseOTXMapString(v)
	case map[string]any:
		converted := make(map[string]string, len(v))
		for key, val := range v {
			converted[key] = fmt.Sprint(val)
		}
		return parseOTXMapString(converted)
	case map[any]any:
		converted := make(map[string]string, len(v))
		for key, val := range v {
			converted[fmt.Sprint(key)] = fmt.Sprint(val)
		}
		return parseOTXMapString(converted)
	default:
		return providers.OTXConfig{BaseURL: strings.TrimSpace(fmt.Sprint(v))}
	}
}

func parseOTXMapString(values map[string]string) providers.OTXConfig {
	cfg := providers.OTXConfig{}
	for key, value := range values {
		switch strings.ToLower(strings.ReplaceAll(key, "_", "")) {
		case "baseurl", "url", "host", "endpoint":
			cfg.BaseURL = strings.TrimSpace(value)
		case "apikey", "key", "token":
			cfg.APIKey = strings.TrimSpace(value)
		}
	}
	return cfg
}

type Options struct {
	viper *viper.Viper
}

func New() *Options {
	v := viper.New()

	pflag.String("o", "", "filename to write results to")
	pflag.String("config", "", "location of config file (default $HOME/.gau.toml, $HOME/.config/gau/config.toml or %USERPROFILE%\\.gau.toml)")
	pflag.Uint("threads", 1, "number of workers to spawn")
	pflag.Uint("timeout", 45, "timeout (in seconds) for HTTP client")
	pflag.Uint("retries", 0, "retries for HTTP client")
	pflag.String("proxy", "", "http proxy to use")
	pflag.StringSlice("blacklist", []string{}, "list of extensions to skip")
	pflag.StringSlice("providers", []string{}, "list of providers to use (wayback,commoncrawl,otx,urlscan,arquivopt,ghostarchive,virustotal,leakix,brave,serpapi,firecrawl)")
	pflag.Bool("subs", false, "include subdomains of target domain")
	pflag.Bool("fp", false, "remove different parameters of the same endpoint")
	pflag.Bool("verbose", false, "show verbose output")
	pflag.Bool("json", false, "output as json")

	// filter flags
	pflag.StringSlice("mc", []string{}, "list of status codes to match")
	pflag.StringSlice("fc", []string{}, "list of status codes to filter")
	pflag.StringSlice("mt", []string{}, "list of mime-types to match")
	pflag.StringSlice("ft", []string{}, "list of mime-types to filter")
	pflag.String("from", "", "fetch urls from date (format: YYYYMM)")
	pflag.String("to", "", "fetch urls to date (format: YYYYMM)")
	pflag.Bool("version", false, "show gau version")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()

	if err := v.BindPFlags(pflag.CommandLine); err != nil {
		log.Fatal(err)
	}

	return &Options{viper: v}
}

func Args() []string {
	return pflag.Args()
}

func (o *Options) ReadInConfig() (*Config, error) {
	confFile := o.viper.GetString("config")

	if confFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return o.DefaultConfig(), err
		}

		candidates := []string{
			filepath.Join(home, ".gau.toml"),
			filepath.Join(home, ".config", "gau", ".gau.toml"),
			filepath.Join(home, ".config", "gau", "config.toml"),
		}
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			candidates = append([]string{
				filepath.Join(xdg, "gau", ".gau.toml"),
				filepath.Join(xdg, "gau", "config.toml"),
			}, candidates...)
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				confFile = candidate
				break
			}
		}

		if confFile == "" {
			confFile = filepath.Join(home, ".gau.toml")
		}
	}

	return o.ReadConfigFile(confFile)
}

func (o *Options) ReadConfigFile(name string) (*Config, error) {
	if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
		return o.DefaultConfig(), fmt.Errorf("Config file %s not found, using default config", name)
	}

	o.viper.SetConfigFile(name)

	if err := o.viper.ReadInConfig(); err != nil {
		return o.DefaultConfig(), err
	}

	var c Config

	if err := o.viper.Unmarshal(&c); err != nil {
		return o.DefaultConfig(), err
	}

	o.getFlagValues(&c)

	return &c, nil
}

func (o *Options) DefaultConfig() *Config {
	c := &Config{
		Filters:           providers.Filters{},
		Proxy:             "",
		Timeout:           45,
		Threads:           1,
		Verbose:           false,
		MaxRetries:        5,
		IncludeSubdomains: false,
		RemoveParameters:  false,
		Providers:         []string{"wayback", "commoncrawl", "otx", "arquivopt", "ghostarchive", "virustotal", "leakix", "brave", "serpapi", "firecrawl"},
		Blacklist:         []string{},
		JSON:              false,
		Outfile:           "",
	}

	o.getFlagValues(c)

	return c
}

func (o *Options) getFlagValues(c *Config) {
	version := o.viper.GetBool("version")
	verbose := o.viper.GetBool("verbose")
	json := o.viper.GetBool("json")
	retries := o.viper.GetUint("retries")
	proxy := o.viper.GetString("proxy")
	outfile := o.viper.GetString("o")
	fetchers := o.viper.GetStringSlice("providers")
	threads := o.viper.GetUint("threads")
	blacklist := o.viper.GetStringSlice("blacklist")
	subs := o.viper.GetBool("subs")
	fp := o.viper.GetBool("fp")

	if version {
		fmt.Printf("gau version: %s\n", providers.Version)
		os.Exit(0)
	}

	if proxy != "" {
		c.Proxy = proxy
	}

	if outfile != "" {
		c.Outfile = outfile
	}
	// set if --threads flag is set, otherwise use default
	if threads > 1 {
		c.Threads = threads
	}

	// set if --blacklist flag is specified, otherwise use default
	if len(blacklist) > 0 {
		c.Blacklist = blacklist
	}

	// set if --providers flag is specified, otherwise use default
	if len(fetchers) > 0 {
		c.Providers = fetchers
	}

	if retries > 0 {
		c.MaxRetries = retries
	}

	if subs {
		c.IncludeSubdomains = subs
	}

	if fp {
		c.RemoveParameters = fp
	}

	c.JSON = json
	c.Verbose = verbose

	// get filter flags
	mc := o.viper.GetStringSlice("mc")
	fc := o.viper.GetStringSlice("fc")
	mt := o.viper.GetStringSlice("mt")
	ft := o.viper.GetStringSlice("ft")
	from := o.viper.GetString("from")
	to := o.viper.GetString("to")

	var seenFilterFlag bool

	var filters providers.Filters
	if len(mc) > 0 {
		seenFilterFlag = true
		filters.MatchStatusCodes = mc
	}

	if len(fc) > 0 {
		seenFilterFlag = true
		filters.FilterStatusCodes = fc
	}

	if len(mt) > 0 {
		seenFilterFlag = true
		filters.MatchMimeTypes = mt
	}

	if len(ft) > 0 {
		seenFilterFlag = true
		filters.FilterMimeTypes = ft
	}

	if from != "" {
		seenFilterFlag = true
		if _, err := time.Parse("200601", from); err == nil {
			filters.From = from
		}
	}

	if to != "" {
		seenFilterFlag = true
		if _, err := time.Parse("200601", to); err == nil {
			filters.To = to
		}
	}

	if seenFilterFlag {
		c.Filters = filters
	}
}
