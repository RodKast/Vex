package crawler

import (
	"bytes"
	"context"
	"net/url"
	"strings"

	"github.com/RodKast/Vex/internal/engine"
	"github.com/RodKast/Vex/pkg/types"
	"golang.org/x/net/html"
)

type Crawler struct {
	engine  *engine.Engine
	config  types.Config
	visited map[string]bool
	points  []types.InjectionPoint
}

func NewCrawler(eng *engine.Engine, config types.Config) *Crawler {
	return &Crawler{
		engine:  eng,
		config:  config,
		visited: make(map[string]bool),
		points:  []types.InjectionPoint{},
	}

}

func (c *Crawler) Crawl(ctx context.Context, startURL string) []types.InjectionPoint {
	queue := []string{startURL}

	for len(queue) > 0 {
		// pop first item
		url := queue[0]
		queue = queue[1:]

		// skip if visited
		if c.visited[url] {
			continue
		}
		c.visited[url] = true
		c.extractQueryParams(url)

		// fetch
		resp := c.engine.Do(ctx, types.Request{URL: url, Method: "GET"})
		if resp.Error != nil {
			continue
		}

		// parse (we'll write this next)
		newLinks := c.parse(ctx, url, resp.Body)
		queue = append(queue, newLinks...)
	}

	return c.points
}

func (c *Crawler) parse(ctx context.Context, baseURL string, body []byte) []string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var links []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					base, err := url.Parse(baseURL)
					if err != nil {
						continue
					}
					ref, err := url.Parse(attr.Val)
					if err != nil {
						continue
					}
					resolved := base.ResolveReference(ref).String()
					if strings.Contains(resolved, c.config.Target) {
						links = append(links, resolved)
					}
				}
			}
		} else if n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				if attr.Key == "name" {
					name = attr.Val
				} else if attr.Key == "value" {
					value = attr.Val
				}
			}
			if name != "" {
				c.points = append(c.points, types.InjectionPoint{
					URL:           baseURL,
					Parameter:     name,
					Type:          "form",
					Method:        "POST",
					OriginalValue: value,
				})
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	return links
}

func (c *Crawler) extractQueryParams(rawURL string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	for param, vals := range parsed.Query() {
		c.points = append(c.points, types.InjectionPoint{
			URL:           rawURL,
			Parameter:     param,
			Type:          "query",
			Method:        "GET",
			OriginalValue: vals[0],
		})
	}
}
