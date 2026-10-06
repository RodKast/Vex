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
		u := queue[0]
		queue = queue[1:]

		if c.visited[u] {
			continue
		}
		c.visited[u] = true
		c.extractQueryParams(u)

		resp := c.engine.Do(ctx, types.Request{URL: u, Method: "GET"})
		if resp.Error != nil {
			continue
		}

		newLinks := c.parse(ctx, u, resp.Body)
		queue = append(queue, newLinks...)
	}

	return c.points
}

func (c *Crawler) parse(_ context.Context, baseURL string, body []byte) []string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var links []string

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						base, err := url.Parse(baseURL)
						if err != nil {
							break
						}
						ref, err := url.Parse(attr.Val)
						if err != nil {
							break
						}
						resolved := base.ResolveReference(ref).String()
						if strings.Contains(resolved, c.config.Target) {
							links = append(links, resolved)
						}
					}
				}
			case "form":
				method := "GET"
				for _, attr := range n.Attr {
					if attr.Key == "method" && strings.ToUpper(attr.Val) == "POST" {
						method = "POST"
					}
				}
				formInputs := collectFormInputs(n)
				for _, input := range formInputs {
					others := map[string]string{}
					for _, other := range formInputs {
						if other.name != input.name {
							others[other.name] = other.value
						}
					}
					c.points = append(c.points, types.InjectionPoint{
						URL:           baseURL,
						Parameter:     input.name,
						Type:          "form",
						Method:        method,
						OriginalValue: input.value,
						FormParams:    others,
					})
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	return links
}

type formInput struct {
	name  string
	value string
}

func collectFormInputs(formNode *html.Node) []formInput {
	var inputs []formInput
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			var name, value string
			for _, attr := range n.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				}
			}
			if name != "" {
				inputs = append(inputs, formInput{name: name, value: value})
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(formNode)
	return inputs
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
