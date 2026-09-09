// Package enrich adds context to assets that the registry cannot provide:
// support lifecycle, known vulnerabilities, and exploitation data.
package enrich

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed products.yaml
var catalogYAML []byte

// Catalog maps container repositories to endoflife.date product slugs.
type Catalog struct {
	byRepository map[string]string
}

// catalogFile mirrors the YAML structure.
type catalogFile struct {
	Version  int `yaml:"version"`
	Products []struct {
		Repository string `yaml:"repository"`
		Product    string `yaml:"product"`
	} `yaml:"products"`
}

// LoadCatalog parses the embedded product catalog.
func LoadCatalog() (*Catalog, error) {
	var f catalogFile
	if err := yaml.Unmarshal(catalogYAML, &f); err != nil {
		return nil, fmt.Errorf("parsing product catalog: %w", err)
	}

	c := &Catalog{byRepository: make(map[string]string, len(f.Products))}
	for _, p := range f.Products {
		c.byRepository[strings.ToLower(p.Repository)] = p.Product
	}
	return c, nil
}

// Product returns the endoflife.date slug for a repository. The second
// return value is false when the repository has no known lifecycle data,
// which is common and not an error.
func (c *Catalog) Product(repository string) (string, bool) {
	slug, ok := c.byRepository[strings.ToLower(repository)]
	return slug, ok
}

// Size reports how many mappings the catalog holds.
func (c *Catalog) Size() int { return len(c.byRepository) }
