package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HarborClient struct {
	BaseURL  string
	Username string
	Password string
	HTTP     *http.Client
}

type HarborProject struct {
	ProjectID int    `json:"project_id"`
	Name      string `json:"name"`
}

type HarborArtifact struct {
	Digest     string            `json:"digest"`
	Tags       []HarborTag       `json:"tags"`
	References []HarborReference `json:"references"`
}

type HarborTag struct {
	Name string `json:"name"`
}

type HarborReference struct {
	ChildDigest string `json:"child_digest"`
}

func NewHarborClient(baseURL, username, password string) *HarborClient {
	return &HarborClient{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		Username: username,
		Password: password,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *HarborClient) do(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	return c.HTTP.Do(req)
}

// GetProjectID returns the numeric project ID for a project name.
func (c *HarborClient) GetProjectID(projectName string) (int, error) {
	url := fmt.Sprintf("%s/api/v2.0/projects/%s", c.BaseURL, url.PathEscape(projectName))
	resp, err := c.do(url)
	if err != nil {
		return 0, fmt.Errorf("get project %s: %w", projectName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("get project %s: status %d", projectName, resp.StatusCode)
	}

	var project HarborProject
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return 0, fmt.Errorf("decode project %s: %w", projectName, err)
	}
	return project.ProjectID, nil
}

// getArtifact fetches a single artifact by digest.
func (c *HarborClient) getArtifact(projectName, repoName, digest string) (*HarborArtifact, error) {
	url := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s?with_tag=true",
		c.BaseURL, url.PathEscape(projectName), url.PathEscape(repoName), url.PathEscape(digest))
	resp, err := c.do(url)
	if err != nil {
		return nil, fmt.Errorf("get artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get artifact: status %d", resp.StatusCode)
	}

	var artifact HarborArtifact
	if err := json.NewDecoder(resp.Body).Decode(&artifact); err != nil {
		return nil, fmt.Errorf("decode artifact: %w", err)
	}
	return &artifact, nil
}

// listArtifacts lists all artifacts in a repository with tags.
func (c *HarborClient) listArtifacts(projectName, repoName string) ([]HarborArtifact, error) {
	url := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true&page_size=100",
		c.BaseURL, url.PathEscape(projectName), url.PathEscape(repoName))
	resp, err := c.do(url)
	if err != nil {
		return nil, fmt.Errorf("list artifacts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list artifacts: status %d", resp.StatusCode)
	}

	var artifacts []HarborArtifact
	if err := json.NewDecoder(resp.Body).Decode(&artifacts); err != nil {
		return nil, fmt.Errorf("decode artifacts: %w", err)
	}
	return artifacts, nil
}

// ArtifactInfo holds resolved tag and parent information for an artifact.
type ArtifactInfo struct {
	Tags         []string
	ParentDigest string // non-empty when tags came from a parent manifest list
}

// GetArtifactInfo returns tag names and parent digest for an artifact identified by digest.
// For multi-arch images where the platform artifact has no tags, it finds the
// parent manifest list that references this digest and returns its tags and digest.
func (c *HarborClient) GetArtifactInfo(projectName, repoName, digest string) (*ArtifactInfo, error) {
	artifact, err := c.getArtifact(projectName, repoName, digest)
	if err != nil {
		return nil, err
	}

	// If the artifact has tags directly, return them (no parent).
	if len(artifact.Tags) > 0 {
		return &ArtifactInfo{Tags: extractTags(artifact.Tags)}, nil
	}

	// No tags — this is likely a platform-specific manifest in a multi-arch image.
	// Search for a parent manifest list that references this digest.
	artifacts, err := c.listArtifacts(projectName, repoName)
	if err != nil {
		return nil, fmt.Errorf("searching for parent manifest: %w", err)
	}

	for _, a := range artifacts {
		for _, ref := range a.References {
			if ref.ChildDigest == digest && len(a.Tags) > 0 {
				return &ArtifactInfo{
					Tags:         extractTags(a.Tags),
					ParentDigest: a.Digest,
				}, nil
			}
		}
	}

	return &ArtifactInfo{}, nil
}

func extractTags(tags []HarborTag) []string {
	result := make([]string, len(tags))
	for i, t := range tags {
		result[i] = t.Name
	}
	return result
}
