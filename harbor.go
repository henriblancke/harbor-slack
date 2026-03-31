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
	url := fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true&page_size=100&q=%s",
		c.BaseURL, url.PathEscape(projectName), url.PathEscape(repoName), url.QueryEscape("tags=*"))
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
	// ShouldNotify is true when this digest should send a notification.
	// For multi-arch images only the lexicographically smallest child digest
	// sends, so all pods deterministically agree without shared state.
	// Always true for single-arch images or when the parent cannot be resolved.
	ShouldNotify bool
}

// GetArtifactInfo returns tag names and parent digest for an artifact identified by digest.
// For multi-arch images where the platform artifact has no tags, it finds the
// parent manifest list that references this digest and returns its tags and digest.
func (c *HarborClient) GetArtifactInfo(projectName, repoName, digest string) (*ArtifactInfo, error) {
	artifact, err := c.getArtifact(projectName, repoName, digest)
	if err != nil {
		return nil, err
	}

	// If the artifact has tags directly, it's a single-arch image — always notify.
	if len(artifact.Tags) > 0 {
		return &ArtifactInfo{Tags: extractTags(artifact.Tags), ShouldNotify: true}, nil
	}

	// No tags — this is likely a platform-specific manifest in a multi-arch image.
	// Search for a tagged parent manifest list that references this digest.
	artifacts, err := c.listArtifacts(projectName, repoName)
	if err != nil {
		return nil, fmt.Errorf("searching for parent manifest: %w", err)
	}

	for _, a := range artifacts {
		if len(a.Tags) == 0 || len(a.References) == 0 {
			continue
		}
		for _, ref := range a.References {
			if ref.ChildDigest == digest {
				return &ArtifactInfo{
					Tags:         extractTags(a.Tags),
					ParentDigest: a.Digest,
					ShouldNotify: isSmallestDigest(digest, a.References),
				}, nil
			}
		}
	}

	// No parent found — send anyway as a fallback.
	return &ArtifactInfo{ShouldNotify: true}, nil
}

// isSmallestDigest returns true if digest is the lexicographically smallest
// child digest in refs. This provides a deterministic way for all pods to
// agree on which child sends the notification without shared state.
func isSmallestDigest(digest string, refs []HarborReference) bool {
	for _, ref := range refs {
		if ref.ChildDigest < digest {
			return false
		}
	}
	return true
}

func extractTags(tags []HarborTag) []string {
	result := make([]string, len(tags))
	for i, t := range tags {
		result[i] = t.Name
	}
	return result
}
