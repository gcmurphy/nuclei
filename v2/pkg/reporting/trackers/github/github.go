package github

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/google/go-github/github"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/dedupe"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	client  *github.Client
	options *Options
}

// Options contains the configuration options for GitHub issue tracker client
type Options struct {
	// BaseURL (optional) is the self-hosted GitHub application url
	BaseURL string `yaml:"base-url" validate:"omitempty,url"`
	// Username is the username of the github user
	Username string `yaml:"username" validate:"required"`
	// Owner is the owner name of the repository for issues.
	Owner string `yaml:"owner" validate:"required"`
	// Token is the token for GitHub account.
	Token string `yaml:"token" validate:"required"`
	// ProjectName is the name of the repository.
	ProjectName string `yaml:"project-name" validate:"required"`
	// IssueLabel (optional) is the label of the created issue type
	IssueLabel string `yaml:"issue-label"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
	// Dedupe avoids creating duplicate issues by searching Github for existing
	// issues with the same fingerprint
	Dedupe bool `yaml:"dedupe-issues"`

	HttpClient *retryablehttp.Client `yaml:"-"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: options.Token},
	)
	tc := oauth2.NewClient(ctx, ts)

	// patch transport to support proxy - only http
	// TODO: investigate if it's possible to reuse existing retryablehttp
	if types.ProxyURL != "" {
		if proxyURL, err := url.Parse(types.ProxyURL); err == nil {
			tc.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := github.NewClient(tc)
	if options.BaseURL != "" {
		parsed, err := url.Parse(options.BaseURL)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse custom baseurl")
		}
		if !strings.HasSuffix(parsed.Path, "/") {
			parsed.Path += "/"
		}
		client.BaseURL = parsed
	}
	return &Integration{client: client, options: options}, nil
}

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) error {

	fingerprint := dedupe.NewFingerprint(event)
	summary := format.Summary(event)
	description := format.MarkdownDescription(event)
	if i.options.Dedupe {
		context := context.Background()
		query := fmt.Sprintf("%s in:body repo:%s/%s is:issue", fingerprint.ToString(), i.options.Owner, i.options.ProjectName)
		issues, _, err := i.client.Search.Issues(context, query, nil)
		if err != nil {
			return err
		}
		if issues.GetTotal() > 0 {
			log.Printf("skipping creation of issue for match for %s on %s as github issue: %s already exists", event.TemplateID, event.Host, *issues.Issues[0].HTMLURL)
			return nil
		}
		description = fmt.Sprintf("%s\n\n\n%s", description, fingerprint.ToString())
	}

	labels := []string{}
	severityLabel := fmt.Sprintf("Severity: %s", event.Info.SeverityHolder.Severity.String())
	if i.options.SeverityAsLabel && severityLabel != "" {
		labels = append(labels, severityLabel)
	}
	if label := i.options.IssueLabel; label != "" {
		labels = append(labels, label)
	}

	req := &github.IssueRequest{
		Title:     &summary,
		Body:      &description,
		Labels:    &labels,
		Assignees: &[]string{i.options.Username},
	}
	_, _, err := i.client.Issues.Create(context.Background(), i.options.Owner, i.options.ProjectName, req)
	return err
}
