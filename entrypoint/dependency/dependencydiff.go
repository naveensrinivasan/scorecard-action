package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type DependencyDiff struct {
	ChangeType          string `json:"change_type"`
	Manifest            string `json:"manifest"`
	Ecosystem           string `json:"ecosystem"`
	Name                string `json:"name"`
	Version             string `json:"version"`
	PackageURL          string `json:"package_url"`
	License             string `json:"license"`
	SourceRepositoryURL string `json:"source_repository_url"`
}

func main() {
	os.Setenv("SCORECARD_IGNORE_LIST", "ignores.json")
	os.Setenv("SCORECARD_CHECKS", "checks.json")
	ghToken := os.Getenv("GITHUB_TOKEN")
	fmt.Println(ghToken)
	repoLocation := os.Getenv("SCORECARD_REPO_LOCATION")
	ignoreList, err := GetIgnoreList()
	if err != nil {
		panic(err)
	}
	checks, err := GetScorecardChecks()
	fmt.Println(checks)
	if err != nil {
		panic(err)
	}
	// Get the commit SHA
	commitSHA, err := getCommitSHA(repoLocation)
	if err != nil {
		panic(err)
	}

	// Get the dependency diff
	data, err := GetDependencyDiff("naveensrinivasan", "scorecard-action", ghToken, "HEAD", commitSHA)
	m := make(map[string]DependencyDiff)
	if err != nil {
		panic(err)
	}
	data = filter(data, func(dep DependencyDiff) bool {
		for _, ignore := range ignoreList {
			if dep.SourceRepositoryURL == ignore {
				return false
			}
		}
		return true
	})
	for _, dep := range data {
		m[dep.SourceRepositoryURL] = dep
	}
	do(m, checks)
}

func do(m map[string]DependencyDiff, checks []string) {
	for k, _ := range m {
		url := strings.TrimPrefix(k, "https://")
		scorecard, error := GetScore(url)
		if error != nil {
			fmt.Println(error)
			continue
		}
		scorecard.Checks = filter(scorecard.Checks, func(check Check) bool {
			for _, c := range checks {
				if check.Name == c {
					return true
				}
			}
			return false
		})
		result := WriteGitHubIssueComment(scorecard)
		fmt.Println(result)
	}
}

func WriteGitHubIssueComment(checks ScorecardResult) string {
	sb := strings.Builder{}
	for _, check := range checks.Checks {
		// Write the score as a GitHub issue comment as HTML so that it can be rendered
		// as a table
		//append all of this to a string builder
		//write a header with <details> and <summary> tags
		sb.WriteString(fmt.Sprintf("<details><summary>%s</summary>\n", "Sccorecard"))
		sb.WriteString(fmt.Sprintf("Check: %s, Score: %d\n", check.Name, check.Score))
		sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", check.Name, check.Score))
	}
	sb.WriteString("</details>")
	return sb.String()
}

// getCommitSHA returns the commit SHA of the current branch.
// This assumes that there is git executable in the path.
func getCommitSHA(dir string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	if dir != "" {
		cmd.Dir = dir
	}
	// Capture the output of the command
	var out bytes.Buffer
	cmd.Stdout = &out

	// Run the command
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to get commit SHA: %w", err)
	}
	//remove the trailing newline
	return out.String()[:len(out.String())-1], nil
}
func GetDependencyDiff(owner, repo, token, base, head string) ([]DependencyDiff, error) {
	if owner == "" {
		return nil, fmt.Errorf("owner is required")
	}
	if repo == "" {
		return nil, fmt.Errorf("repo is required")
	}
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}
	resp, err := GetGitHubData(owner, repo, token, base, head)
	if err != nil {
		return nil, err
	}
	var data []DependencyDiff
	err = json.NewDecoder(resp.Body).Decode(&data)

	if err != nil {
		//read the body
		message, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode response: %w , %s, %s", err, resp.Status, string(message))
	}
	// filter out the dependencies that are not added
	var filteredData []DependencyDiff
	for _, dep := range data {
		// also if the source repo doesn't start with GitHub.com, we can ignore it
		if dep.ChangeType == "added" && dep.SourceRepositoryURL != "" && strings.HasPrefix(dep.SourceRepositoryURL, "https://github.com") {
			filteredData = append(filteredData, dep)
		}
	}
	return filteredData, nil
}
func GetGitHubData(owner string, repo string, token string, base string, head string) (*http.Response, error) {
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://api.github.com/repos/%s/%s/dependency-graph/compare/%s...%s", owner, repo, base, head), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
		// handle err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		//
		return nil, err
	}
	return resp, nil
}
func filter[T any](slice []T, f func(T) bool) []T {
	var n []T
	for _, e := range slice {
		if f(e) {
			n = append(n, e)
		}
	}
	return n
}

// GetIgnoreList returns the list of repositories to ignore.
// This uses the IGNORE_LIST environment variable to get the path to the ignore list.
func GetIgnoreList() ([]string, error) {
	fileName := os.Getenv("SCORECARD_IGNORE_LIST")
	//check if the file exists
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return nil, nil
	}
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	var ignoreListFromFile []string
	err = decoder.Decode(&ignoreListFromFile)
	if err != nil {
		return nil, err
	}
	return ignoreListFromFile, nil
}

// GetScorecardChecks returns a list of checks to run from SCORECARD_CHECKS
// if the file does not exist, or it is empty, it returns nil
// if the file contains a list of checks, it returns that list
func GetScorecardChecks() ([]string, error) {
	fileName := os.Getenv("SCORECARD_CHECKS")
	//check if the file exists
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return nil, nil
	}
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	var checksFromFile []string
	err = decoder.Decode(&checksFromFile)
	if err != nil {
		return nil, err
	}
	return checksFromFile, nil
}

type ScorecardResult struct {
	Date string `json:"date"`
	Repo struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"repo"`
	Scorecard struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"scorecard"`
	Score  float64 `json:"score"`
	Checks []Check `json:"checks"`
}
type Check struct {
	Name          string   `json:"name"`
	Score         int      `json:"score,omitempty"`
	Reason        string   `json:"reason"`
	Details       []string `json:"details"`
	Documentation struct {
		Short string `json:"short"`
		Url   string `json:"url"`
	} `json:"documentation"`
}

func GetScore(repo string) (ScorecardResult, error) {
	fmt.Println(repo)
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.securityscorecards.dev/projects/%s", repo), nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ScorecardResult{}, err
	}
	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ScorecardResult{}, err
	}
	var scorecard ScorecardResult
	err = json.Unmarshal(result, &scorecard)
	if err != nil {
		return ScorecardResult{}, err
	}
	return scorecard, nil
}
