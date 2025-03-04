import argparse
import csv
import requests
import time
import traceback
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from pathlib import Path

def setup_logging(debug=False):
    """Configure logging with formatting and debug level option"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger('github_analyzer')

class GitHubAnalyzer:
    def __init__(self, token: str, enterprise: Optional[str] = None, enterprise_server_hostname: Optional[str] = None, logger=None):
        self.token = token
        self.enterprise = enterprise
        self.enterprise_server = enterprise_server_hostname is not None
        self.logger = logger or logging.getLogger('github_analyzer')
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        if self.enterprise_server:
            self.graphql_endpoint = f"https://{enterprise_server_hostname}/api/graphql"
            self.rest_endpoint = f"https://{enterprise_server_hostname}/api/v3"
        else:
            self.graphql_endpoint = 'https://api.github.com/graphql'
            self.rest_endpoint = 'https://api.github.com'
    
    def get_ghas_data(self) -> Dict:
        """Fetch GHAS active committers for enterprise with pagination"""
        if not self.enterprise:
            raise ValueError("Enterprise name is required for GHAS analysis")

        all_repos = []
        page = 1
        per_page = 100  # Maximum allowed by GitHub API
        
        while True:
            endpoint = (
                f"{self.rest_endpoint}/enterprises/{self.enterprise}"
                f"/settings/billing/advanced-security"
                f"?per_page={per_page}&page={page}"
            )
            
            try:
                response = requests.get(endpoint, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                
                # Add repositories from current page
                all_repos.extend(data.get('repositories', []))
                
                # Check if there are more pages
                # GitHub uses the Link header for pagination info
                if 'Link' not in response.headers or 'rel="next"' not in response.headers['Link']:
                    break
                    
                page += 1
                
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to fetch GHAS data: {str(e)}")
        
        # Reconstruct the response with all repositories
        return {
            'total_advanced_security_committers': data.get('total_advanced_security_committers', 0),
            'total_count': data.get('total_count', 0),
            'maximum_advanced_security_committers': data.get('maximum_advanced_security_committers', 0),
            'purchased_advanced_security_committers': data.get('purchased_advanced_security_committers', 0),
            'repositories': all_repos
        }

    def fetch_org_repos(self, org: str) -> List[Dict]:
        """Fetch all repositories for a given organization"""
        repos = []
        page = 1
        per_page = 100
        has_more = True
        
        while has_more:
            endpoint = f"{self.rest_endpoint}/orgs/{org}/repos?per_page={per_page}&page={page}"
            
            try:
                response = requests.get(endpoint, headers=self.headers)
                response.raise_for_status()
                repo_batch = response.json()
                
                if not repo_batch:
                    has_more = False
                else:
                    repos.extend(repo_batch)
                    page += 1
                    
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to fetch repos for {org}: {str(e)}")
        
        return repos

    def process_organizations(self, csv_path: str) -> Dict[str, List[str]]:
        """Process organizations from a CSV file and analyze all their repositories"""
        results = {}
        
        if not Path(csv_path).exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        with open(csv_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            if not {'org'}.issubset(set(reader.fieldnames or [])):
                raise ValueError("CSV must contain 'org' column")
                
            for row in reader:
                org = row['org']
                try:
                    print(f"Fetching repositories for {org}...")
                    repos = self.fetch_org_repos(org)
                    print(f"Found {len(repos)} repositories for {org}")
                    
                    # Process each repository in the organization
                    for repo in repos:
                        # Skip archived and forks
                        if repo.get('archived', False) or repo.get('fork', False):
                            continue
                            
                        repo_name = repo['name']
                        repo_key = f"{org}/{repo_name}"
                        
                        try:
                            print(f"Fetching committers for {repo_key}...")
                            committers = self.fetch_repo_committers(org, repo_name)
                            results[repo_key] = committers
                        except Exception as e:
                            print(f"Error processing {repo_key}: {str(e)}")
                            results[repo_key] = []
                            
                except Exception as e:
                    print(f"Error processing organization {org}: {str(e)}")
        
        return results
    
    def fetch_repo_committers(self, owner: str, repo: str) -> List[str]:
        """Fetch all committers for a specific repository in the last 90 days"""
        ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
        committers: Set[str] = set()
        cursor = None
        has_next_page = True
        
        self.logger.debug(f"Starting to fetch committers for {owner}/{repo}")

        query = """
        query RecentCommitters($owner: String!, $repo: String!, $cursor: String) {
            repository(owner: $owner, name: $repo) {
                defaultBranchRef {
                    target {
                        ... on Commit {
                            history(first: 100, since: "%s", after: $cursor) {
                                pageInfo { hasNextPage endCursor }
                                nodes {
                                    author {
                                        name
                                        email
                                        user { login }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """ % ninety_days_ago

        while has_next_page:
            try:
                # # Check rate limit before making the API call
                # rate_limit = self.check_rate_limit()
                # remaining = rate_limit["remaining"]
                # reset_at = rate_limit["resetAt"]
                # self.logger.debug(f"Rate limit check for {owner}/{repo}: {remaining} remaining, resets at {reset_at}")
                
                # if remaining < 1:
                #     reset_time = datetime.fromisoformat(reset_at.replace('Z', '+00:00'))
                #     wait_time = (reset_time - datetime.now(reset_time.tzinfo)).total_seconds()
                    
                #     if wait_time > 0:
                #         self.logger.info(f"API rate limit reached. Waiting {int(wait_time)} seconds until {reset_at}...")
                #         time.sleep(wait_time + 1)  # Add 1 second buffer
                
                self.logger.debug(f"Sending GraphQL request for {owner}/{repo} with cursor: {cursor}")
                response = requests.post(
                    self.graphql_endpoint,
                    headers=self.headers,
                    json={"query": query, "variables": {
                        "owner": owner,
                        "repo": repo,
                        "cursor": cursor
                    }}
                )
                
                if response.status_code != 200:
                    self.logger.error(f"Query failed with status code: {response.status_code}")
                    self.logger.debug(f"Response body: {response.text}")
                    raise Exception(f"Query failed with status code: {response.status_code}")

                data = response.json()
                if "errors" in data:
                    self.logger.error(f"GraphQL query failed: {data['errors']}")
                    raise Exception(f"GraphQL query failed: {data['errors']}")

                # Debug the response structure
                self.logger.debug(f"Response structure for {owner}/{repo}: {list(data.keys())}")
                if 'data' in data:
                    self.logger.debug(f"Data structure: {list(data['data'].keys())}")
                    if 'repository' in data['data']:
                        repo_data = data['data']['repository']
                        self.logger.debug(f"Repository structure: {list(repo_data.keys())}")
                        if 'defaultBranchRef' in repo_data:
                            self.logger.debug(f"DefaultBranchRef present: {repo_data['defaultBranchRef'] is not None}")
                            if repo_data['defaultBranchRef']:
                                self.logger.debug(f"Target present: {repo_data['defaultBranchRef'].get('target') is not None}")

                # Using get() for all nested accesses with detailed logging
                repository = data.get("data", {}).get("repository", {})
                self.logger.debug(f"Repository data: {bool(repository)}")
                
                default_branch_ref = repository.get("defaultBranchRef", {})
                self.logger.debug(f"Default branch ref: {bool(default_branch_ref)}")
                
                target = default_branch_ref.get("target", {})
                self.logger.debug(f"Target: {bool(target)}")
                
                history = target.get("history")
                self.logger.debug(f"History: {bool(history)}")

                if not history:
                    self.logger.info(f"Repository {owner}/{repo} has no commit history or is empty.")
                    return []

                # Use the safely accessed history object, not the direct path
                page_info = history.get("pageInfo", {})
                nodes = history.get("nodes", [])
                self.logger.debug(f"Found {len(nodes)} commits in this batch")
                
                for commit in nodes:
                    author = commit.get("author", {})
                    if author.get("user") and author["user"].get("login"):
                        committers.add(author["user"]["login"])
                    elif author.get("email"):
                        committers.add(author["email"])

                has_next_page = page_info.get("hasNextPage", False)
                cursor = page_info.get("endCursor")
                self.logger.debug(f"Pagination: has_next_page={has_next_page}, cursor={cursor}")
                
            except Exception as e:
                self.logger.error(f"Error in fetch_repo_committers for {owner}/{repo}: {str(e)}")
                self.logger.debug(f"Detailed error: {traceback.format_exc()}")
                raise
        
        self.logger.info(f"Found {len(committers)} committers for {owner}/{repo}")
        return sorted(list(committers))

    def process_repositories(self, csv_path: str) -> Dict[str, List[str]]:
        """Process multiple repositories from a CSV file"""
        results = {}
        
        if not Path(csv_path).exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        with open(csv_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            if not {'owner', 'repo'}.issubset(set(reader.fieldnames or [])):
                raise ValueError("CSV must contain 'owner' and 'repo' columns")
                
            for row in reader:
                repo_key = f"{row['owner']}/{row['repo']}"
                try:
                    print(f"Fetching committers for {repo_key}...")
                    committers = self.fetch_repo_committers(row['owner'], row['repo'])
                    results[repo_key] = committers
                except Exception as e:
                    print(f"Error processing {repo_key}: {str(e)}")
                    results[repo_key] = []
        
        return results

    def check_rate_limit(self) -> Dict:
        """Check GitHub API rate limit status"""
        query = """
        query {
            rateLimit {
                limit
                remaining
                resetAt
            }
        }
        """
        
        response = requests.post(
            self.graphql_endpoint,
            headers=self.headers,
            json={"query": query}
        )
        
        if response.status_code != 200:
            raise Exception("Failed to check rate limit")
            
        data = response.json()
        return data["data"]["rateLimit"]

    def analyze_committer_coverage(self, ghas_data: Dict, repo_data: Dict[str, List[str]]) -> Dict:
        """Compare repository committers against GHAS billing data"""
        all_repo_committers = set()
        for committers in repo_data.values():
            all_repo_committers.update(committers)
        
        ghas_committers = set()
        for repo in ghas_data.get('repositories', []):
            if repo.get('advanced_security_committers', 0) > 0:
                # Extract user_login from the breakdown
                for committer in repo.get('advanced_security_committers_breakdown', []):
                    if committer.get('user_login'):
                        ghas_committers.add(committer['user_login'])
        
        new_committers = all_repo_committers - ghas_committers
        
        return {
            'total_repo_committers': len(all_repo_committers),
            'total_ghas_committers': len(ghas_committers),
            'ghas_committers': sorted(list(ghas_committers)),  # List of user_logins
            'new_committers': sorted(list(new_committers)),
            'new_committer_count': len(new_committers)
        }

def main():
    parser = argparse.ArgumentParser(description='Analyze GitHub Advanced Security committers')
    parser.add_argument('--token', '-t',
                      required=True,
                      help='GitHub Personal Access Token')
    parser.add_argument('--enterprise', '-e',
                      required=False,
                      help='GitHub Enterprise name (required for GHAS analysis)')
    parser.add_argument('--csv', '-c',
                      required=False,
                      help='Path to CSV file containing organizations (format: org)')
    parser.add_argument('--orgs', '-g',
                      required=False,
                      nargs='+',
                      help='List of organizations to analyze (space-separated)')
    parser.add_argument('--output', '-o',
                      default='github_analysis_report.md',
                      help='Output file path (default: github_analysis_report.md)')
    parser.add_argument('--enterprise_server_hostname', '-H',
                      required=False,
                      help='GitHub Enterprise Server hostname (eg: github.fabrikam.com)')
    parser.add_argument('--debug', '-d',
                      action='store_true',
                      help='Enable debug logging')
                      
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.debug)
    
    # Validate that either CSV or organizations are provided
    if not args.csv and not args.orgs:
        parser.error("Either --csv or --orgs must be specified")

    analyzer = GitHubAnalyzer(args.token, args.enterprise, args.enterprise_server_hostname, logger)
    
    try:
        # Fetch GHAS data if enterprise is provided
        ghas_data = None
        if args.enterprise:
            print("Fetching GHAS data...")
            ghas_data = analyzer.get_ghas_data()

        # Process organizations
        print("Processing organizations...")
        repo_data = {}
        
        # If orgs are provided directly on command line
        if args.orgs:
            for org in args.orgs:
                try:
                    print(f"Fetching repositories for {org}...")
                    repos = analyzer.fetch_org_repos(org)
                    print(f"Found {len(repos)} repositories for {org}")
                    
                    # Process each repository in the organization
                    for repo in repos:
                        # Skip archived and forks
                        if repo.get('archived', False) or repo.get('fork', False):
                            continue
                            
                        repo_name = repo['name']
                        repo_key = f"{org}/{repo_name}"
                        
                        try:
                            print(f"Fetching committers for {repo_key}...")
                            committers = analyzer.fetch_repo_committers(org, repo_name)
                            repo_data[repo_key] = committers
                        except Exception as e:
                            print(f"Error processing {repo_key}: {str(e)}")
                            repo_data[repo_key] = []
                            
                except Exception as e:
                    print(f"Error processing organization {org}: {str(e)}")
        
        # Process organizations from CSV if provided
        elif args.csv:
            repo_data = analyzer.process_organizations(args.csv)

        # Generate report
        with open(args.output, 'w') as f:
            f.write("# GitHub Analysis Report\n\n")
            
            if ghas_data:
                f.write("## GHAS Usage\n")
                f.write(f"Total Advanced Security Committers: {ghas_data.get('total_advanced_security_committers', 0)}\n\n")
                f.write(f"Total purchased Advanced Security Committers available: {ghas_data.get('purchased_advanced_security_committers', 0)}\n\n")
                f.write(f"Total remaining Advanced Security Committers: {ghas_data.get('purchased_advanced_security_committers', 0) - ghas_data.get('total_advanced_security_committers', 0)}\n\n")

                
                # Add comparison analysis
                comparison = analyzer.analyze_committer_coverage(ghas_data, repo_data)
                f.write("## Committer Coverage Analysis\n")
                f.write(f"Total committers in specified repositories: {comparison['total_repo_committers']}\n\n")
                f.write(f"Total GitHub Advanced Security active committers: {comparison['total_ghas_committers']}\n\n")
                f.write(f"New committers without a GitHub Advanced Security license: {comparison['new_committer_count']}\n\n")
                
                if comparison['new_committers']:
                    f.write("### Committers Not Covered by GHAS\n")
                    for committer in comparison['new_committers']:
                        f.write(f"- {committer}\n")
                    f.write("\n")

                f.write("<details>\n")
                f.write("<summary>Existing Committers with GHAS License</summary>\n\n")
                for committer in comparison['ghas_committers']:
                    f.write(f"- {committer}\n")
                f.write("</details>\n\n")
            
            f.write("<details>\n")
            f.write("<summary>Repository Committer Analysis</summary>\n\n")
            
            for repo, committers in repo_data.items():
                f.write("<details>\n")
                f.write(f"<summary> {repo} (Active committers: {len(committers)})</summary>\n\n")
                for committer in committers:
                    f.write(f"- {committer}\n")
                f.write("</details>\n\n")
            
            f.write("</details>\n\n")

        print(f"\nReport generated: {args.output}")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
