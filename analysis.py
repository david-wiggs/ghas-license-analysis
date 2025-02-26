import argparse
import csv
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from pathlib import Path

class GitHubAnalyzer:
    def __init__(self, token: str, enterprise: Optional[str] = None):
        self.token = token
        self.enterprise = enterprise
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
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

    def fetch_repo_committers(self, owner: str, repo: str) -> List[str]:
        """Fetch all committers for a specific repository in the last 90 days"""
        ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
        committers: Set[str] = set()
        cursor = None
        has_next_page = True

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
                raise Exception(f"Query failed with status code: {response.status_code}")

            data = response.json()
            if "errors" in data:
                raise Exception(f"GraphQL query failed: {data['errors']}")

            history = data["data"]["repository"]["defaultBranchRef"]["target"]["history"]
            
            for commit in history["nodes"]:
                author = commit["author"]
                if author.get("user") and author["user"].get("login"):
                    committers.add(author["user"]["login"])
                elif author.get("email"):
                    committers.add(author["email"])

            has_next_page = history["pageInfo"]["hasNextPage"]
            cursor = history["pageInfo"]["endCursor"]

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
                      required=True,
                      help='Path to CSV file containing repositories (format: owner,repo)')
    parser.add_argument('--output', '-o',
                      default='github_analysis_report.md',
                      help='Output file path (default: github_analysis_report.md)')

    args = parser.parse_args()

    analyzer = GitHubAnalyzer(args.token, args.enterprise)
    
    try:
        # Fetch GHAS data if enterprise is provided
        ghas_data = None
        if args.enterprise:
            print("Fetching GHAS data...")
            ghas_data = analyzer.get_ghas_data()

        # Process repositories from CSV
        print("Processing repositories...")
        repo_data = analyzer.process_repositories(args.csv)

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
