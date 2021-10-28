/*
GitHub Advanced Security (GHAS)
dashboard to track implementation
JavaScript console to https://api.github.com/favicon.ico
*/

// GitHub organisation
var owner = "...";

// array of repo names
var repos = ["..."];

// Personal access token
// https://github.com/settings/tokens
var TOKEN = "...";

// sugar for GraphQL API
async function GraphQL(query) {
	var escaped = query.replaceAll('"', '\\"').replaceAll("\n", " ").replaceAll("\t", " ");
	var body = `{ "query": "${escaped}" }`;
	return (await (await fetch("/graphql", { method: "POST", headers: { Authorization: `bearer ${TOKEN}` }, body: body })).json());
}

// sugar for REST API
async function REST(url) {
	return (await (await fetch(url, { headers: { Authorization: `bearer ${TOKEN}` }})).json());
}

// Get a repository
// https://docs.github.com/en/rest/reference/repos#get-a-repository
async function get_repository(owner, repo) {
	return await REST(`/repos/${owner}/${repo}`);
}

// Get all contributor commit activity
// https://docs.github.com/en/rest/reference/repos#get-all-contributor-commit-activity
async function get_contributors(owner, repo) {
	return await REST(`/repos/${owner}/${repo}/stats/contributors`);
}

// filter contributor commit activity of the last 90 days
function get_contributors_90_days(contributors) {
	// calculate from/to weeks; convert from JavaScript Date ms to UTC epoch seconds
	var from = Math.round((Date.now() - 90*24*3600*1000) / 1000); // 90 days ago
	var to = Math.round((new Date()) / 1000); // today
	return contributors.filter((contributor) => (contributor.weeks.find((week) => (week.w >= from && week.w <= to && week.c > 0))));
}

// List code scanning alerts for a repository
// https://docs.github.com/en/rest/reference/code-scanning#list-code-scanning-alerts-for-a-repository
async function get_code_scanning_alerts(owner, repo) {
	return await REST(`/repos/${owner}/${repo}/code-scanning/alerts`);
}

// list Dependabot alerts
// https://docs.github.com/en/graphql/reference/objects#repositoryvulnerabilityalert
async function get_dependabot_alerts(owner, repo) {
	var query = `{
		repository(name: "${repo}", owner: "${owner}") {
			isPrivate
			vulnerabilityAlerts(first: 100) {
				nodes {
					createdAt
					dismissedAt
					securityVulnerability {
						package {
							name
						}
						advisory {
							description
						}
					}
				}
			}
		}
	}`;
	return await GraphQL(query);
}

// List secret scanning alerts for a repository
// https://docs.github.com/en/rest/reference/secret-scanning#list-secret-scanning-alerts-for-a-repository
async function get_secret_scanning_alerts(owner, repo) {
	return await REST(`/repos/${owner}/${repo}/secret-scanning/alerts`);
}

// load the data
var promises = repos.map(async (repo) => ({
	repo: repo,
	repository: await get_repository(owner, repo),
	contributors: await get_contributors(owner, repo),
	code_scanning: await get_code_scanning_alerts(owner, repo),
	dependabot: await get_dependabot_alerts(owner, repo),
	secret_scanning: await get_secret_scanning_alerts(owner, repo)
}));
var result = await Promise.all(promises);

// pretty print
console.table(result.map(o => ({
	repository: o.repo,
	private: (o.repository.private ? "private" : "public"),
	contributors_90_days: get_contributors_90_days(o.contributors).map(contributor => contributor.author.login).length,
	code_scanning: (o.code_scanning.length || o.code_scanning.message),
	dependabot: (o.dependabot.data.repository.vulnerabilityAlerts.nodes.length),
	secret_scanning: (o.secret_scanning.length || o.secret_scanning.message),
})));
