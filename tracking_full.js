/*
GitHub Advanced Security (GHAS)
dashboard to track implementation

HOW TO USE:
- browse to https://api.github.com/favicon.ico
- set the global variables
- execute the script in the JavaScript console

PENDING:
- last column DONE: await prior code before rendering
- add comments as hover
- swap columns updated_at hours/days
- add column CMake if CMakeLists.txt
- GitHub API sometimes returns blank object {} instead of actual response, despite no error message and no exceeded rate limit
	api-3dtiles/stats/contributors response is not array
	cdn-global-api/stats/contributors response is not array
	result.filter(o => !Array.isArray(o.contributors))
- what's the API to get the 160 count of seats ? to un-hardcode value
- what's the API to get the list of 51 repos that have GHAS setup ? to un-hardcode the repos.js list
- what other build systems?
- repo has branch protection? yes/no
- repo has break builds? yes/no
- repo has automatic security fixes, automated PR? yes/no
*/


/*
	global variables, change as needed
*/

// GitHub organisation
var owner = "acme";

// array of repo names
var repos = ["foo", "bar", "baz"];

// Personal access token
// https://github.com/settings/tokens
var TOKEN = "abc123";

// CodeQL supports, from codeql-analysis.yml
var codeql_supports = ["cpp", "csharp", "go", "java", "javascript", "python"];


/*
	syntactic sugar
*/

// sugar for fetch
async function fetch_(method, url, body) {
	var response = (await fetch(url, { method: method, headers: { Authorization: `bearer ${TOKEN}` }, body: body }));
	// rate limit?
	var x_ratelimit_remaining = response.headers.get("x-ratelimit-remaining");
	if ((url.startsWith("/search/issues?") && x_ratelimit_remaining === 0) || (!url.startsWith("/search/issues?") && x_ratelimit_remaining < 1000)) {
		throw `x-ratelimit-remaining: ${x_ratelimit_remaining}`;
	}
	// data
	var data = (await response.json());
	// error message?
	if (data.message === "Resource protected by organization SAML enforcement. Your token's access was revoked. Please generate a new Personal Access token and grant it access to this organization." || data.message === "API rate limit exceeded for user ID 6137886.") {
		throw data.message;
	}
	// OK
	return data;
}

// sugar for GraphQL API
async function GraphQL(query) {
	var escaped = query.replaceAll('"', '\\"').replaceAll("\n", " ").replaceAll("\t", " ");
	var body = `{ "query": "${escaped}" }`;
	return await fetch_("POST", "/graphql", body);
}

// sugar for REST API
async function REST(method, url, body) {
	return await fetch_(method, url, body);
}


/*
	GitHub API
*/

// Get a repository
// https://docs.github.com/en/rest/reference/repos#get-a-repository
async function get_repository(owner, repo) {
	return await REST("GET", `/repos/${owner}/${repo}`);
}

// List repository teams
// https://docs.github.com/en/rest/reference/repos#list-repository-teams
async function get_teams(owner, repo) {
	return await REST("GET", `/repos/${owner}/${repo}/teams`);
}

// List repository languages
// https://docs.github.com/en/rest/reference/repos#list-repository-languages
async function get_languages(owner, repo) {
	return await REST("GET", `/repos/${owner}/${repo}/languages`);
}

// Search issues and pull requests
// https://docs.github.com/en/rest/reference/search#search-issues-and-pull-requests
async function search_issues(owner, q) {
	return await REST("GET", `/search/issues?q=${encodeURIComponent(q)}&per_page=100`);
}

// Get allowed actions for a repository
// https://docs.github.com/en/rest/reference/actions#get-allowed-actions-for-a-repository
async function get_allowed_actions(owner, repo) {
	return await REST("GET", `/repos/${owner}/${repo}/actions/permissions/selected-actions`);
}

// Get repository content
// https://docs.github.com/en/rest/reference/repos#get-repository-content
async function get_content(owner, repo, path) {
	return await REST("GET", `/repos/${owner}/${repo}/contents/${path}`);
}

// Get all contributor commit activity
// https://docs.github.com/en/rest/reference/repos#get-all-contributor-commit-activity
async function get_contributors(owner, repo) {
	var url = `/repos/${owner}/${repo}/stats/contributors`;
	var response = await REST("GET", url);
	// PENDING
	if (!Array.isArray(response)) {
		throw `${url} response is not array`;
	}
	return response;
}

// List repository workflows
// https://docs.github.com/en/rest/reference/actions#list-repository-workflows
async function get_actions_workflows(owner, repo) {
	return await REST("GET", `/repos/${owner}/${repo}/actions/workflows`);
}

// List code scanning alerts for a repository
// https://docs.github.com/en/rest/reference/code-scanning#list-code-scanning-alerts-for-a-repository
async function get_code_scanning_alerts(owner, repo) {
	return await REST("GET", `/repos/${owner}/${repo}/code-scanning/alerts`);
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
	return await REST("GET", `/repos/${owner}/${repo}/secret-scanning/alerts`);
}

// Check if vulnerability alerts are enabled for a repository
// https://docs.github.com/en/rest/reference/repos#check-if-vulnerability-alerts-are-enabled-for-a-repository
async function get_vulnerability_alerts(owner, repo) {
	var response = (await fetch(`/repos/${owner}/${repo}/vulnerability-alerts`, { headers: { Authorization: `bearer ${TOKEN}` }}));
	var data = await response.text();
	return {
		response: response, // needed for HTTP response status
		data: data,
	};
}


/*
	get common files
*/

// get the Travis CI YAML
async function get_travis_yml(owner, repo) {
	return await get_content(owner, repo, ".travis.yml");
}

// get the Circle CI YAML
async function get_circleci_yml(owner, repo) {
	return await get_content(owner, repo, ".circleci/config.yml");
}

// get the AWS CodeBuild YAML
async function get_aws_codebuild_yml(owner, repo) {
	return await get_content(owner, repo, "buildspec.yml");
}

// get the Makefile
async function get_makefile(owner, repo) {
	return await get_content(owner, repo, "Makefile");
}

// get the CodeQL YAML
async function get_codeql_analysis_yml(owner, repo) {
	return await get_content(owner, repo, ".github/workflows/codeql-analysis.yml");
}

// get the Dependabot YAML
async function get_dependabot_yml(owner, repo) {
	return await get_content(owner, repo, ".github/dependabot.yml");
}


/*
	other
*/

// return the GHAS tracking issues
async function get_GHAS_issues(owner) {
	return await search_issues(owner, `org:${owner} is:issue label:GHAS`);
}

// return the CodeQL pull request
async function get_CodeQL_pull_requests(owner) {
	return await search_issues(owner, `org:${owner} is:pr in:title "Create codeql-analysis.yml"`);
}

// filter contributor commit activity of the last 90 days
function get_contributors_90_days(contributors) {
	// calculate from/to weeks; convert from JavaScript Date ms to UTC epoch seconds
	var from = Math.round((Date.now() - 90*24*3600*1000) / 1000); // 90 days ago
	var to = Math.round((new Date()) / 1000); // today
	return contributors.filter((contributor) => (contributor.weeks.find((week) => (week.w >= from && week.w <= to && week.c > 0))));
}

// returns true if repo has Travis CI
function has_travis(o) {
	return (o.travis_yml?.message !== "Not Found");
}

// returns true if repo has Circle CI
function has_circleci(o) {
	return (o.circleci_yml?.message !== "Not Found");
}

// returns true if repo has AWS CodeBuild
function has_codebuild(o) {
	return (o.aws_codebuild_yml?.message !== "Not Found");
}

// returns true if repo has a Makefile
function has_makefile(o) {
	return (o.makefile?.message !== "Not Found");
}

// returns true if code scanning is setup for this repository
function has_code_scanning(o) {
	if (Array.isArray(o.code_scanning)) {
		return true;
	}
	if (o.code_scanning.message === "Advanced Security must be enabled for this repository to use code scanning.") {
		return false;
	}
	if (o.code_scanning.message === "no analysis found") {
		// PENDING
		return undefined;
	}
	throw `unknown code_scanning ${o.repo}: ${o.code_scanning.message}`;
}

// returns true if dependabot is setup for this repository
function has_dependabot(o) {
	var nodes = o.dependabot.data.repository.vulnerabilityAlerts.nodes;
	if (nodes.length > 0) {
		return true;
	}
	if (nodes.length === 0) {
		// PENDING
		return undefined;
	}
}

// returns true if secret scanning is setup for this repository
function has_secret_scanning(o) {
	if (Array.isArray(o.secret_scanning)) {
		return true;
	}
	if (o.secret_scanning.message === "Secret scanning is disabled on this repository.") {
		return false;
	}
	if (o.secret_scanning.message === "Secret scanning APIs are not available on public repositories") {
		// PENDING
		return undefined;
	}
	throw `unknown secret_scanning ${o.repo}: ${o.secret_scanning.message}`;
}

// returns true if vulnerability alerts are enabled for a repository
function has_vulnerability_alerts(o) {
	if (o.vulnerability_alerts.response.status === 204 /*&& o.vulnerability_alerts.response.statusText === "No Content"*/) {
		return true;
	}
	if (o.vulnerability_alerts.response.status === 404 /*&& o.vulnerability_alerts.response.statusText === "Not Found"*/) {
		return false;
	}
	// PENDING
	return undefined;
}

// returns true if GitHub Actions is actions/checkout@* and github/codeql-action/*
function has_github_actions(o) {
	return (o.allowed_actions.patterns_allowed && o.allowed_actions.patterns_allowed.includes("actions/checkout@*") && o.allowed_actions.patterns_allowed.includes("github/codeql-action/*"));
}

// returns true if this repository has a CodeQL workflow
function has_codeql_workflow(o) {
	return (o.actions_workflows.workflows.filter(w => w.name === "CodeQL" && w.path === ".github/workflows/codeql-analysis.yml" && w.state === "active").length > 0);
}

// returns the languages setup in the CodeQL YAML
function get_languages_yml(o) {
	if (!o.codeql_analysis_yml.content) {
		return [];
	}
	var yml = atob(o.codeql_analysis_yml.content);
	var languages = JSON.parse(yml.match(/language: (\[.*\])\n/)[1].replaceAll("'", '"'));
	return languages;
}

// returns true if the CodeQL YAML is missing a supported language
function get_languages_yml_missing(o) {
	var languages_yml = get_languages_yml(o);
	if (languages_yml.length === 0) {
		return [];
	}
	var repo_languages = Object.keys(o.languages).map(s => s.toLowerCase());
	var codeql_supports_ = codeql_supports.filter(language => repo_languages.includes(language));
	var languages_missing = codeql_supports_.filter(language => !languages_yml.includes(language));
	return languages_missing;
}


/*
	visual stuff
*/

// returns the ratio [0,1] by language
function get_ratios(languages) {
	var langs = Object.keys(languages);
	var total = langs.map(language => languages[language]).reduce((acc, curr) => acc + curr, 0);
	var ratios = langs.map(language => ({ language: language, ratio: (languages[language] / total) }));
	return ratios;
}

// return a cloud map
function cloud_map(languages) {
	return get_ratios(languages).map(({language, ratio}) => `<span style="font-size:${Number(ratio**2).toFixed(14)}em">${language}</span>`).join(" ");
}

// escape specified string for element attribute value
function escape_attr(s) {
	return s.replaceAll('"', "&quot;");
}

// return a link to the team members
function get_team_link(team) {
	return `<a href="https://github.com/orgs/${owner}/teams/${team}/members">${team}</a>`;
}


/*
	get the data
*/

// clean HTML
document.head.innerHTML = "";
document.body.innerHTML = "";

// get all the data, loop repos
var timestamp = new Date().toISOString();
var promises = repos.map(async (repo) => ({
		repo: repo,
		repository: await get_repository(owner, repo),
		teams: await get_teams(owner, repo),
		languages: await get_languages(owner, repo),
		allowed_actions: await get_allowed_actions(owner, repo),
		actions_workflows: await get_actions_workflows(owner, repo),
		travis_yml: await get_travis_yml(owner, repo),
		circleci_yml: await get_circleci_yml(owner, repo),
		aws_codebuild_yml: await get_aws_codebuild_yml(owner, repo),
		makefile: await get_makefile(owner, repo),
		contributors: await get_contributors(owner, repo),
		codeql_analysis_yml: await get_codeql_analysis_yml(owner, repo),
		dependabot_yml: await get_dependabot_yml(owner, repo),
		code_scanning: await get_code_scanning_alerts(owner, repo),
		dependabot: await get_dependabot_alerts(owner, repo),
		secret_scanning: await get_secret_scanning_alerts(owner, repo),
		vulnerability_alerts: await get_vulnerability_alerts(owner, repo),
}));
var result = await Promise.all(promises);
var issues = await get_GHAS_issues(owner);
var issues_ = issues.items.filter(o => repos.find(repo => o.repository_url.endsWith(repo)));
var pull_requests = await get_CodeQL_pull_requests(owner);
var pull_requests_ = pull_requests.items.filter(o => repos.find(repo => o.repository_url.endsWith(repo)));

// repo stats
var unique_teams = [...new Set(result.flatMap(o => o.teams.map(team => team.name)))].sort();
var contributors_90_days = [...new Set(result.flatMap(o => get_contributors_90_days(o.contributors)).map(contributor => contributor.author.login))].sort(); // PENDING: case insensitive sort

// language stats
var unique_languages = [...new Set(result.flatMap(o => Object.keys(o.languages)))].sort();
var languages = result.map(o => o.languages);
var languages_total = unique_languages.map(language => ({ [`${language}`]: languages.filter(o => o[language]).map(o => o[language]).reduce((acc, curr) => acc + curr, 0) }));
languages_total = languages_total.reduce((acc, curr) => { var language = Object.keys(curr)[0]; acc[language] = curr[language]; return acc; }, {});

// build stats
var count_travis = result.filter(o => has_travis(o)).length;
var count_circleci = result.filter(o => has_circleci(o)).length;
var count_codebuild = result.filter(o => has_codebuild(o)).length;
var count_makefile = result.filter(o => has_makefile(o)).length;

// GHAS stats
var count_code_scanning_alerts = (result.filter(o => has_code_scanning(o) === true).length);
var count_dependabot_alerts = (result.filter(o => has_dependabot(o) === true).length);
var count_secret_scanning_alerts = (result.filter(o => has_secret_scanning(o) === true).length);

// implementation stats
var expected_tasks = (result.length * 3); // code-scanning, dependabot, secret-scanning
var completed_tasks = result.flatMap(o => [has_code_scanning(o) === true, has_dependabot(o) === true, has_secret_scanning(o) === true]).filter(e => e === true).length;


/*
	pretty print to HTML table
*/

// sort the clicked column
function sort(event) {
	var ASC = "▲";
	var DESC = "▼";
	var th = event.srcElement;
	var tr = th.parentElement;
	var thead = th.parentElement.parentElement;
	var table = th.parentElement.parentElement.parentElement;
	var tbody = table.querySelector("tbody");
	// detect the column index
	var column = [...tr.cells].indexOf(th);
	// detect the sort direction
	var ascending = (th.innerText.endsWith(ASC) ? true : false);
	// replace the sort icon
	[...tr.cells].forEach(th => th.innerText = th.innerText.replace(/[▲▼]*$/g, ""))
	th.innerText += (ascending ? DESC : ASC);
	// sort in the opposite direction
	[...tbody.rows].sort((a, b) => {
		var [c, d] = (ascending ? [b, a] : [a, b]);
		var s = c.cells[column].innerText;
		var t = d.cells[column].innerText;
		return s.localeCompare(t, undefined, { numeric: true });
	}).forEach(tr => tbody.append(tr));
}

// HTML head
document.head.innerHTML = `
	<style>
		table, tr, th, td {
			border: 1px solid black;
			border-collapse: collapse;
		}
		table thead tr:nth-child(1) {
			background: lightslategray;
		}
		table thead tr:nth-child(2) {
			background: lightgrey;
		}
		table thead tr:nth-child(1) th {
			border-left: 5px solid;
			border-right: 5px solid;
		}
		table {
			margin-bottom: 50px;
		}
		/* hack for colgroup */
		td:nth-child(1),  /*[i]*/
		td:nth-child(7),  /*repository*/
		td:nth-child(11), /*build*/
		td:nth-child(18), /*issue*/
		td:nth-child(21), /*GHAS*/
		td:nth-child(22), /*GitHub Actions*/
		td:nth-child(23), /*CodeQL workflow*/
		td:nth-child(26), /*CodeQL YAML*/
		td:nth-child(34), /*Pull Request*/
		td:nth-child(35), /*Dependabot YAML*/
		td:nth-child(38), /*Tasks*/
		td:nth-child(39)  /*DONE*/
		{
			border-right: 5px solid black;
		}
		table tbody tr:hover {
			background:#EEEEEE;
			opacity:0.95;
			filter: contrast(0.95);
		}
		td:nth-child(n+2) {
			text-align:center;
		}
		.highlight {
			background: yellow;
			font-size: 2em;
		}
		.green {
			background: lightgreen;
		}
		.red {
			background: lightcoral;
		}
	</style>
`;

// HTML body
document.body.getAttributeNames().forEach(attribute => document.body.removeAttribute(attribute));
document.body.innerHTML = `
	${timestamp}
	<table>
		<thead>
			<tr>
				<th></th>
				<th colspan="6">repository</th>
				<th colspan="4">build</th>
				<th colspan="7">issue</th>
				<th colspan="3">GHAS</th>
				<th>GitHub Actions</th>
				<th>CodeQL workflow</th>
				<th colspan="3">CodeQL YAML</th>
				<th colspan="8">Pull Request</th>
				<th rowspan="2">Dependabot YAML</th>
				<th colspan="3">tasks</th>
				<th rowspan="2">DONE</th>
			</tr>
			<tr>
				<!-- [i] -->
				<th>[i]</th>
				<!-- repository -->
				<th>name</th>
				<th>is public</th>
				<th>default_branch</th>
				<th>teams</th>
				<th>languages</th>
				<th>contributors in the last 90 days</th>
				<!-- build -->
				<th>Travis CI</th>
				<th>Circle CI</th>
				<th>AWS CodeBuild</th>
				<th>Makefile</th>
				<!-- issue -->
				<th>#</th>
				<th>state</th>
				<th>assignees</th>
				<th>comments</th>
				<th>updated_at</th>
				<th>updated hours ago</th>
				<th>updated days ago</th>
				<!-- GHAS -->
				<th>advanced_security</th>
				<th>secret_scanning</th>
				<th>vulnerability-alerts</th>
				<!-- GitHub Actions -->
				<th>actions/checkout@*, github/codeql-action/*</th>
				<!-- CodeQL workflow -->
				<th></th>
				<!-- CodeQL YAML -->
				<th>codeql-analysis.yml</th>
				<th>languages</th>
				<th>missing languages</th>
				<!-- Pull Request -->
				<th>#</th>
				<th>state</th>
				<th>user</th>
				<th>assignees</th>
				<th>comments</th>
				<th>updated_at</th>
				<th>updated hours ago</th>
				<th>updated days ago</th>
				<!-- Dependabot YAML -->
				<!-- tasks -->
				<th>code-scanning</th>
				<th>dependabot</th>
				<th>secret-scanning</th>
				<!-- DONE -->
			</tr>
		</thead>
		<tbody>
			${result.map((o, i) => {
				// issue
				var issues__ = issues_.filter(p => p.repository_url.endsWith(o.repo));
				if (issues__.length > 1) {
					console.warn(`repo ${o.repo} has ${issues__.length} issues instead of 1`);
				}
				var issue = issues__[0];
				if (issue && issue.title !== "GHAS (GitHub Advanced Security) setup for repository") {
					console.warn(`repo ${o.repo} issue ${issue.number} has different title, ${issue.title}`);
				}
				if (issue) {
					var issue_updated_ago = (Date.now() - new Date(issue.updated_at));
				}
				// pull request
				var pull_requests__ = pull_requests_.filter(p => p.repository_url.endsWith(o.repo));
				if (pull_requests__.length > 1) {
					console.warn(`repo ${o.repo} has ${pull_requests__.length} pull requests instead of 1`);
				}
				var pull_request = pull_requests__[0];
				if (pull_request && pull_request.title !== "Create codeql-analysis.yml") {
					console.warn(`repo ${o.repo} pull request ${pull_request.number} has different title, ${pull_request.title}`);
				}
				if (pull_request) {
					var pull_request_updated_ago = (Date.now() - new Date(pull_request.updated_at));
				}
				// contributors
				var contributors_90_days = get_contributors_90_days(o.contributors).map(contributor => contributor.author.login).sort(); // PENDING: case insensitive sort
				// HTML row
				return `
					<tr>
						<td>${i}</td>
						<!-- repository -->
						<td><a href="https://github.com/${owner}/${o.repo}">${o.repo}</a></td>
						<td>${o.repository.private ? "" : "✓"}</td>
						<td>${o.repository.default_branch}</td>
						<td>${o.teams.map(team => get_team_link(team.name)).join(", ")}</td>
						<td title="${escape_attr(JSON.stringify(o.languages))}">${cloud_map(o.languages)}</td>
						<td title="${contributors_90_days}">${contributors_90_days.length}</td>
						<!-- build -->
						<td>${has_travis(o) ? "✓" : ""}</td>
						<td>${has_circleci(o) ? "✓" : ""}</td>
						<td>${has_codebuild(o) ? "✓" : ""}</td>
						<td>${has_makefile(o) ? "✓" : ""}</td>
						<!-- issue -->
						<td>${issue ? `<a href="https://github.com/${owner}/${o.repo}/issues/${issue.number}">#${issue.number}</a>` : ""}</td>
						<td class="${issue && issue.state === "closed" ? "green" : "red"}">${issue?.state || ""}</td>
						<td>${issue?.assignees.map(assignee => `<a href="https://github.com/${assignee.login}">${assignee.login}</a>`).join(", ") || ""}</td>
						<td>${issue?.comments || ""}</td>
						<td>${issue ? issue.updated_at : ""}</td>
						<td>${issue ? Math.round(issue_updated_ago / 1000 / 3600) : ""}</td>
						<td>${issue ? Math.round(issue_updated_ago / 1000 / 3600 / 24) : ""}</td>
						<!-- GHAS -->
						<td class="${o.repository.security_and_analysis?.advanced_security.status === "enabled" ? "green" : ""}">${o.repository.security_and_analysis?.advanced_security.status === "enabled" ? "✓" : "?"}</td>
						<td class="${o.repository.security_and_analysis?.secret_scanning.status === "enabled" ? "green" : ""}">${o.repository.security_and_analysis?.secret_scanning.status === "enabled" ? "✓" : "?"}</td>
						<td class="${has_vulnerability_alerts(o) ? "green" : "red"}">${has_vulnerability_alerts(o) === true ? "✓" : (has_vulnerability_alerts(o) === false ? "✘" : "?")}</td>
						<!-- GitHub Actions -->
						<td class="${!o.allowed_actions.patterns_allowed ? "red" : "green"}">${has_github_actions(o) && o.allowed_actions.patterns_allowed.length === 2 ? "✓" : o.allowed_actions.patterns_allowed?.join(", ")}</td>
						<!-- CodeQL workflow -->
						<td class="${has_codeql_workflow(o) ? "green" : "red"}">${has_codeql_workflow(o) ? "✓" : "✘"}</td>
						<!-- CodeQL YAML -->
						<td class="${o.codeql_analysis_yml.message ? "red" : "green"}">${o.codeql_analysis_yml.name ? `<a href="https://github.com/${owner}/${o.repo}/blob/main/.github/workflows/${o.codeql_analysis_yml.name}">${o.codeql_analysis_yml.name}</a>` : o.codeql_analysis_yml.message}</td>
						<td>${get_languages_yml(o)}</td>
						<td class="${get_languages_yml_missing(o).length > 0 ? "red" : ""}">${get_languages_yml_missing(o).length > 0 ? `${get_languages_yml_missing(o)}` : ""}</td>
						<!-- Pull Request -->
						<td>${pull_request ? `<a href="https://github.com/${owner}/${o.repo}/pull/${pull_request.number}">#${pull_request.number}</a>` : ""}</td>
						<td class="${pull_request && pull_request.state === "closed" ? "green" : "red"}">${pull_request?.state || ""}</td>
						<td>${pull_request?.user.login || ""}</td>
						<td>${pull_request?.assignees.map(assignee => `<a href="https://github.com/${assignee.login}">${assignee.login}</a>`).join(", ") || ""}</td>
						<td>${pull_request?.comments || ""}</td>
						<td>${pull_request?.updated_at || ""}</td>
						<td>${pull_request ? Math.round(pull_request_updated_ago / 1000 / 3600) : ""}</td>
						<td>${pull_request ? Math.round(pull_request_updated_ago / 1000 / 3600 / 24) : ""}</td>
						<!-- Dependabot YAML -->
						<td>${o.dependabot_yml.name || o.dependabot_yml.message}</td>
						<!-- tasks -->
						<td class="${has_code_scanning(o) === true ? "green" : (has_code_scanning(o) === false ? "red" : "")}" title="${o.code_scanning.message || o.code_scanning.length}">${has_code_scanning(o) === true ? "✓" : (has_code_scanning(o) === undefined ? o.code_scanning.message : "✘")}</td>
						<td class="${has_dependabot(o) === true ? "green" : (has_dependabot(o) === false ? "red" : "")}" title="${o.dependabot.data.repository.vulnerabilityAlerts.nodes.length}">${has_dependabot(o) === true ? "✓" : (has_dependabot(o) === undefined ? "?" : "✘")}</td>
						<td class="${has_secret_scanning(o) === true ? "green" : (has_secret_scanning(o) === false ? "red" : "")}" title="${o.secret_scanning.message || o.secret_scanning.length}">${has_secret_scanning(o) === true ? "✓" : (has_secret_scanning(o) === undefined ? o.secret_scanning.message : "✘")}</td>
						<!-- DONE -->
						<td></td>
					</tr>
				`;
			}).join("\n")}
		</tbody>
		<tfoot>
			<tr>
				<th rowspan="2"></th>
				<!-- repository -->
				<th rowspan="2">${result.length} repos</th>
				<th rowspan="2">${result.filter(o => o.repository.private === false).length} repos public</th>
				<th rowspan="2"></th>
				<th rowspan="2">${unique_teams.length} unique teams<br/>${unique_teams.map(team => get_team_link(team)).join(", ")}</th>
				<th rowspan="2" title="${escape_attr(JSON.stringify(languages_total))}">${unique_languages.length} languages<br/><span style="font-size:2em">${cloud_map(languages_total)}</span></th>
				<th rowspan="2" title="${contributors_90_days}">${contributors_90_days.length} unique contributors out of 160 seats</th>
				<!-- build -->
				<th rowspan="2">${count_travis} Travis CI</th>
				<th rowspan="2">${count_circleci} Circle CI</th>
				<th rowspan="2">${count_codebuild} AWS CodeBuild</th>
				<th rowspan="2">${count_makefile} Makefiles</th>
				<!-- issue -->
				<th rowspan="2">${result.filter(o => issues.items.find(p => p.repository_url.endsWith(o.repo))).length} issues</th>
				<th rowspan="2">${[...new Set(issues_.map(issue => issue.state))].map(state => [issues_.filter(issue => issue.state === state).length, state].join(" ")).join("<br/>")}</th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<!-- GHAS -->
				<th rowspan="2">${result.filter(o => o.repository.security_and_analysis?.advanced_security.status === "enabled").length} repos have advanced_security enabled</th>
				<th rowspan="2">${result.filter(o => o.repository.security_and_analysis?.secret_scanning.status === "enabled").length} repos have secret_scanning enabled</th>
				<th rowspan="2"></th>
				<!-- GitHub Actions -->
				<th rowspan="2">${result.filter(o => has_github_actions(o)).length} repos setup with GHAS Actions</th>
				<!-- CodeQL workflow -->
				<th rowspan="2"></th>
				<!-- CodeQL YAML -->
				<th rowspan="2">${result.filter(o => o.codeql_analysis_yml.name).length} codeql-analysis.yml files setup</th>
				<th rowspan="2">${[...new Set(result.flatMap(o => get_languages_yml(o)))].length} languages setup</th>
				<th rowspan="2"></th>
				<!-- Pull Request -->
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<th rowspan="2"></th>
				<!-- Dependabot YAML -->
				<th rowspan="2"></th>
				<!-- tasks -->
				<th>${count_code_scanning_alerts} repos setup with code-scanning</th>
				<th>${count_dependabot_alerts} repos setup with dependabot</th>
				<th>${count_secret_scanning_alerts} repos setup with secret_scanning</th>
				<!-- DONE -->
				<th rowspan="2"></th>
			</tr>
			<tr>
				<th colspan="3">
					= ${count_code_scanning_alerts} + ${count_dependabot_alerts} + ${count_secret_scanning_alerts}<br/>
					= ${count_code_scanning_alerts + count_dependabot_alerts + count_secret_scanning_alerts} tasks completed out of ${expected_tasks}
				</th>
			</tr>
		</tfoot>
	</table>
	<div>
		tasks completed: ${completed_tasks} tasks<br/>
		tasks expected: ${result.length} repos * 3 tasks/repo = ${expected_tasks} tasks<br/>
		progress: ${completed_tasks} / ${expected_tasks} =
		<span class="highlight">${Math.round(completed_tasks / expected_tasks * 100)}%</span>
	</div>
`;

// make the columns sortable
document.querySelectorAll("table thead tr th").forEach(th => th.addEventListener("click", sort));

// ugly hack to calculate - based on the cell's color green - if a repo is done or not
var expected_green = 11; // issue close, pull request closed, GHAS setup, YAML setup, 3 tasks done, etc.
var rows = [...document.querySelectorAll("table tbody tr")];
rows.forEach(tr => {
	var td = tr.cells[tr.cells.length - 1];
	var greens = $x(`td[@class='green' and position()!=last()]`, tr);
	if (greens.length === expected_green) {
		td.innerText = "✓";
		td.className = "green";
	} else {
		td.innerText = "✘";
		td.className = "red";
	}
});
var DONE = $x("//table/tbody/tr/td[last()][@class='green']").length;
$x("//table/tfoot/tr[1]/th[last()]")[0].innerText = `${DONE} repos are DONE`;
