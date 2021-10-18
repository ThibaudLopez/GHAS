/*
GHAS implementation tracking
JavaScript console to https://api.github.com/favicon.ico
PENDING:
- repo
- is private/public
- programming languages (JavaScript, Python, Go) (the UI gives the list)
- build system (Travis, Circle, Makefile)
- branch protection
- GitHub issue tracking
- code scanning (UI scraping + REST API + .github/workflows/codeql-analysis.yml)
- dependabot
- secret scanning
- break builds yes/no
- automatic security fixes yes/no, automated PR
*/

// GitHub organisation
var owner = ...;

// https://github.com/settings/tokens
var TOKEN = ...;

// array of repo names
var repos = [...];

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
	// calculate from/to weeks; convert from ms to s to match GitHub format
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

// clean HTML
document.head.innerHTML = "";
document.body.innerHTML = "";

// get all the data, loop repos
var promises = repos.map(async (repo) => {
	var p = [
		get_repository(owner, repo),
		get_contributors(owner, repo),
		get_code_scanning_alerts(owner, repo),
		get_dependabot_alerts(owner, repo),
		get_secret_scanning_alerts(owner, repo)
	];
	var [repository, contributors, code_scanning, dependabot, secret_scanning] = await Promise.all(p);
	return {
		repo: repo,
		repository: repository,
		contributors: contributors,
		code_scanning: code_scanning,
		dependabot: dependabot,
		secret_scanning: secret_scanning
	};
});
var result = await Promise.all(promises);

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
	throw `unknown code_scanning ${o.repo}`;
}

// returns true if dependabot is setup for this repository
function has_dependabot(o) {
	var a = o.dependabot.data.repository.vulnerabilityAlerts.nodes;
	if (a.length > 0) {
		return true;
	}
	if (a.length === 0) {
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
	throw `unknown secret_scanning ${o.repo}`;
}

// calculate stats
var expected = (result.length * 3); // code-scanning, dependabot, secret-scanning
var completed = result.flatMap(o => [has_code_scanning(o) === true, has_dependabot(o) === true, has_secret_scanning(o) === true]).filter(e => e === true).length;
var contributors_90_days = [...new Set(result.flatMap(o => get_contributors_90_days(o.contributors)).map(contributor => contributor.author.login))].sort(); // PENDING: case insensitive sort
var count_code_scanning = (result.filter(o => has_code_scanning(o) === true).length);
var count_dependabot = (result.filter(o => has_dependabot(o) === true).length);
var count_secret_scanning = (result.filter(o => has_secret_scanning(o) === true).length);

// pretty print
var head = `
	<style>
		table, tr, th, td {
			border: 1px solid black;
			border-collapse: collapse;
		}
		td:nth-child(n+2) {
			text-align:center;
		}
		span {
			margin-top: 10px;
		}
		.highlight {
			background: yellow;
			font-size: 2em;
		}
	</style>
`;
var body = `
	${new Date().toISOString()}
	<table>
		<thead>
			<tr>
				<th rowspan="2">repo</th>
				<th rowspan="2">is public</th>
				<th rowspan="2">contributors in the last 90 days</th>
				<th colspan="3">tasks</th>
			</tr>
			<tr>
				<!--th>tracking</th-->
				<th>code-scanning</th>
				<th>dependabot</th>
				<th>secret-scanning</th>
			</tr>
		<thead>
		<tbody>
			${result.map(o => {
				var contributors_90_days = get_contributors_90_days(o.contributors).map(contributor => contributor.author.login).sort(); // PENDING: case insensitive sort
				return `
					<tr>
						<td><a href="https://github.com/${owner}/${o.repo}">${o.repo}</a></td>
						<td>${o.repository.private ? "" : "✓"}</td>
						<td title="${contributors_90_days}">${contributors_90_days.length}</td>
						<td title="${o.code_scanning.message || o.code_scanning.length}">${has_code_scanning(o) === true ? "✓" : (has_code_scanning(o) === undefined ? "?" : "")}</td>
						<td title="${o.dependabot.data.repository.vulnerabilityAlerts.nodes.length}">${has_dependabot(o) === true ? "✓" : (has_dependabot(o) === undefined ? "?" : "")}</td>
						<td title="${o.secret_scanning.message || o.secret_scanning.length}">${has_secret_scanning(o) === true ? "✓" : (has_secret_scanning(o) === undefined ? "?" : "")}</td>
					</tr>
				`;
			}).join("\n")}
		</tbody>
		<tfoot>
			<tr>
				<th rowspan="2">${result.length} repos</th>
				<th rowspan="2">${result.filter(o => o.repository.private === false).length} repos public</th>
				<th title="${contributors_90_days}" rowspan="2">${contributors_90_days.length} unique contributors out of 160 seats</th>
				<th>${count_code_scanning} repos setup with code-scanning</th>
				<th>${count_dependabot} repos setup with dependabot</th>
				<th>${count_secret_scanning} repos setup with secret_scanning</th>
			</tr>
			<tr>
				<th colspan="3">
					= ${count_code_scanning} + ${count_dependabot} + ${count_secret_scanning}<br/>
					= ${count_code_scanning + count_dependabot + count_secret_scanning} tasks completed out of ${expected}
				</th>
			</tr>
		</tfoot>
	</table>
	<span>
		completed: ${completed} tasks<br/>
		expected: ${result.length} repos * 3 tasks/repo = ${expected} tasks<br/>
		progress: ${completed} / ${expected} =
	</span>
	<span class="highlight">${Math.round(completed / expected * 100)}%</span>
`;
document.head.innerHTML = head;
document.body.innerHTML = body;

/*
in-scope only
var result_ = result;
result = result_.slice(10);
*/

/*
// pretty pretty print
// hide columns "is public" and "contributors"
[...document.querySelectorAll("table thead tr:nth-child(1) th:nth-child(n+2):nth-child(-n+3)")].forEach(th => th.style.display = "none");
[...document.querySelectorAll("table tbody tr td:nth-child(n+2):nth-child(-n+3)")].forEach(td => td.style.display = "none");
// hide row "tasks"
$("table thead tr:nth-child(1) th:nth-child(4)").style.display = "none";
// hide footer
$("table tfoot").style.display = "none";
// hide progress details
$("span:nth-child(n+1)").style.display = "none";
// revert
$x("//*").forEach(e => e.style.display = "");
*/
