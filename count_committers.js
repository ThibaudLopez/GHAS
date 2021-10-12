// count the number of committers for the GHAS billing
// https://docs.github.com/en/billing/managing-billing-for-github-advanced-security/about-billing-for-github-advanced-security

const fetch = require("node-fetch");

// https://github.com/settings/tokens/new
// Scope: role
var TOKEN = "...";

var owner = "ThibaudLopez";
var repo = "GHAS-canary";

// Get all contributor commit activity
// https://docs.github.com/en/rest/reference/repos#get-all-contributor-commit-activity
var url = `https://api.github.com/repos/${owner}/${repo}/stats/contributors`;
var contributors = (await (await fetch(url, { headers: { Authorization: `token ${TOKEN}` }})).json());

// calculate from/to weeks; convert from ms to s to match GitHub format
var from = Math.round(((new Date()).getTime() - 90*24*3600*1000) / 1000); // 90 days ago
var to = Math.round((new Date()) / 1000); // today

// filter from/to
var committers = contributors.filter(contributor => contributor.weeks.find(week => week.w >= from && week.w <= to && week.c > 0)).map(contributor => contributor.author.login);

/*
compare with:

repo > Insights > Contributors > Contributions: Commits
https://github.com/{owner}/{repo}/graphs/contributors?from={yyyy-mm-dd}&to={yyyy-mm-dd}&type=c

owner > Billing & plans > GitHub Advanced Security
https://github.com/organizations/{owner}/settings/billing

owner > Security & analysis > Configure security and analysis features
https://github.com/organizations/{owner}/settings/security_analysis
*/
