# Contributing

Anyone may propose a pull request from a fork. A pull request does not grant write access, deployment access or permission to use any application identity. Maintainers decide whether to merge it. Do not request production credentials for development.

Use an isolated test application and disposable accounts. Never include real users, private grants, private keys, cookies, browser state, captures or customer data in commits, issues, screenshots, test output or pull requests. Report security issues privately as described in SECURITY.md.

## Commit privacy

Enable **Keep my email addresses private** and **Block command line pushes that expose my email** in your own GitHub email settings. Configure this checkout with the exact GitHub-provided noreply address:

```sh
git config --local user.email 'YOUR_GITHUB_NOREPLY_ADDRESS'
```

The account setting does not change local Git configuration or old commits. All author and committer addresses in proposed commits must be GitHub noreply addresses. Do not copy personal contact details into commit messages or trailers. Secret scanning and ignore rules are safeguards, not permission to commit sensitive data.

## Before opening a pull request

Run `npm ci`, `npm run typecheck`, `npm test`, and `npm run privacy:check`. Browser changes also require `npx playwright install chromium` and `npm run test:browser`. Describe the final behavior and verification; use generic example projects and accounts. Never include credential artifacts or unredacted logs.

Changes to authorization, signing, dependencies, workflows or release files require maintainer review. Fork CI receives no production secrets. A maintainer should inspect changes before approving workflow runs; do not execute contributor scripts with privileged credentials.
