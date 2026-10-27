# Contributing

Issues and pull requests are welcome.

**Issues.** For a bug, say what you ran, what you expected and what happened, with kordn's output. Leave out your keys and tokens. Security problems go through [private vulnerability reporting](https://github.com/Pheonix-dev0410/kordn/security/advisories/new), not issues.

**Pull requests.**
1. Fork the repo and branch off `dev`.
2. Make the change, with a test for it.
3. Run `npm run typecheck` and `npm test`.
4. Open the pull request into `dev`, and link the issue it fixes.

CI has to pass, and a maintainer reviews every pull request.

**Branches.** `dev` is where work lands. It moves to `staging` to be tried out, and then to `main`, which is what people install. All three only change through pull requests.

By contributing, you agree that your work is licensed under [Apache-2.0](LICENSE).
