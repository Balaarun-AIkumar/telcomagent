# Manual GitHub upload

Use the new `output/github/switchboard-source.zip`, not the old ZIP in the parent RAG folder.

1. Extract this ZIP to a new empty folder.
2. Confirm its root contains README.md, pyproject.toml, src, tests, .github, .gitignore and .env.example.
3. Upload the extracted contents to your GitHub repository. Include dotfiles; check the upload list shows .gitignore and .env.example. The .env.example values must remain empty.
4. Do not upload .env, .sbdata, .venv, credential downloads or the parent folder's resumes and archives.
5. After upload, inspect the GitHub file list. The actual .env and any private keys/database files must be absent.

Git ignore rules apply to Git, not arbitrary browser uploads. The checked archive handles that exclusion for this handoff. Uploading the ZIP as a single file does not make a reviewable source repository; extract it first.

To repeat the local check:

```powershell
.venv\Scripts\python scripts/check_secrets.py
git status --short
git diff --cached --stat
```

The scanner reports filenames and categories only, never secret values. The current parent repository had no commits and nothing staged. If a key was exposed in another repository, old archive or message, rotate it at its provider; deleting one file does not undo disclosure.

Publishing source is different from running the app. GitHub Pages cannot run this FastAPI backend. For the interview, run locally using the README. Do not publish the demo token endpoints as a production service.

Reviewers can run the offline demo with no keys. Cloud integrations are optional and each reviewer supplies their own private configuration.
