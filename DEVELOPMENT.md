# Development

Clone the repo and do:

```
poetry install
```

This will install `black`, `flake8`, `isort`, `mypy` & `pytest`. There is also a
self-documenting `Makefile` in here with the usual targets.

**Do not add any non-dev dependencies!**

## Tips

- You could streamline the setup by having `direnv` set the environment variables for you
  rather than having to do it by hand every time.
