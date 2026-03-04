# OpenAI-Compatible Example

This example uses only Python standard library modules and demonstrates the Nomos side of an OpenAI-compatible local tool loop.

## Run

1. Start Nomos:

```powershell
.\bin\nomos.exe serve -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

2. Run the example:

```powershell
python .\examples\openai-compatible\nomos_http_loop.py
```

The script sends:

- one allowed `fs.read` action for `README.md`
- one denied `fs.read` action for `.env`

Environment overrides:

- `NOMOS_BASE_URL`
- `NOMOS_API_KEY`
