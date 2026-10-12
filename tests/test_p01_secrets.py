"""PATCH 1 acceptance: no API key in source/config, and config snapshots are redacted."""
import pytest
import yaml

from bench_cfg import REDACTED, BenchConfig, redact_secrets

# Built at runtime so no key-shaped literal is stored in the repository.
FAKE_KEY = "sk-" + "test" + "x" * 40


def _write_cfg(tmp_path, extra=""):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"save_root: {tmp_path / 'out'}\nmodel_name: gpt-5-mini\n"
                   f"model_token_limit: 8096\nusage_token_limit: 1000\n{extra}")
    return cfg


def test_redact_nested_dicts_and_lists():
    data = {
        "llm_api_key": FAKE_KEY,
        "OPENAI_API_KEY": "abc",
        "model_token_limit": 8096,
        "usage_token_limit": 1000,
        "temperature": 1,
        "nested": {
            "GitHub_Token": "ghp_abc",
            "items": [{"client_secret": "s3cr3t"}, {"keep": "plain"}, f"inline {FAKE_KEY}"],
            "deeper": [[{"api-key": "x"}]],
        },
    }
    out = redact_secrets(data)

    assert out["llm_api_key"] == REDACTED
    assert out["OPENAI_API_KEY"] == REDACTED
    assert out["nested"]["GitHub_Token"] == REDACTED
    assert out["nested"]["items"][0]["client_secret"] == REDACTED
    assert out["nested"]["items"][1]["keep"] == "plain"
    assert out["nested"]["items"][2] == f"inline {REDACTED}"
    assert out["nested"]["deeper"][0][0]["api-key"] == REDACTED
    # Experiment parameters that merely contain "token" must survive.
    assert out["model_token_limit"] == 8096
    assert out["usage_token_limit"] == 1000
    assert out["temperature"] == 1
    # Input is not mutated.
    assert data["llm_api_key"] == FAKE_KEY
    assert "sk-" not in yaml.safe_dump(out)


def test_missing_env_key_exits_with_clear_message(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        BenchConfig(str(_write_cfg(tmp_path)))
    assert "OPENAI_API_KEY" in str(exc.value.code)


def test_key_in_config_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    with pytest.raises(SystemExit) as exc:
        BenchConfig(str(_write_cfg(tmp_path, extra=f'llm_api_key: "{FAKE_KEY}"\n')))
    msg = str(exc.value.code)
    assert "llm_api_key" in msg and FAKE_KEY not in msg


def test_key_comes_from_env_and_snapshot_is_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    cfg = BenchConfig(str(_write_cfg(tmp_path)))
    assert cfg.llm_api_key == FAKE_KEY

    snap = tmp_path / "config.yaml"
    cfg.write_snapshot(snap)
    text = snap.read_text()

    assert "sk-" not in text
    loaded = yaml.safe_load(text)  # plain YAML, no python/object tags
    assert loaded["llm_api_key"] == REDACTED
    assert loaded["model_token_limit"] == 8096
    assert loaded["model_name"] == "gpt-5-mini"
