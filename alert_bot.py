#!/usr/bin/env python3
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os, sys, time, json, threading
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from dotenv import load_dotenv
from yaml.loader import SafeLoader
from yaml.constructor import SafeConstructor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from elasticsearch import Elasticsearch
from slack_sdk import WebClient
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend

print(f"🚀 running {__file__} with {sys.executable}")

# ───────────── YAML 날짜 파싱 제거 ─────────────
SafeLoader.add_constructor(
    "tag:yaml.org,2002:timestamp",
    lambda loader, node: loader.construct_scalar(node)
)
SafeConstructor.yaml_constructors.pop("tag:yaml.org,2002:timestamp", None)

# ───────────── 환경 변수 ─────────────
load_dotenv(".env")
IGNORE_DIR_SUFFIXES = os.getenv("IGNORE_DIR_SUFFIXES", ".bak").split(",")
RULE_BASE = Path(os.getenv("RULE_BASE", "/rules")).expanduser()

ES_URL  = os.getenv("ES_URL",  "http://es01:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "changeme")

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_CHAN      = os.getenv("SLACK_DEFAULT_CHAN", "#pysigma")

STATE_INDEX = ".pysigma_state"
STATE_ID    = "alert_bot_last_ts"

LEVEL_NUM = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW",0:"INFO"}
def level_text(lv): return LEVEL_NUM.get(int(lv), "INFO") if isinstance(lv, (int, float)) else str(lv).upper()

EXTRA_KEYS = ["class_uid", "client_ip", "path"]

def get_nested(src: dict, dotted_key: str):
    cur = src
    for part in dotted_key.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur

class RuleManager(FileSystemEventHandler):
    def __init__(self, root: Path):
        super().__init__()
        self.root = root
        self.backend = LuceneBackend()
        self.rules = {}
        self.lock  = threading.Lock()
        self._load_all()
        ob = Observer(); ob.schedule(self, str(root), recursive=True); ob.start()
        self.observer = ob

    def _compile(self, yml: str):
        coll = SigmaCollection.from_yaml(Path(yml).read_text())
        return coll[0].title, self.backend.convert(coll)[0], coll[0]

    def _load_all(self):
        for p in self.root.rglob("*.yml"):
            if any(part.endswith(s) for part in p.parts for s in IGNORE_DIR_SUFFIXES): continue
            try: self.rules[str(p)] = self._compile(str(p))
            except Exception as e: print(f"[RULE] load error {p}: {e}")

    def _reload(self, e):
        if e.is_directory or not e.src_path.endswith(".yml") or any(part.endswith(s) for part in Path(e.src_path).parts for s in IGNORE_DIR_SUFFIXES):
            return
        try:
            self.rules[e.src_path] = self._compile(e.src_path)
            print(f"[RULE] reloaded {e.src_path}")
        except Exception as ex:
            print(f"[RULE] reload error {e.src_path}: {ex}")
    on_created = on_modified = on_moved = _reload

    def on_deleted(self, e):
        if e.src_path.endswith(".yml") and not any(part.endswith(s) for part in Path(e.src_path).parts for s in IGNORE_DIR_SUFFIXES):
            self.rules.pop(e.src_path, None); print(f"[RULE] removed {e.src_path}")

    def snapshot(self):
        with self.lock:
            return list(self.rules.values())

def load_last_ts(es):
    try:
        res = es.options(ignore_status=[404]).get(index=STATE_INDEX, id=STATE_ID)
        if res.get("found"):
            return res["_source"]["last_ts"]
    except Exception as e:
        print(f"[STATE] load error: {e}")
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def save_last_ts(es, ts):
    try:
        es.index(index=STATE_INDEX, id=STATE_ID, document={"last_ts": ts})
    except Exception as e:
        print(f"[STATE] save error: {e}")

def main():
    es    = Elasticsearch(ES_URL, basic_auth=(ES_USER, ES_PASS), verify_certs=False)
    slack = WebClient(token=SLACK_BOT_TOKEN)
    mgr   = RuleManager(RULE_BASE)

    last_ts = load_last_ts(es)
    seen    = set()
    MAX_JSON, POLL = 4000, 15

    while True:
        loop_start  = time.time()
        loop_max_ts = last_ts

        for title, lucene, rule in mgr.snapshot():
            es_query = {
                "size": 10,
                "sort": [{"@timestamp": "asc"}],
                "query": {
                    "bool": {
                        "must":   {"query_string": {"query": lucene}},
                        "filter": {"range": {"@timestamp": {"gt": last_ts}}}
                    }
                }
            }

            try:
                res = es.search(index="*", body=es_query)
            except Exception as e:
                print(f"[ES] {title} search error: {e}")
                continue

            print(f"[DEBUG] {title} → {res['hits']['total']['value']} hits")

            for hit in res["hits"]["hits"]:
                uid = hit["_id"]
                seen.add(uid)
                src = hit.get("_source", {})

                # ─── UTC → KST 변환  ───
                raw_ts = src.get("@timestamp", "")
                try:
                    if raw_ts.endswith("Z"):
                        base = raw_ts[:-1]
                        if "." in base:
                            date_part, frac = base.split(".", 1)
                            frac6 = (frac + "000000")[:6]
                            base = f"{date_part}.{frac6}"
                        iso_str = base + "+00:00"
                    else:
                        iso_str = raw_ts
                    utc_dt = datetime.fromisoformat(iso_str)
                    kst_dt = utc_dt.astimezone(ZoneInfo("Asia/Seoul"))
                    ts = kst_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
                except Exception:
                    ts = raw_ts
                # ─────────────────────────

                if raw_ts > loop_max_ts:
                    loop_max_ts = raw_ts

                sev = level_text(getattr(rule, "level", ""))
                msg = rule.description or title

                fields = [
                    {"type": "mrkdwn", "text": f"*Time*\n`{ts}`"},
                    {"type": "mrkdwn", "text": f"*Severity*\n{sev}"},
                    {"type": "mrkdwn", "text": f"*Message*\n{msg}"},
                ]
                for k in EXTRA_KEYS:
                    val = get_nested(src, k)
                    if val in (None, "", "N/A"): continue
                    pretty = k.replace("_", " ").title()
                    fields.append({"type": "mrkdwn", "text": f"*{pretty}*\n`{val}`"})
                    if len(fields) >= 10: break

                blocks = [
                    {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {title} 🚨"}},
                    {"type": "divider"},
                    {"type": "section", "fields": fields},
                ]

                try:
                    resp      = slack.chat_postMessage(channel=SLACK_CHAN, text=f"{title} – {sev}", blocks=blocks)
                    thread_ts = resp.get("ts")
                    pretty    = json.dumps(hit, ensure_ascii=False, indent=2)[:MAX_JSON]
                    slack.chat_postMessage(channel=SLACK_CHAN, thread_ts=thread_ts, text=f"```{pretty}```")
                    print("[INFO] JSON thread posted")
                except Exception as e:
                    print(f"[SLACK] send error: {e}")

        if loop_max_ts > last_ts:
            save_last_ts(es, loop_max_ts)
            last_ts = loop_max_ts
        if len(seen) > 20000:
            seen = set(list(seen)[-10000:])
        time.sleep(max(1, POLL - (time.time() - loop_start)))

if __name__ == "__main__":
    main()
