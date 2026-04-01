import argparse
import json
from typing import Any, Dict

from .scanner import analyze_apk, analyze_source_tree


def _render_summary(result: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "kind": result["kind"],
            "target": result["target"],
            "report_path": result["report_path"],
            "dynamic_plan": result["dynamic_plan"],
            "inventory": result["inventory"],
        },
        indent=2,
        sort_keys=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Static APK/Android artifact analysis with LIEF")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apk", help="Path to APK file")
    group.add_argument("--source-dir", help="Path to decompiled source tree or extracted artifact directory")
    parser.add_argument("--output", help="Optional output JSON path")
    args = parser.parse_args()

    if args.apk:
        result = analyze_apk(args.apk, args.output)
    else:
        result = analyze_source_tree(args.source_dir, args.output)

    print(_render_summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
