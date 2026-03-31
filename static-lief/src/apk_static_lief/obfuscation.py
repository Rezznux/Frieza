import re
from typing import Any, Dict, List

_SEQ_RE = re.compile(r"^[a-z]{1,3}$")


def analyze_obfuscation(class_names: List[str]) -> Dict[str, Any]:
    """Score obfuscation likelihood from DEX class name patterns."""
    if not class_names:
        return {
            "score": 0,
            "likely_obfuscated": False,
            "indicators": [],
            "short_name_ratio": 0.0,
            "average_class_name_length": 0.0,
        }

    # Use the simple class name (last component, strip inner class suffix)
    simple_names = [n.split(".")[-1].split("$")[0] for n in class_names]
    total = len(simple_names)

    short_names = [n for n in simple_names if len(n) <= 2]
    sequential_names = [n for n in simple_names if _SEQ_RE.match(n)]
    avg_len = sum(len(n) for n in simple_names) / total

    indicators: List[str] = []
    score = 0

    short_ratio = len(short_names) / total
    if short_ratio > 0.4:
        score += 40
        indicators.append(f"{short_ratio:.0%} of class names are ≤2 chars (ProGuard/R8 pattern)")

    if len(sequential_names) > 5:
        seq_ratio = len(sequential_names) / total
        score += min(int(seq_ratio * 60), 35)
        indicators.append(f"{len(sequential_names)} sequentially-named classes (a, b, c pattern)")

    if avg_len < 4.0:
        score += 20
        indicators.append(f"Average class name length is {avg_len:.1f} chars (very short)")

    # Single-char package path components (e.g. com.a.b.C)
    pkg_components = [part for n in class_names for part in n.split(".")[:-1]]
    if pkg_components:
        single_char_pkgs = sum(1 for p in pkg_components if len(p) == 1)
        pkg_ratio = single_char_pkgs / len(pkg_components)
        if pkg_ratio > 0.5:
            score += 15
            indicators.append(
                f"Single-char package path components: {single_char_pkgs}/{len(pkg_components)} ({pkg_ratio:.0%})"
            )

    score = min(score, 100)
    return {
        "score": score,
        "likely_obfuscated": score >= 50,
        "short_name_ratio": round(short_ratio, 3),
        "average_class_name_length": round(avg_len, 1),
        "indicators": indicators,
    }
