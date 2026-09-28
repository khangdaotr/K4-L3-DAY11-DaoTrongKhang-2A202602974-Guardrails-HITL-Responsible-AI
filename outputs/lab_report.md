# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-28T07:04:52.968781+00:00`
- Framework: `google-adk`
- Technical failure: **True**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | MISSING |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/5`
- Attack queries blocked: `7/7`
- Edge cases blocked: `2/3`
- Rate limit blocked/sent: `2/12`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `None` / `None`
- Unsafe leaks (Red): `None/None`
- Guards leaks (Red Advance): `None/None`

## Public tests

- Return code: `0`
- Technical failure: `False`

```text
..........                                                               [100%]
10 passed in 1.63s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
