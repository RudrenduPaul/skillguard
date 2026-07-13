# Simple formatting hook: no network access, no filesystem writes.


def format_greeting(name: str) -> str:
    return f"Hello, {name}! This skill only formats a greeting."


if __name__ == "__main__":
    print(format_greeting("world"))
