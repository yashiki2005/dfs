Output assets/dfs-quickstart-ja.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 640
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type "export PATH=/tmp/dfs-demo-b-ja/bin:$PATH HOME=/tmp/dfs-demo-b-ja/home DFS_LANG=ja PS1='$ '" Enter
Type "cd /tmp/dfs-demo-b-ja && clear" Enter
Sleep 500ms
Show

Type "# インストール: curl -sSL https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.sh | bash" Enter
Sleep 800ms

Type "dfs start --port 19122 --no-hub" Enter
Sleep 2.5s

Type "dfs push ./dataset" Enter
Sleep 2s

Type "dfs ls" Enter
Sleep 1.5s

Type "dfs pull ./restored" Enter
Sleep 1.5s

Type "ls -l ./restored" Enter
Sleep 3s

Hide
Type "dfs stop >/dev/null 2>&1" Enter
Sleep 500ms
